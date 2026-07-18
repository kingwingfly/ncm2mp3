//! Async, `futures`-based adapters for decoding and encoding `.ncm` audio.
//!
//! These wrappers are **executor-agnostic**: they implement
//! [`futures_core::Stream`] / [`futures_sink::Sink`] with hand-written `poll_*`
//! methods and contain no `async fn` in any trait, so they compose with tokio,
//! smol, async-std, etc.
//!
//! * [`NcmStream`] — parse a complete `.ncm` byte stream (header first) and
//!   yield the decrypted audio body as a [`Stream`] of [`Bytes`]. This is the
//!   entry point for the "download a `.ncm` and decode it on the fly" case
//!   (e.g. `reqwest::Response::bytes_stream()`).
//! * [`DecryptStream`] — the lower-level body-only adapter, for callers that
//!   already hold a [`Key`] (from [`NcmFile::into_cipher`](crate::NcmFile::into_cipher)).
//! * [`EncryptSink`] — the encoding dual: encrypt each chunk before forwarding
//!   it to an inner [`Sink`].
//!
//! See the crate-level docs for a `reqwest` example and notes on bridging to
//! tokio's `AsyncRead`/`AsyncWrite`.

use crate::{
    Key, Meta, decrypt_key_blob, decrypt_meta_blob,
    error::{NcmError, Result},
};
use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_sink::Sink;
use futures_util::{
    TryStreamExt as _,
    io::{AsyncRead, AsyncReadExt as _},
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

/// Size of the read buffer used when polling the decoded body.
const CHUNK: usize = 8192;

/// A decoded `.ncm` audio stream built from a raw byte stream.
///
/// [`NcmStream::open`] consumes the header from the front of the stream, then
/// the value itself is a [`Stream`] yielding the decrypted audio body.
pub struct NcmStream {
    reader: Box<dyn AsyncRead + Send + Unpin>,
    key: Key,
    meta: Meta,
}

impl NcmStream {
    /// Parse a complete `.ncm` byte stream, returning a handle that streams the
    /// decrypted audio body.
    ///
    /// `stream` is any `Stream` of byte chunks whose error converts into
    /// [`io::Error`] — for example `reqwest::Response::bytes_stream()` mapped
    /// with `.map_err(io::Error::other)`.
    pub async fn open<S, B, E>(stream: S) -> Result<Self>
    where
        S: Stream<Item = core::result::Result<B, E>> + Send + Unpin + 'static,
        B: AsRef<[u8]> + Send,
        E: Into<io::Error> + 'static,
    {
        let mut reader = stream.map_err(Into::into).into_async_read();
        let (key, meta) = parse_header(&mut reader).await?;
        Ok(Self {
            reader: Box::new(reader),
            key,
            meta,
        })
    }

    /// The parsed metadata (including the embedded cover, if any).
    pub fn meta(&self) -> &Meta {
        &self.meta
    }
}

impl Stream for NcmStream {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buf = [0u8; CHUNK];
        match Pin::new(&mut *this.reader).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(0)) => Poll::Ready(None),
            Poll::Ready(Ok(n)) => {
                this.key.apply(&mut buf[..n]);
                Poll::Ready(Some(Ok(Bytes::copy_from_slice(&buf[..n]))))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Read a `u32`-length-prefixed blob from an async reader.
async fn read_len_prefixed<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Read and discard `n` bytes from an async reader.
async fn skip<R: AsyncRead + Unpin>(reader: &mut R, mut n: usize) -> Result<()> {
    let mut scratch = [0u8; 4096];
    while n > 0 {
        let take = n.min(scratch.len());
        reader.read_exact(&mut scratch[..take]).await?;
        n -= take;
    }
    Ok(())
}

/// Parse the `.ncm` header (magic, key, metadata, CRC, cover) from an async
/// reader, leaving it positioned at the start of the encrypted audio body.
///
/// Mirrors the sync parse in [`NcmFile::open`](crate::NcmFile::open), sharing
/// the same pure crypto helpers.
async fn parse_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Key, Meta)> {
    let mut magic = [0u8; 10];
    reader.read_exact(&mut magic).await?;
    if &magic[..8] != b"CTENFDAM" {
        return Err(NcmError::Invalid("Invalid file header".to_string()));
    }
    let key = Key::from_key_data(&decrypt_key_blob(&mut read_len_prefixed(reader).await?)?);
    let mut meta = decrypt_meta_blob(&mut read_len_prefixed(reader).await?)?;
    let mut crc = [0u8; 5];
    reader.read_exact(&mut crc).await?; // CRC(5)
    let mut frame = [0u8; 4];
    reader.read_exact(&mut frame).await?;
    let frame_len = u32::from_le_bytes(frame);
    reader.read_exact(&mut frame).await?;
    let img_len = u32::from_le_bytes(frame);
    let mut cover = vec![0u8; img_len as usize];
    reader.read_exact(&mut cover).await?;
    skip(reader, (frame_len - img_len) as usize).await?;
    meta.cover = cover;
    Ok((key, meta))
}

/// A [`Stream`] adapter that (de/en)crypts the audio body of an inner byte
/// stream with a [`Key`].
///
/// Use this when you already hold a [`Key`] (e.g. via
/// [`NcmFile::into_cipher`](crate::NcmFile::into_cipher)) and only need to
/// transform the body chunks. The transform is symmetric, so it both decrypts
/// and encrypts.
pub struct DecryptStream<S> {
    inner: S,
    key: Key,
}

impl<S> DecryptStream<S> {
    /// Wrap `inner`, transforming each chunk with `key`.
    pub fn new(inner: S, key: Key) -> Self {
        Self { inner, key }
    }

    /// Unwrap, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, B, E> Stream for DecryptStream<S>
where
    S: Stream<Item = core::result::Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: Into<io::Error>,
{
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let mut buf = BytesMut::from(chunk.as_ref());
                this.key.apply(&mut buf);
                Poll::Ready(Some(Ok(buf.freeze())))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(NcmError::Io(e.into())))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A [`Sink`] adapter that (de/en)crypts each [`Bytes`] chunk with a [`Key`]
/// before forwarding it to an inner sink.
///
/// The encoding dual of [`DecryptStream`]; symmetric, so it also decrypts.
pub struct EncryptSink<Si> {
    inner: Si,
    key: Key,
}

impl<Si> EncryptSink<Si> {
    /// Wrap `inner`, transforming each chunk with `key` before it is sent.
    pub fn new(inner: Si, key: Key) -> Self {
        Self { inner, key }
    }

    /// Unwrap, returning the underlying sink.
    pub fn into_inner(self) -> Si {
        self.inner
    }
}

impl<Si> Sink<Bytes> for EncryptSink<Si>
where
    Si: Sink<Bytes> + Unpin,
{
    type Error = Si::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<core::result::Result<(), Si::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> core::result::Result<(), Si::Error> {
        let this = self.get_mut();
        let mut buf = BytesMut::from(item.as_ref());
        this.key.apply(&mut buf);
        Pin::new(&mut this.inner).start_send(buf.freeze())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<core::result::Result<(), Si::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<core::result::Result<(), Si::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}
