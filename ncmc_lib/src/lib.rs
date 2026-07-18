#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod encode;
mod error;
#[cfg(feature = "stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "stream")))]
pub mod stream;

use aes::cipher::{BlockModeDecrypt as _, KeyInit as _, block_padding::Pkcs7};
use base64::{Engine, prelude::BASE64_STANDARD};
use ecb::Decryptor;
use error::{NcmError, Result};
use id3::{
    Tag, TagLike as _,
    frame::{Picture, PictureType},
};
use serde::{Deserialize, Serialize, ser::SerializeTuple as _};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Seek as _, Write},
    path::{Path, PathBuf},
};

const CORE_KEY: &[u8; 16] = b"hzHRAmso5kInbaxW";
const META_KEY: &[u8; 16] = br#"#14ljk_!\]&0U<'("#;
const KEY_MASK: u8 = 0x64;
const META_MASK: u8 = 0x63;
const KEY_MAGIC: &[u8] = b"neteasecloudmusic";
const META_MAGIC: &[u8] = b"163 key(Don't modify):";
const META_MARKER: &[u8] = b"music:";

/// Build the 256-byte RC4 key box (KSA) from the raw content key.
///
/// This is the pure, I/O-free core shared by parsing and encoding.
pub(crate) fn build_keybox(key_data: &[u8]) -> Vec<u8> {
    let mut key_box: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut last_byte = 0u8;
    let mut key_offset = 0;
    for i in 0..256 {
        let c = key_box[i]
            .wrapping_add(last_byte)
            .wrapping_add(key_data[key_offset]);
        key_offset += 1;
        if key_offset >= key_data.len() {
            key_offset = 0;
        }
        key_box.swap(i, c as usize);
        last_byte = c;
    }
    key_box.to_vec()
}

/// Decrypt a raw content-key blob (the bytes following its `u32` length prefix)
/// into the raw content key (`key_data`). Pure and I/O-free so it can be reused
/// by the sync, async and encode paths.
pub(crate) fn decrypt_key_blob(buf: &mut [u8]) -> Result<Vec<u8>> {
    buf.iter_mut().for_each(|byte| *byte ^= KEY_MASK);
    let aes = Decryptor::<aes::Aes128>::new_from_slice(CORE_KEY).unwrap();
    let buf = aes
        .decrypt_padded::<Pkcs7>(buf)
        .map_err(|_| NcmError::Invalid("Failed to decrypt key".to_string()))?;
    if buf.len() < KEY_MAGIC.len() || &buf[..KEY_MAGIC.len()] != KEY_MAGIC {
        return Err(NcmError::Invalid("Invalid key header".to_string()));
    }
    Ok(buf[KEY_MAGIC.len()..].to_vec())
}

/// Decrypt a raw metadata blob (the bytes following its `u32` length prefix)
/// into a [`Meta`]. Pure and I/O-free.
pub(crate) fn decrypt_meta_blob(buf: &mut [u8]) -> Result<Meta> {
    buf.iter_mut().for_each(|byte| *byte ^= META_MASK);
    if buf.len() < META_MAGIC.len() || &buf[..META_MAGIC.len()] != META_MAGIC {
        return Err(NcmError::Invalid("Invalid metadata header".to_string()));
    }
    let mut buf = BASE64_STANDARD
        .decode(&buf[META_MAGIC.len()..])
        .map_err(|_| NcmError::Invalid("Failed to decode base64 metadata".to_string()))?;
    let aes = Decryptor::<aes::Aes128>::new_from_slice(META_KEY).unwrap();
    let buf = aes
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| NcmError::Invalid("Failed to decrypt metadata".to_string()))?;
    if buf.len() < META_MARKER.len() || &buf[..META_MARKER.len()] != META_MARKER {
        return Err(NcmError::Invalid("Invalid meta marker".to_string()));
    }
    serde_json::from_slice(&buf[META_MARKER.len()..])
        .map_err(|e| NcmError::Invalid(format!("Failed to parse metadata: {e}")))
}

/// Ncm file
#[derive(Debug)]
pub struct NcmFile {
    file: File,
    path: PathBuf,
    key: Key,
    meta: Meta,
}

impl NcmFile {
    /// Open a ncm file
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let mut file = File::open(&path)?;
        Self::verify_header(&mut file)?;
        let key = Key::from_key_data(&Self::get_key(&mut file)?);
        let mut meta = Self::get_meta(&mut file)?;
        file.seek_relative(5)?; // CRC(5)
        meta.cover = Self::get_cover(&mut file)?;
        Ok(Self {
            file,
            path,
            key,
            meta,
        })
    }

    /// If cover in meta is empty, download it from the meta.album_pic
    #[cfg(feature = "cover_download")]
    pub fn with_cover(mut self) -> Result<Self> {
        self.fetch_cover()?;
        Ok(self)
    }

    /// `with_cover` but in place
    #[cfg(feature = "cover_download")]
    pub fn fetch_cover(&mut self) -> Result<()> {
        if self.meta.cover.is_empty() && !self.meta.album_pic.is_empty() {
            self.meta.cover = ureq::get(&self.meta.album_pic)
                .call()?
                .body_mut()
                .with_config() // cancel the default body size limit
                .read_to_vec()?;
        }
        Ok(())
    }

    fn verify_header(file: &mut File) -> Result<()> {
        let mut buf = [0; 10];
        file.read_exact(&mut buf)?;
        if &buf[..8] != b"CTENFDAM" {
            return Err(NcmError::Invalid("Invalid file header".to_string()));
        }
        Ok(())
    }

    fn get_key(file: &mut File) -> Result<Vec<u8>> {
        let mut buf = [0; 4];
        file.read_exact(&mut buf)?;
        let length = u32::from_le_bytes(buf) as usize;
        let mut buf = vec![0; length];
        file.read_exact(&mut buf)?;
        decrypt_key_blob(&mut buf)
    }

    fn get_meta(file: &mut File) -> Result<Meta> {
        let mut buf = [0; 4];
        file.read_exact(&mut buf)?;
        let length = u32::from_le_bytes(buf) as usize;
        let mut buf = vec![0; length];
        file.read_exact(&mut buf)?;
        decrypt_meta_blob(&mut buf)
    }

    fn get_cover(file: &mut File) -> Result<Vec<u8>> {
        let mut buf = [0; 4];
        file.read_exact(&mut buf)?;
        let cover_frame_length = u32::from_le_bytes(buf);
        file.read_exact(&mut buf)?;
        let length = u32::from_le_bytes(buf);
        let mut buf = vec![0; length as usize];
        file.read_exact(&mut buf)?;
        file.seek_relative((cover_frame_length - length) as i64)?;
        Ok(buf)
    }

    /// save as general format next to the original ncm file
    pub fn save(self) -> Result<PathBuf> {
        let path = self.path.with_extension(&self.meta.format);
        self.save_to(path)
    }

    /// save as general format to the specified path
    pub fn save_to(self, path: impl AsRef<Path>) -> Result<PathBuf> {
        let tag = Tag::from(&self.meta);
        self.save_without_meta_to(path.as_ref())?;
        tag.write_to_path(path.as_ref(), id3::Version::Id3v24)?;
        Ok(path.as_ref().to_owned())
    }

    /// save next to the original ncm file without tags
    pub fn save_without_meta(self) -> Result<PathBuf> {
        let path = self.path.with_extension(&self.meta.format);
        self.save_without_meta_to(path)
    }

    /// save to the specified path without tags
    pub fn save_without_meta_to(mut self, path: impl AsRef<Path>) -> Result<PathBuf> {
        let mut file = std::fs::File::create(path.as_ref())?;
        std::io::copy(&mut self, &mut file)?;
        file.flush()?;
        Ok(path.as_ref().to_owned())
    }

    /// Get the meta data (including cover, artist, album, etc.)
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Consume the file, returning its parsed metadata and the audio keystream.
    ///
    /// Useful for driving the [`CipherReader`]/[`CipherWriter`] adapters or the
    /// async wrappers (with the `stream` feature) by hand.
    pub fn into_parts(self) -> (Meta, Key) {
        (self.meta, self.key)
    }

    /// Consume the file, returning just the audio keystream.
    pub fn into_cipher(self) -> Key {
        self.key
    }
}

impl Read for NcmFile {
    /// Read decrypted bytes from ncm file
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.file.read(buf)?;
        self.key.apply(&mut buf[..size]);
        Ok(size)
    }
}

/// The RC4-style keystream that (de/en)crypts the audio body of a `.ncm` file.
///
/// The keystream is independent of the data, and the body transform is a plain
/// XOR — so the same [`Key`] both decrypts and encrypts. Obtain one from
/// [`NcmFile::into_cipher`] / [`NcmFile::into_parts`], then drive any of the
/// adapters (sync [`CipherReader`]/[`CipherWriter`] or, with the `stream`
/// feature, the async wrappers).
#[derive(Debug, Clone)]
pub struct Key {
    key: Vec<u8>,
    i: u8,
}

impl Key {
    /// Build the keystream from the raw content key (`key_data`).
    pub(crate) fn from_key_data(key_data: &[u8]) -> Self {
        Self {
            key: build_keybox(key_data),
            i: 0,
        }
    }

    /// XOR `buf` in place against the keystream, advancing its state.
    ///
    /// Because the transform is symmetric this both decrypts ciphertext and
    /// encrypts plaintext.
    pub fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            // The keystream never terminates, so `next` is always `Some`.
            *byte ^= self.next().unwrap();
        }
    }
}

/// A [`Read`] adapter that (de/en)crypts the `.ncm` audio body while reading
/// from an arbitrary underlying reader.
///
/// The transform is symmetric, so the same adapter decrypts a ciphertext body
/// and encrypts a plaintext one.
#[derive(Debug)]
pub struct CipherReader<R> {
    inner: R,
    key: Key,
}

impl<R> CipherReader<R> {
    /// Wrap `inner`, transforming bytes with `key` as they are read.
    pub fn new(inner: R, key: Key) -> Self {
        Self { inner, key }
    }

    /// Unwrap, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CipherReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.inner.read(buf)?;
        self.key.apply(&mut buf[..size]);
        Ok(size)
    }
}

/// A [`Write`] adapter that (de/en)crypts bytes before forwarding them to an
/// underlying writer.
///
/// The transform is symmetric, so this both encrypts a plaintext body (for the
/// [`encode`] path) and decrypts a ciphertext one.
///
/// [`encode`]: crate::encode
#[derive(Debug)]
pub struct CipherWriter<W> {
    inner: W,
    key: Key,
}

impl<W> CipherWriter<W> {
    /// Wrap `inner`, transforming bytes with `key` before they are written.
    pub fn new(inner: W, key: Key) -> Self {
        Self { inner, key }
    }

    /// Unwrap, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CipherWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The input is immutable, so transform a scratch copy.
        let start = self.key.i;
        let mut tmp = buf.to_vec();
        self.key.apply(&mut tmp);
        let written = self.inner.write(&tmp)?;
        // On a short write we advanced the keystream too far; rewind it to
        // reflect only the bytes actually written. The keystream is a pure
        // function of `i` (period 256), so restoring `i` is exact — `written`
        // truncated to `u8` is `written mod 256`.
        self.key.i = start.wrapping_add(written as u8);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Iterator for Key {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.i = self.i.wrapping_add(1);
        Some(
            self.key[self.key[self.i as usize]
                .wrapping_add(self.key[self.key[self.i as usize].wrapping_add(self.i) as usize])
                as usize],
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(missing_docs)]
pub struct Meta {
    #[serde(default)]
    pub album: String,
    #[serde(rename = "albumId", deserialize_with = "deserialize_to_string")]
    pub album_id: String,
    /// The url of the cover image
    #[serde(rename = "albumPic")]
    pub album_pic: String,
    #[serde(rename = "albumPicDocId", deserialize_with = "deserialize_to_string")]
    pub album_pic_doc_id: String,
    #[serde(default)]
    pub alias: Vec<String>,
    #[serde(default)]
    pub artist: Vec<Artist>,
    pub bitrate: usize,
    pub duration: usize,
    pub fee: Option<usize>,
    pub flag: Option<usize>,
    pub format: String,
    #[serde(rename = "mp3DocId")]
    pub mp3_doc_id: Option<String>,
    pub gain: Option<f64>,
    #[serde(rename = "musicId", deserialize_with = "deserialize_to_string")]
    pub music_id: String,
    #[serde(rename = "musicName")]
    pub music_name: String,
    #[serde(default, rename = "mvId", deserialize_with = "deserialize_to_string")]
    pub mv_id: String,
    #[serde(default, rename = "transNames")]
    pub trans_names: Vec<String>,
    #[serde(skip)]
    pub cover: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Artist {
    pub name: String,
    pub id: String,
}

impl Serialize for Artist {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(2)?;
        seq.serialize_element(&self.name)?;
        seq.serialize_element(&self.id)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Artist {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;
        match v.as_array() {
            Some(v) => {
                if let [Value::String(name), Value::String(id)] = v.as_slice() {
                    Ok(Artist {
                        name: name.clone(),
                        id: id.clone(),
                    })
                } else if let [Value::String(name), Value::Number(id)] = v.as_slice() {
                    Ok(Artist {
                        name: name.clone(),
                        id: id.to_string(),
                    })
                } else {
                    Err(serde::de::Error::custom("Invalid value"))
                }
            }
            None => Err(serde::de::Error::custom("Invalid value")),
        }
    }
}

fn deserialize_to_string<'de, D>(deserializer: D) -> core::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = Value::deserialize(deserializer)?;
    match s {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(serde::de::Error::custom("Invalid value")),
    }
}

impl From<&Meta> for Tag {
    fn from(meta: &Meta) -> Self {
        let mut tag = Tag::new();
        tag.set_album(meta.album.clone());
        tag.add_frame(Picture {
            mime_type: "image/jpeg".to_string(),
            picture_type: PictureType::CoverFront,
            description: "Cover".to_string(),
            data: meta.cover.clone(),
        });
        tag.set_artist(meta.artist.iter().map(|artist| &artist.name).fold(
            String::new(),
            |acc, x| {
                if acc.is_empty() {
                    x.to_string()
                } else {
                    acc + ", " + x
                }
            },
        ));
        tag.set_duration(meta.duration as u32);
        tag.set_title(meta.music_name.clone());
        tag
    }
}
