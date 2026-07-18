#![cfg(feature = "stream")]

use futures::{StreamExt as _, executor::block_on, stream};
use ncmc_lib::{Meta, NcmFile, encode::encode_ncm, stream::NcmStream};
use std::io::Read as _;

fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test/ヰ世界情緒 - シリウスの心臓.ncm")
}

/// Sync reference decode of the fixture.
fn sync_decode() -> (Meta, Vec<u8>) {
    let mut ncm = NcmFile::open(fixture()).unwrap();
    let mut audio = Vec::new();
    ncm.read_to_end(&mut audio).unwrap();
    let meta = NcmFile::open(fixture()).unwrap().into_parts().0;
    (meta, audio)
}

/// Decode a complete `.ncm` byte buffer in memory via `NcmStream`, feeding it in
/// small chunks to exercise the async header parse across chunk boundaries.
fn stream_decode(bytes: Vec<u8>) -> (Meta, Vec<u8>) {
    let chunks: Vec<std::io::Result<Vec<u8>>> = bytes.chunks(7).map(|c| Ok(c.to_vec())).collect();
    block_on(async {
        let mut ncm = NcmStream::open(stream::iter(chunks)).await.unwrap();
        let meta = ncm.meta().clone();
        let mut audio = Vec::new();
        while let Some(chunk) = ncm.next().await {
            audio.extend_from_slice(&chunk.unwrap());
        }
        (meta, audio)
    })
}

#[test]
fn stream_decode_matches_sync() {
    let (meta_sync, audio_sync) = sync_decode();
    let (meta_stream, audio_stream) = stream_decode(std::fs::read(fixture()).unwrap());

    assert_eq!(audio_stream, audio_sync, "stream decode != sync decode");
    assert_eq!(meta_stream.music_name, meta_sync.music_name);
}

#[test]
fn encode_decode_roundtrip() {
    let (meta, audio) = sync_decode();

    // Encode with an arbitrary content key, then decode again in memory.
    let key_data: Vec<u8> = (0u8..=200).collect();
    let mut encoded = Vec::new();
    encode_ncm(&meta, &key_data, std::io::Cursor::new(&audio), &mut encoded).unwrap();
    let (meta_re, audio_re) = stream_decode(encoded);

    assert_eq!(audio_re, audio, "audio bytes mismatch after re-encode");
    assert_eq!(meta_re.music_name, meta.music_name);
    assert_eq!(meta_re.format, meta.format);
}
