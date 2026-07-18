//! Encoding decoded audio back into the `.ncm` container format.
//!
//! This is the inverse of [`NcmFile::open`](crate::NcmFile::open): given track
//! [`Meta`], a raw content key and a plaintext audio stream, [`encode_ncm`]
//! writes a container that [`NcmFile::open`](crate::NcmFile::open) (and the
//! NetEase client) can read back.

use crate::{
    CORE_KEY, KEY_MAGIC, KEY_MASK, Key, META_KEY, META_MAGIC, META_MARKER, META_MASK, Meta,
    error::{NcmError, Result},
};
use aes::cipher::{BlockModeEncrypt as _, KeyInit as _, block_padding::Pkcs7};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use ecb::Encryptor;
use std::io::{Read, Write};

/// Magic header written at the start of every `.ncm` file.
const MAGIC: &[u8; 8] = b"CTENFDAM";
/// The two bytes following the magic are a version/flag the decoder ignores.
const GAP: [u8; 2] = [0x01, 0x70];
/// Five reserved/CRC bytes between the metadata blob and the cover frame. The
/// decoder skips them, so any value round-trips; we emit zeros.
const CRC: [u8; 5] = [0; 5];

/// Encode a raw content key (`key_data`) into a `.ncm` key blob (without its
/// `u32` length prefix). Inverse of the key-blob decryption in `NcmFile::open`.
pub(crate) fn encode_key_blob(key_data: &[u8]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(KEY_MAGIC.len() + key_data.len());
    plain.extend_from_slice(KEY_MAGIC);
    plain.extend_from_slice(key_data);
    let aes = Encryptor::<aes::Aes128>::new_from_slice(CORE_KEY).unwrap();
    let mut cipher = aes.encrypt_padded_vec::<Pkcs7>(&plain);
    cipher.iter_mut().for_each(|byte| *byte ^= KEY_MASK);
    cipher
}

/// Encode a [`Meta`] into a `.ncm` metadata blob (without its `u32` length
/// prefix). Inverse of the metadata decryption in `NcmFile::open`.
pub(crate) fn encode_meta_blob(meta: &Meta) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(meta)
        .map_err(|e| NcmError::Invalid(format!("Failed to serialize metadata: {e}")))?;
    let mut plain = Vec::with_capacity(META_MARKER.len() + json.len());
    plain.extend_from_slice(META_MARKER);
    plain.extend_from_slice(&json);
    let aes = Encryptor::<aes::Aes128>::new_from_slice(META_KEY).unwrap();
    let cipher = aes.encrypt_padded_vec::<Pkcs7>(&plain);
    let b64 = BASE64_STANDARD.encode(&cipher);
    let mut out = Vec::with_capacity(META_MAGIC.len() + b64.len());
    out.extend_from_slice(META_MAGIC);
    out.extend_from_slice(b64.as_bytes());
    out.iter_mut().for_each(|byte| *byte ^= META_MASK);
    Ok(out)
}

fn write_len_prefixed<W: Write>(out: &mut W, blob: &[u8]) -> Result<()> {
    out.write_all(&(blob.len() as u32).to_le_bytes())?;
    out.write_all(blob)?;
    Ok(())
}

/// Encode a plaintext `audio` stream into a valid `.ncm` container, written to
/// `out`.
///
/// * `meta` — the track metadata; its `cover` (if non-empty) is embedded.
/// * `key_data` — the raw RC4 content key. Any non-empty slice yields a
///   decodable file (the NetEase client uses a per-file random key); the audio
///   body is XORed with the keystream derived from it.
/// * `audio` — the plaintext audio (e.g. the decoded mp3/flac bytes).
///
/// The audio is streamed in fixed-size chunks, so arbitrarily large tracks are
/// encoded with bounded memory.
pub fn encode_ncm<R: Read, W: Write>(
    meta: &Meta,
    key_data: &[u8],
    mut audio: R,
    mut out: W,
) -> Result<()> {
    out.write_all(MAGIC)?;
    out.write_all(&GAP)?;
    write_len_prefixed(&mut out, &encode_key_blob(key_data))?;
    write_len_prefixed(&mut out, &encode_meta_blob(meta)?)?;
    out.write_all(&CRC)?;
    // Cover frame: [frame_len][image_len][image]. We write no padding, so the
    // frame length equals the image length and the decoder's skip is zero.
    let cover_len = meta.cover.len() as u32;
    out.write_all(&cover_len.to_le_bytes())?;
    out.write_all(&cover_len.to_le_bytes())?;
    out.write_all(&meta.cover)?;
    // Audio body, XORed with the keystream derived from `key_data`.
    let mut key = Key::from_key_data(key_data);
    let mut buf = [0u8; 8192];
    loop {
        let n = audio.read(&mut buf)?;
        if n == 0 {
            break;
        }
        key.apply(&mut buf[..n]);
        out.write_all(&buf[..n])?;
    }
    out.flush()?;
    Ok(())
}
