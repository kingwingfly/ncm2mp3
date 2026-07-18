# About

The lib for the tool to convert ncm file to mp3/flac/...

网易云音乐的ncm文件转换工具`ncm_c`的库。

# Usage

```rust no_run
use ncmc_lib::NcmFile;

let ncm = NcmFile::open("path/to/your.ncm").unwrap();
ncm.save().unwrap();
```

# Encoding

The pipeline is reversible: [`encode::encode_ncm`] wraps a plaintext audio
stream back into a valid `.ncm` container. The audio body is XOR-based and
therefore symmetric — the same keystream both decrypts and encrypts.

```rust no_run
use ncmc_lib::{NcmFile, encode::encode_ncm};
use std::io::Read;

// Decode an existing file to plaintext audio + metadata...
let mut ncm = NcmFile::open("in.ncm").unwrap();
let mut audio = Vec::new();
ncm.read_to_end(&mut audio).unwrap();
let meta = NcmFile::open("in.ncm").unwrap().into_parts().0;

// ...then re-encode. `key_data` is the raw content key: any non-empty slice
// yields a decodable file (the NetEase client uses a per-file random key).
let key_data: Vec<u8> = (0..=200).collect();
let out = std::fs::File::create("out.ncm").unwrap();
encode_ncm(&meta, &key_data, std::io::Cursor::new(audio), out).unwrap();
```

# Async streaming (`stream` feature)

With the `stream` feature, `stream::NcmStream` decodes a `.ncm` **as it
arrives** over the network: it parses the header off the front of the stream,
then is itself a `futures::Stream` yielding the decrypted audio body. The
adapters are plain `poll`-based wrappers over the `futures` traits (no
`async fn` in traits), so they are executor-agnostic — tokio, smol, async-std
all work.

```rust ignore
use futures::StreamExt;
use ncmc_lib::stream::NcmStream;
use std::io;

let resp = reqwest::get("https://example.com/song.ncm").await?;
// Map the stream's error into `io::Error`, which `NcmStream` requires.
let bytes = resp.bytes_stream().map_err(io::Error::other);

let mut ncm = NcmStream::open(bytes).await?;
println!("decoding {}", ncm.meta().music_name);

let mut file = tokio::fs::File::create("song.mp3").await?;
while let Some(chunk) = ncm.next().await {
    tokio::io::AsyncWriteExt::write_all(&mut file, &chunk?).await?;
}
```

## Bridging to tokio

`NcmStream` is a `futures::Stream`, which tokio consumes directly (as above).
For the reverse direction — turning our decoded `futures::Stream<Item = Bytes>`
into a `tokio::io::AsyncRead` — wrap it with `tokio_util::io::StreamReader`; to
feed a tokio `AsyncRead` *source* into `NcmStream::open`, turn it into a
stream first with `tokio_util::io::ReaderStream`:

```rust ignore
use tokio_util::io::{ReaderStream, StreamReader};

// tokio AsyncRead source -> stream -> decoded NcmStream
let src = tokio::fs::File::open("song.ncm").await?;
let ncm = NcmStream::open(ReaderStream::new(src)).await?;

// decoded futures::Stream -> tokio AsyncRead
let mut reader = StreamReader::new(ncm);
tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await?;
```

For lower-level composition, `stream::DecryptStream` transforms a body-only
chunk stream when you already hold a [`Key`] (from [`NcmFile::into_cipher`]),
and `stream::EncryptSink` is the encoding dual.

# features

- `cover_download`: provide `with_cover` method to download cover image from internet if not contained in ncm file.
- `stream`: async, `futures`-based `stream::NcmStream` / `stream::DecryptStream` / `stream::EncryptSink` adapters for decoding and encoding over a `futures::Stream`.

# Acknowledgement

- [YTSakura233/ncm2mp3](https://github.com/YTSakura233/ncm2mp3)
- [taurusxin/ncmdump](https://github.com/taurusxin/ncmdump)
