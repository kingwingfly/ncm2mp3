# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`ncmc` is a Rust workspace (edition 2024, `resolver = "3"`) that decrypts NetEase Cloud Music
`.ncm` files into standard audio (mp3/flac/…). Two members:

- **`ncmc_lib`** — the library that parses and decrypts `.ncm` files. Published to crates.io.
- **`ncm_c`** — the CLI binary that wraps the library with parallelism. Published to crates.io.

## Commands

```bash
# Build (features + all targets, as CI does)
cargo build --all-features --all-targets

# Lint — CI treats warnings as errors
cargo clippy --all-features --all-targets -- -D warnings

# Test (no unit tests exist yet; `test/` holds sample .ncm/.mp3 fixtures)
cargo test

# Library docs
cargo doc --no-deps -p ncmc_lib

# Run the CLI against files (output lands next to each input)
cargo run -p ncm_c -- path/to/*.ncm

# Pre-publish gate for a crate (clippy + test + doc + publish dry-run)
.github/scripts/publish_test.sh ncmc_lib   # or ncm_c
```

## Architecture

### `ncmc_lib/src/lib.rs` — decryption pipeline

The core type is `NcmFile`. `NcmFile::open` runs the parse pipeline:

1. Verify the `CTENFDAM` magic header.
2. Decrypt the RC4-style content key with AES-128-ECB under `CORE_KEY` (bytes XOR-masked with
   `0x64` first).
3. Decrypt the metadata JSON with AES-128-ECB under `META_KEY` (bytes XOR-masked with `0x63`,
   then base64-decoded).
4. Read the embedded cover-art frame.

Audio decryption is streamed: `impl Read for NcmFile` XORs file bytes against the RC4 keystream
(`Key` iterator) on the fly. `save()`/`save_to()` write the decrypted audio (extension comes from
`Meta.format`) and then attach ID3v2.4 tags built by `From<&Meta> for Tag` (title, artist, album,
duration, cover). `save_without_meta*` variants skip tagging.

`Meta` and `Artist` use custom serde (`deserialize_to_string`, hand-written `Deserialize`) to
coerce numeric JSON fields to strings — this handles the metadata shape variations between the
macOS app and other clients. Errors live in `ncmc_lib/src/error.rs` (`NcmError`, via `thiserror`).

The `cover_download` feature (adds `ureq`) enables `with_cover`/`fetch_cover`, which fetch album
art from `Meta.album_pic` when the file has no embedded cover.

### `ncm_c/src/main.rs` — CLI

clap-derive CLI. Input paths are pushed into a `crossbeam-deque` `Injector`; `-j` worker threads
(default = logical core count) drain it via a work-stealing `Worker`/`Stealer` pool. `ncm_c` depends
on `ncmc_lib` with the `cover_download` feature on.

Flags: `-j/--threads`, `--no-internet` (skip cover fetching), `-q/--quiet`. In `--quiet` mode
decoded output paths go to stdout and failures to stderr (so failures can be piped/moved). The
process exits with `FAILURE` if any file failed to decrypt.

## Conventions

- PRs target the **`dev`** branch (CI runs on PRs into `dev`).
- Releases are CHANGELOG-driven: update `CHANGELOG.md`, then a `v*` git tag triggers the release
  workflow (builds binaries for macOS/Linux/Windows). Publishing to crates.io is a manual
  `workflow_dispatch`.
- When bumping versions, keep the two crate versions and the `ncmc_lib` dependency version pinned
  in `ncm_c/Cargo.toml` in sync.
- The root `README.md` is a symlink to `ncm_c/README.md`; `ncmc_lib/src/lib.rs` includes
  `ncmc_lib/README.md` as its crate-level docs.
