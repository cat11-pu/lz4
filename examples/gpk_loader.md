# Hardened GPK1 loader

`gpk_loader.c` reads the container used by the resource fixtures in
`artifacts/samples/`. Each texture, mesh or audio chunk is one LZ4 frame.

## Format

All integers are little-endian.

```
GPK header (12 bytes)
  "GPK1"            magic
  u32 version       must be 1
  u32 chunkCount    at least 1

chunk record (16 bytes)
  u32 type          1 texture, 2 mesh, 3 audio
  u32 flags         reserved, must be 0
  u32 compressed    size of the following LZ4 frame
  u32 uncompressed  expected decoded size
```

## Validation

The loader never trusts a size before checking it against the remaining file:

- The chunk table must fit in the input, and `chunkCount` is capped before
  allocation.
- Every `compressed` size must fit in the remaining input; every addition is
  overflow-checked.
- `uncompressed` is capped per chunk and for the archive total. The output
  buffer grows only as decoded bytes are actually produced, so a tiny malformed
  frame cannot request a large allocation from its header.
- A chunk must be one regular LZ4 frame. Skippable frames, dictionary frames
  and concatenated frames are rejected.
- If the LZ4 header declares a content size, it must equal the chunk record.
- Decoding must consume exactly `compressed` bytes and produce exactly
  `uncompressed` bytes. EOF before the end mark is a truncation error; checksum
  and block decode errors are reported by the LZ4 frame decoder.

Every failure prints a status, chunk index, record offset and payload offset:

```
gpk_loader: error=DECOMPRESSION code=14 chunk=0 offset=28 payload=44 detail=...
```

## Commands

```
./gpk_loader check   archive.gpk
./gpk_loader list    archive.gpk
./gpk_loader extract archive.gpk output-directory
```

`extract` writes `NNNN-texture.bin`, `NNNN-mesh.bin` or `NNNN-audio.bin` into
an existing directory. The output names are derived only from the index and
the validated type, never from archive bytes.
