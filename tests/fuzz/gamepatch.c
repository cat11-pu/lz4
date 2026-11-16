/*
    gamepatch - property tests of LZ4 frames carrying game resources
    Copyright (C) 2026

    GPL-2.0-or-later License

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    You can contact the author at :
    - LZ4 homepage : http://www.lz4.org
    - LZ4 source repository : https://github.com/lz4/lz4
*/

/*
 * The corpus is deterministic: 50 valid patches and 200 malformed ones.
 * A patch is one LZ4 frame whose blocks are texture, mesh and audio resources.
 * Malformed frames alternate between:
 * - truncated texture, mesh and audio blocks ;
 * - bad magic, flags, block size id and header checksum ;
 * - a truncated frame header ;
 * - corrupted block payloads and block checksums ;
 * - oversized compressed and uncompressed blocks.
 *
 * Every frame is decoded with custom allocators that count live allocations.
 * Output buffers have guards on both sides.  A failure reports the frame,
 * resource, block index, block offset and mutation offset.
 */

#ifdef _MSC_VER
#  pragma warning(disable : 4127)    /* conditional expression is constant */
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include "lz4.h"
#include "xxhash.h"


/*-************************************
*  Constants
**************************************/
#define KB *(1U<<10)
#define MB *(1U<<20)

#define GAMEPATCH_MAX_RESOURCES 8U
#define GAMEPATCH_MAX_RESOURCE_SIZE (64 KB)
#define GAMEPATCH_MAX_PLAIN (320 KB)
#define GAMEPATCH_MAX_FRAME (384 KB)
#define GAMEPATCH_CANARY_SIZE 32U
#define GAMEPATCH_CANARY_BYTE 0xA5U
#define GAMEPATCH_FRAME_HEADER_SIZE 15U

static const unsigned g_defaultValidPatches = 50;
static const unsigned g_defaultMalformedCases = 200;


/*-************************************
*  Basic helpers
**************************************/
static unsigned readLE32(const void* src)
{
    const unsigned char* const p = (const unsigned char*)src;
    return (unsigned)p[0]
         | ((unsigned)p[1] << 8)
         | ((unsigned)p[2] << 16)
         | ((unsigned)p[3] << 24);
}

static unsigned long long readLE64(const void* src)
{
    const unsigned char* const p = (const unsigned char*)src;
    return (unsigned long long)p[0]
         | ((unsigned long long)p[1] << 8)
         | ((unsigned long long)p[2] << 16)
         | ((unsigned long long)p[3] << 24)
         | ((unsigned long long)p[4] << 32)
         | ((unsigned long long)p[5] << 40)
         | ((unsigned long long)p[6] << 48)
         | ((unsigned long long)p[7] << 56);
}

static void writeLE32(void* dst, unsigned value)
{
    unsigned char* const p = (unsigned char*)dst;
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void writeLE64(void* dst, unsigned long long value)
{
    unsigned char* const p = (unsigned char*)dst;
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
    p[4] = (unsigned char)(value >> 32);
    p[5] = (unsigned char)(value >> 40);
    p[6] = (unsigned char)(value >> 48);
    p[7] = (unsigned char)(value >> 56);
}

static unsigned xorshift32(unsigned* state)
{
    unsigned x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}


/*-************************************
*  Allocation tracking
**************************************/
typedef struct {
    size_t allocations;
    size_t frees;
    size_t live;
} AllocStats;

static void* trackedAlloc(void* opaque, size_t size)
{
    AllocStats* const stats = (AllocStats*)opaque;
    void* const ptr = malloc(size ? size : 1);
    if (ptr != NULL) {
        stats->allocations++;
        stats->live++;
    }
    return ptr;
}

static void* trackedCalloc(void* opaque, size_t size)
{
    void* const ptr = trackedAlloc(opaque, size);
    if (ptr != NULL) memset(ptr, 0, size);
    return ptr;
}

static void trackedFree(void* opaque, void* address)
{
    AllocStats* const stats = (AllocStats*)opaque;
    if (address == NULL) return;
    stats->frees++;
    stats->live--;
    free(address);
}


/*-************************************
*  Patch model
**************************************/
typedef enum {
    RES_TEXTURE = 0,
    RES_MESH = 1,
    RES_AUDIO = 2
} ResourceKind;

typedef struct {
    ResourceKind kind;
    const char* name;
    size_t size;           /* uncompressed resource size */
    size_t srcOffset;      /* offset within the uncompressed patch */
    unsigned long long hash;
    size_t blockIndex;
    size_t blockOffset;    /* block header, from the start of the frame */
    size_t payloadOffset;
    size_t storedSize;
    int raw;
} Resource;

typedef struct {
    unsigned char* plain;
    unsigned char* frame;
    unsigned char* compressed;
    size_t plainSize;
    size_t frameSize;
    unsigned nbResources;
    Resource resource[GAMEPATCH_MAX_RESOURCES];
    unsigned long long hash;
} Patch;

static const char* resourceName(ResourceKind kind)
{
    switch (kind) {
    case RES_TEXTURE: return "texture";
    case RES_MESH:    return "mesh";
    case RES_AUDIO:   return "audio";
    }
    return "unknown";
}

static int patchInit(Patch* patch)
{
    memset(patch, 0, sizeof(*patch));
    patch->plain = (unsigned char*)malloc(GAMEPATCH_MAX_PLAIN);
    patch->frame = (unsigned char*)malloc(GAMEPATCH_MAX_FRAME);
    patch->compressed = (unsigned char*)malloc((size_t)LZ4_compressBound((int)GAMEPATCH_MAX_RESOURCE_SIZE) + 64);
    if (patch->plain == NULL || patch->frame == NULL || patch->compressed == NULL) {
        free(patch->plain);
        free(patch->frame);
        free(patch->compressed);
        memset(patch, 0, sizeof(*patch));
        return 0;
    }
    return 1;
}

static void patchFree(Patch* patch)
{
    free(patch->plain);
    free(patch->frame);
    free(patch->compressed);
    memset(patch, 0, sizeof(*patch));
}

static size_t resourceSize(ResourceKind kind, unsigned patchIndex, unsigned resourceIndex)
{
    size_t base;
    size_t span;
    size_t variation;

    switch (kind) {
    case RES_TEXTURE:
        base = 4 KB;
        span = 20 KB;
        variation = (size_t)(patchIndex * 4093U + resourceIndex * 97U) % span;
        break;
    case RES_MESH:
        base = 3 KB;
        span = 26 KB;
        variation = (size_t)(patchIndex * 8191U + resourceIndex * 53U) % span;
        break;
    case RES_AUDIO:
    default:
        base = 6 KB;
        span = 36 KB;
        variation = (size_t)(patchIndex * 12289U + resourceIndex * 31U) % span;
        break;
    }
    return base + variation;
}

static void fillResource(unsigned char* dst, size_t size, ResourceKind kind,
                         unsigned patchIndex, unsigned resourceIndex)
{
    unsigned state = (patchIndex + 1U) * 2654435761U + (resourceIndex + 1U) * 2246822519U;
    size_t i;
    int const noisy = (((patchIndex + resourceIndex) & 3U) == 0);

    if (state == 0) state = 1;
    if (noisy) {
        for (i = 0; i < size; i++) dst[i] = (unsigned char)(xorshift32(&state) >> 24);
        return;
    }

    switch (kind) {
    case RES_TEXTURE:
        for (i = 0; i < size; i++)
            dst[i] = (unsigned char)((i * 3U + (i >> 8) + patchIndex) & 0xFF);
        break;
    case RES_MESH:
        for (i = 0; i < size; i++)
            dst[i] = (unsigned char)(((i / 3U) % 16U) * 16U + (i % 3U));
        break;
    case RES_AUDIO:
    default:
        for (i = 0; i < size; i++)
            dst[i] = (unsigned char)(((i * 5U) ^ (i >> 5)) + patchIndex);
        break;
    }
}

/* Builds a valid frame: 64 KB independent blocks, block checksums,
 * content size and content checksum.  Each resource is one block. */
static int buildPatch(Patch* patch, unsigned patchIndex)
{
    unsigned resourceIndex;
    unsigned const nbResources = 3U + (patchIndex % 3U);
    size_t plainPos = 0;
    size_t pos = 0;

    patch->nbResources = nbResources;
    patch->plainSize = 0;
    patch->frameSize = 0;

    for (resourceIndex = 0; resourceIndex < nbResources; resourceIndex++) {
        ResourceKind const kind = (ResourceKind)(resourceIndex % 3U);
        Resource* const resource = &patch->resource[resourceIndex];
        size_t const size = resourceSize(kind, patchIndex, resourceIndex);

        if (size > GAMEPATCH_MAX_RESOURCE_SIZE || plainPos + size > GAMEPATCH_MAX_PLAIN)
            return 0;
        resource->kind = kind;
        resource->name = resourceName(kind);
        resource->size = size;
        resource->srcOffset = plainPos;
        fillResource(patch->plain + plainPos, size, kind, patchIndex, resourceIndex);
        resource->hash = XXH64(patch->plain + plainPos, size, 0);
        plainPos += size;
    }
    patch->plainSize = plainPos;
    patch->hash = XXH64(patch->plain, patch->plainSize, 0);

    if (patch->plainSize > GAMEPATCH_MAX_PLAIN) return 0;

    /* Frame header, with content size: 15 bytes */
    writeLE32(patch->frame + pos, LZ4F_MAGICNUMBER);
    pos += 4;
    patch->frame[pos++] = 0x7C;   /* version 01, independent, block + content checksums, content size */
    patch->frame[pos++] = 0x40;   /* 64 KB blocks */
    writeLE64(patch->frame + pos, (unsigned long long)patch->plainSize);
    pos += 8;
    patch->frame[pos] = (unsigned char)(XXH32(patch->frame + 4, pos - 4, 0) >> 8);
    pos++;
    if (pos != GAMEPATCH_FRAME_HEADER_SIZE) return 0;

    for (resourceIndex = 0; resourceIndex < nbResources; resourceIndex++) {
        Resource* const resource = &patch->resource[resourceIndex];
        int compressedSize;
        size_t storedSize;
        int raw;

        compressedSize = LZ4_compress_default(
                (const char*)patch->plain + resource->srcOffset,
                (char*)patch->compressed,
                (int)resource->size,
                (int)LZ4_compressBound((int)resource->size));
        raw = (compressedSize <= 0 || (size_t)compressedSize >= resource->size);
        storedSize = raw ? resource->size : (size_t)compressedSize;

        if (pos + 4 + storedSize + 4 > GAMEPATCH_MAX_FRAME) return 0;
        resource->blockIndex = resourceIndex;
        resource->blockOffset = pos;
        resource->payloadOffset = pos + 4;
        resource->storedSize = storedSize;
        resource->raw = raw;

        writeLE32(patch->frame + pos, (unsigned)storedSize | (raw ? 0x80000000U : 0));
        pos += 4;
        if (raw) {
            memcpy(patch->frame + pos, patch->plain + resource->srcOffset, storedSize);
        } else {
            memcpy(patch->frame + pos, patch->compressed, storedSize);
        }
        pos += storedSize;
        writeLE32(patch->frame + pos, XXH32(patch->frame + resource->payloadOffset, storedSize, 0));
        pos += 4;
    }

    if (pos + 8 > GAMEPATCH_MAX_FRAME) return 0;
    writeLE32(patch->frame + pos, 0);   /* end mark */
    pos += 4;
    writeLE32(patch->frame + pos, XXH32(patch->plain, patch->plainSize, 0));
    pos += 4;
    patch->frameSize = pos;
    return 1;
}


/*-************************************
*  Decoding and checks
**************************************/
typedef struct {
    size_t consumed;
    size_t produced;
    size_t returnValue;
    unsigned calls;
    int isError;
    int finished;
    int stalled;
    int leaked;
    int creationFailed;
    LZ4F_errorCodes errorCode;
} DecodeResult;

static int decodeFrame(const unsigned char* frame, size_t frameSize,
                       unsigned char* dst, size_t dstCapacity,
                       size_t inputChunk, size_t outputChunk,
                       DecodeResult* result)
{
    LZ4F_CustomMem cmem;
    LZ4F_dctx* dctx;
    AllocStats stats;
    size_t srcPos = 0;
    size_t dstPos = 0;
    int ok = 1;

    memset(result, 0, sizeof(*result));
    memset(&stats, 0, sizeof(stats));
    cmem.customAlloc = trackedAlloc;
    cmem.customCalloc = trackedCalloc;
    cmem.customFree = trackedFree;
    cmem.opaqueState = &stats;

    dctx = LZ4F_createDecompressionContext_advanced(cmem, LZ4F_VERSION);
    if (dctx == NULL) {
        result->creationFailed = 1;
        if (stats.live != 0) result->leaked = 1;
        return 0;
    }

    while (result->calls < 1000000U) {
        size_t cSize = frameSize - srcPos;
        size_t dSize = dstCapacity - dstPos;
        size_t r;

        if (inputChunk != 0 && cSize > inputChunk) cSize = inputChunk;
        if (outputChunk != 0 && dSize > outputChunk) dSize = outputChunk;
        r = LZ4F_decompress(dctx, dst + dstPos, &dSize, frame + srcPos, &cSize, NULL);

        result->calls++;
        result->returnValue = r;
        srcPos += cSize;
        dstPos += dSize;

        if (LZ4F_isError(r)) {
            result->isError = 1;
            result->errorCode = LZ4F_getErrorCode(r);
            break;
        }
        if (r == 0) {
            result->finished = 1;
            break;
        }
        if (cSize == 0 && dSize == 0) {
            result->stalled = 1;
            break;
        }
        if (srcPos == frameSize && dSize == 0) break;
        if (dstPos == dstCapacity && cSize == 0) break;
    }

    result->consumed = srcPos;
    result->produced = dstPos;
    (void)LZ4F_freeDecompressionContext(dctx);
    if (stats.live != 0) {
        result->leaked = 1;
        ok = 0;
    }
    return ok;
}

/* 0 : no guard changed ; otherwise : 1-based position of the first changed byte */
static size_t guardMismatch(const unsigned char* base, size_t payloadCapacity)
{
    size_t i;
    for (i = 0; i < GAMEPATCH_CANARY_SIZE; i++) {
        if (base[i] != GAMEPATCH_CANARY_BYTE) return i + 1;
    }
    for (i = 0; i < GAMEPATCH_CANARY_SIZE; i++) {
        if (base[GAMEPATCH_CANARY_SIZE + payloadCapacity + i] != GAMEPATCH_CANARY_BYTE)
            return GAMEPATCH_CANARY_SIZE + payloadCapacity + i + 1;
    }
    return 0;
}

static const Resource* resourceAt(const Patch* patch, size_t outputOffset)
{
    unsigned i;
    for (i = 0; i < patch->nbResources; i++) {
        const Resource* const resource = &patch->resource[i];
        if (outputOffset >= resource->srcOffset && outputOffset < resource->srcOffset + resource->size)
            return resource;
    }
    return NULL;
}

static void reportByteDifference(const Patch* patch, size_t pos, const char* what)
{
    const Resource* const resource = resourceAt(patch, pos);
    if (resource != NULL) {
        fprintf(stderr, "gamepatch: %s differs at decoded offset %lu "
                        "(resource=%s block=%lu blockOffset=%lu resourceOffset=%lu)\n",
                what,
                (unsigned long)pos,
                resource->name,
                (unsigned long)resource->blockIndex,
                (unsigned long)resource->blockOffset,
                (unsigned long)(pos - resource->srcOffset));
    } else {
        fprintf(stderr, "gamepatch: %s differs at decoded offset %lu (between resources)\n",
                what, (unsigned long)pos);
    }
}

/* Reference decompression: independent of lz4frame's decoder.
 * Parses the blocks and decodes each compressed block with LZ4_decompress_safe(). */
static int referenceDecode(const Patch* patch, unsigned char* reference, size_t referenceCapacity)
{
    size_t pos = 0;
    size_t refPos = 0;
    unsigned i;

    if (patch->frameSize < GAMEPATCH_FRAME_HEADER_SIZE) return 0;
    if (readLE32(patch->frame) != LZ4F_MAGICNUMBER) return 0;
    if (patch->frame[4] != 0x7C || patch->frame[5] != 0x40) return 0;
    if (readLE64(patch->frame + 6) != (unsigned long long)patch->plainSize) return 0;
    if (patch->frame[14] != (unsigned char)(XXH32(patch->frame + 4, 10, 0) >> 8)) return 0;
    pos = GAMEPATCH_FRAME_HEADER_SIZE;

    for (i = 0; i < patch->nbResources; i++) {
        const Resource* const resource = &patch->resource[i];
        unsigned const blockHeader = readLE32(patch->frame + pos);
        size_t const storedSize = blockHeader & 0x7FFFFFFFU;
        int const raw = (blockHeader >> 31) != 0;

        if (pos != resource->blockOffset) return 0;
        if (storedSize != resource->storedSize || raw != resource->raw) return 0;
        if (pos + 4 + storedSize + 4 > patch->frameSize) return 0;
        if (readLE32(patch->frame + pos + 4 + storedSize)
            != XXH32(patch->frame + pos + 4, storedSize, 0)) return 0;
        if (refPos + resource->size > referenceCapacity) return 0;

        if (raw) {
            if (storedSize != resource->size) return 0;
            memcpy(reference + refPos, patch->frame + pos + 4, storedSize);
        } else {
            int const decodedSize = LZ4_decompress_safe(
                    (const char*)patch->frame + pos + 4,
                    (char*)reference + refPos,
                    (int)storedSize,
                    (int)resource->size);
            if (decodedSize != (int)resource->size) return 0;
        }

        if (XXH64(reference + refPos, resource->size, 0) != resource->hash) return 0;
        refPos += resource->size;
        pos += 4 + storedSize + 4;
    }

    if (pos + 8 != patch->frameSize) return 0;
    if (readLE32(patch->frame + pos) != 0) return 0;
    pos += 4;
    if (readLE32(patch->frame + pos) != XXH32(reference, patch->plainSize, 0)) return 0;
    return refPos == patch->plainSize;
}

static int checkValidPatch(const Patch* patch, unsigned patchIndex,
                           unsigned char* decodedBase, unsigned char* reference,
                           int verbose)
{
    DecodeResult result;
    unsigned i;
    size_t guard;
    size_t diff;
    unsigned const fragmented = (patchIndex % 7U) == 0;
    size_t const inputChunk = fragmented ? 3 : 0;
    size_t const outputChunk = fragmented ? 11 : 0;

    if (!referenceDecode(patch, reference, GAMEPATCH_MAX_PLAIN)) {
        fprintf(stderr, "gamepatch: valid patch %u : reference decompression failed\n", patchIndex);
        return 0;
    }
    if (memcmp(reference, patch->plain, patch->plainSize) != 0) {
        for (diff = 0; diff < patch->plainSize && reference[diff] == patch->plain[diff]; diff++) {}
        reportByteDifference(patch, diff, "reference output");
        return 0;
    }

    memset(decodedBase, GAMEPATCH_CANARY_BYTE, GAMEPATCH_MAX_PLAIN + 2 * GAMEPATCH_CANARY_SIZE);
    if (!decodeFrame(patch->frame, patch->frameSize,
                     decodedBase + GAMEPATCH_CANARY_SIZE, patch->plainSize,
                     inputChunk, outputChunk, &result)) {
        fprintf(stderr, "gamepatch: valid patch %u : decoder context leak or creation failure\n", patchIndex);
        return 0;
    }
    if (!result.finished || result.isError) {
        fprintf(stderr, "gamepatch: valid patch %u : decoding failed (%s, blockOffset=0)\n",
                patchIndex, result.isError ? LZ4F_getErrorName(result.returnValue) : "incomplete");
        return 0;
    }
    if (result.consumed != patch->frameSize || result.produced != patch->plainSize) {
        fprintf(stderr, "gamepatch: valid patch %u : consumed %lu/%lu, produced %lu/%lu (blockOffset=%lu)\n",
                patchIndex,
                (unsigned long)result.consumed, (unsigned long)patch->frameSize,
                (unsigned long)result.produced, (unsigned long)patch->plainSize,
                (unsigned long)patch->resource[0].blockOffset);
        return 0;
    }
    guard = guardMismatch(decodedBase, patch->plainSize);
    if (guard != 0) {
        fprintf(stderr, "gamepatch: valid patch %u : output guard changed at +%lu (blockOffset=%lu)\n",
                patchIndex, (unsigned long)(guard - 1),
                (unsigned long)patch->resource[0].blockOffset);
        return 0;
    }

    if (memcmp(decodedBase + GAMEPATCH_CANARY_SIZE, reference, patch->plainSize) != 0) {
        for (diff = 0; diff < patch->plainSize
                    && decodedBase[GAMEPATCH_CANARY_SIZE + diff] == reference[diff]; diff++) {}
        reportByteDifference(patch, diff, "frame decoder output");
        return 0;
    }
    if (memcmp(decodedBase + GAMEPATCH_CANARY_SIZE, patch->plain, patch->plainSize) != 0) {
        for (diff = 0; diff < patch->plainSize
                    && decodedBase[GAMEPATCH_CANARY_SIZE + diff] == patch->plain[diff]; diff++) {}
        reportByteDifference(patch, diff, "decoded patch");
        return 0;
    }

    for (i = 0; i < patch->nbResources; i++) {
        const Resource* const resource = &patch->resource[i];
        unsigned long long const decodedHash =
            XXH64(decodedBase + GAMEPATCH_CANARY_SIZE + resource->srcOffset, resource->size, 0);
        if (decodedHash != resource->hash) {
            fprintf(stderr, "gamepatch: valid patch %u : %s hash %016llx != %016llx "
                            "(block=%lu blockOffset=%lu resourceOffset=%lu)\n",
                    patchIndex, resource->name,
                    decodedHash, resource->hash,
                    (unsigned long)resource->blockIndex,
                    (unsigned long)resource->blockOffset,
                    (unsigned long)resource->srcOffset);
            return 0;
        }
    }
    if (XXH64(decodedBase + GAMEPATCH_CANARY_SIZE, patch->plainSize, 0) != patch->hash) {
        fprintf(stderr, "gamepatch: valid patch %u : patch hash mismatch (blockOffset=%lu)\n",
                patchIndex, (unsigned long)patch->resource[0].blockOffset);
        return 0;
    }

    if (verbose)
        printf("valid %02u : %u resources, %lu bytes, hash=%016llx\n",
               patchIndex + 1, patch->nbResources,
               (unsigned long)patch->plainSize, patch->hash);
    return 1;
}


/*-************************************
*  Malformed corpus
**************************************/
typedef enum {
    MUT_TRUNC_TEXTURE = 0,
    MUT_TRUNC_MESH = 1,
    MUT_TRUNC_AUDIO = 2,
    MUT_BAD_MAGIC = 3,
    MUT_BAD_FLAGS = 4,
    MUT_BAD_BLOCKSIZE = 5,
    MUT_BAD_HEADER_CHECKSUM = 6,
    MUT_TRUNC_HEADER = 7,
    MUT_CORRUPT_PAYLOAD = 8,
    MUT_CORRUPT_BLOCK_CHECKSUM = 9,
    MUT_OVERSIZED_COMPRESSED = 10,
    MUT_OVERSIZED_RAW = 11,
    MUT_CORRUPT_VALID_CHECKSUM = 12,
    MUT_KIND_COUNT = 13
} MutationKind;

typedef struct {
    const char* name;
    MutationKind kind;
    unsigned caseIndex;
    unsigned patchIndex;
    unsigned resourceIndex;
    int hasResource;
    size_t blockIndex;
    size_t blockOffset;
    size_t mutationOffset;
    size_t frameSize;
    int expectError;
    int acceptAnyError;
    LZ4F_errorCodes expectedError;
} Mutation;

static const char* mutationName(MutationKind kind)
{
    switch (kind) {
    case MUT_TRUNC_TEXTURE:          return "truncate-texture";
    case MUT_TRUNC_MESH:             return "truncate-mesh";
    case MUT_TRUNC_AUDIO:            return "truncate-audio";
    case MUT_BAD_MAGIC:              return "bad-magic";
    case MUT_BAD_FLAGS:              return "bad-flags";
    case MUT_BAD_BLOCKSIZE:          return "bad-blocksize";
    case MUT_BAD_HEADER_CHECKSUM:    return "bad-header-checksum";
    case MUT_TRUNC_HEADER:           return "truncated-header";
    case MUT_CORRUPT_PAYLOAD:        return "corrupt-payload";
    case MUT_CORRUPT_BLOCK_CHECKSUM: return "corrupt-block-checksum";
    case MUT_OVERSIZED_COMPRESSED:   return "oversized-compressed-block";
    case MUT_OVERSIZED_RAW:          return "oversized-raw-block";
    case MUT_CORRUPT_VALID_CHECKSUM: return "corrupt-block-valid-checksum";
    case MUT_KIND_COUNT:             break;
    }
    return "unknown";
}

static const char* errorCodeName(LZ4F_errorCodes code)
{
    if (code == LZ4F_ERROR_frameType_unknown) return "frameType_unknown";
    if (code == LZ4F_ERROR_headerVersion_wrong) return "headerVersion_wrong";
    if (code == LZ4F_ERROR_reservedFlag_set) return "reservedFlag_set";
    if (code == LZ4F_ERROR_maxBlockSize_invalid) return "maxBlockSize_invalid";
    if (code == LZ4F_ERROR_headerChecksum_invalid) return "headerChecksum_invalid";
    if (code == LZ4F_ERROR_blockChecksum_invalid) return "blockChecksum_invalid";
    return "other error";
}

static int findResource(const Patch* patch, ResourceKind kind)
{
    unsigned i;
    for (i = 0; i < patch->nbResources; i++) {
        if (patch->resource[i].kind == kind) return (int)i;
    }
    return -1;
}

static int findCompressedResource(const Patch* patch)
{
    unsigned i;
    for (i = 0; i < patch->nbResources; i++) {
        if (!patch->resource[i].raw) return (int)i;
    }
    return -1;
}

static int prepareMutation(const Patch* patch, unsigned caseIndex,
                           unsigned char* mutated, size_t mutatedCapacity,
                           Mutation* mutation)
{
    MutationKind const kind = (MutationKind)(caseIndex % (unsigned)MUT_KIND_COUNT);
    int resourceIndex = -1;

    memset(mutation, 0, sizeof(*mutation));
    mutation->name = mutationName(kind);
    mutation->kind = kind;
    mutation->caseIndex = caseIndex;
    mutation->patchIndex = caseIndex % g_defaultValidPatches;
    mutation->frameSize = patch->frameSize;

    if (patch->frameSize > mutatedCapacity) return 0;
    memcpy(mutated, patch->frame, patch->frameSize);

    switch (kind) {
    case MUT_TRUNC_TEXTURE:
        resourceIndex = findResource(patch, RES_TEXTURE);
        break;
    case MUT_TRUNC_MESH:
        resourceIndex = findResource(patch, RES_MESH);
        break;
    case MUT_TRUNC_AUDIO:
        resourceIndex = findResource(patch, RES_AUDIO);
        break;
    case MUT_CORRUPT_PAYLOAD:
    case MUT_CORRUPT_BLOCK_CHECKSUM:
    case MUT_OVERSIZED_COMPRESSED:
    case MUT_OVERSIZED_RAW:
        resourceIndex = (int)((caseIndex / (unsigned)MUT_KIND_COUNT + caseIndex)
                              % patch->nbResources);
        break;
    case MUT_CORRUPT_VALID_CHECKSUM:
        resourceIndex = findCompressedResource(patch);
        break;
    case MUT_BAD_MAGIC:
    case MUT_BAD_FLAGS:
    case MUT_BAD_BLOCKSIZE:
    case MUT_BAD_HEADER_CHECKSUM:
    case MUT_TRUNC_HEADER:
    case MUT_KIND_COUNT:
        break;
    }

    if (resourceIndex >= 0) {
        const Resource* const resource = &patch->resource[resourceIndex];
        mutation->resourceIndex = (unsigned)resourceIndex;
        mutation->hasResource = 1;
        mutation->blockIndex = resource->blockIndex;
        mutation->blockOffset = resource->blockOffset;
        mutation->mutationOffset = resource->blockOffset;
    }

    switch (kind) {
    case MUT_TRUNC_TEXTURE:
    case MUT_TRUNC_MESH:
    case MUT_TRUNC_AUDIO:
        if (!mutation->hasResource) return 0;
        {
            const Resource* const resource = &patch->resource[mutation->resourceIndex];
            size_t cut;
            if (kind == MUT_TRUNC_TEXTURE)
                cut = resource->payloadOffset + resource->storedSize / 3;
            else if (kind == MUT_TRUNC_MESH)
                cut = resource->payloadOffset + (resource->storedSize * 2) / 3;
            else
                cut = resource->payloadOffset + resource->storedSize - 1;
            if (cut <= resource->payloadOffset)
                cut = resource->payloadOffset + 1;   /* keep a truncated payload byte */
            if (cut >= patch->frameSize) return 0;
            mutation->frameSize = cut;
            mutation->mutationOffset = cut;
        }
        break;

    case MUT_BAD_MAGIC:
        mutated[0] ^= 0xA5;
        mutation->mutationOffset = 0;
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_frameType_unknown;
        break;

    case MUT_BAD_FLAGS:
        switch ((caseIndex / (unsigned)MUT_KIND_COUNT) % 3U) {
        case 0:
            mutated[4] |= 0x02;   /* reserved FLG bit */
            mutation->mutationOffset = 4;
            mutation->expectedError = LZ4F_ERROR_reservedFlag_set;
            break;
        case 1:
            mutated[4] &= 0x3F;   /* version 00 */
            mutation->mutationOffset = 4;
            mutation->expectedError = LZ4F_ERROR_headerVersion_wrong;
            break;
        default:
            mutated[14] ^= 0x01;  /* header checksum */
            mutation->mutationOffset = 14;
            mutation->expectedError = LZ4F_ERROR_headerChecksum_invalid;
            break;
        }
        mutation->expectError = 1;
        break;

    case MUT_BAD_BLOCKSIZE:
        mutated[5] = 0x30;        /* block size id 3 */
        mutation->mutationOffset = 5;
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_maxBlockSize_invalid;
        break;

    case MUT_BAD_HEADER_CHECKSUM:
        mutated[14] ^= 0x01;
        mutation->mutationOffset = 14;
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_headerChecksum_invalid;
        break;

    case MUT_TRUNC_HEADER:
        mutation->frameSize = 3U + ((caseIndex / (unsigned)MUT_KIND_COUNT) % 4U);   /* 3..6 bytes */
        if (mutation->frameSize >= GAMEPATCH_FRAME_HEADER_SIZE) return 0;
        mutation->mutationOffset = mutation->frameSize;
        break;

    case MUT_CORRUPT_PAYLOAD:
        if (!mutation->hasResource) return 0;
        {
            const Resource* const resource = &patch->resource[mutation->resourceIndex];
            size_t const pos = resource->payloadOffset
                             + (size_t)(caseIndex * 17U + 3U) % resource->storedSize;
            mutated[pos] ^= 0x5A;
            mutation->mutationOffset = pos;
        }
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_blockChecksum_invalid;
        break;

    case MUT_CORRUPT_BLOCK_CHECKSUM:
        if (!mutation->hasResource) return 0;
        {
            const Resource* const resource = &patch->resource[mutation->resourceIndex];
            size_t const pos = resource->payloadOffset + resource->storedSize;
            mutated[pos] ^= 0x01;
            mutation->mutationOffset = pos;
        }
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_blockChecksum_invalid;
        break;

    case MUT_OVERSIZED_COMPRESSED:
        if (!mutation->hasResource) return 0;
        writeLE32(mutated + mutation->blockOffset,
                  (unsigned)GAMEPATCH_MAX_RESOURCE_SIZE + 1U
                  + (caseIndex / (unsigned)MUT_KIND_COUNT) % 3U);
        mutation->mutationOffset = mutation->blockOffset;
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_maxBlockSize_invalid;
        break;

    case MUT_OVERSIZED_RAW:
        if (!mutation->hasResource) return 0;
        writeLE32(mutated + mutation->blockOffset,
                  0x80000000U
                  | ((unsigned)GAMEPATCH_MAX_RESOURCE_SIZE + 1U
                     + (caseIndex / (unsigned)MUT_KIND_COUNT) % 3U));
        mutation->mutationOffset = mutation->blockOffset;
        mutation->expectError = 1;
        mutation->expectedError = LZ4F_ERROR_maxBlockSize_invalid;
        break;

    case MUT_CORRUPT_VALID_CHECKSUM:
        if (!mutation->hasResource) return 0;
        {
            const Resource* const resource = &patch->resource[mutation->resourceIndex];
            size_t const pos = resource->payloadOffset
                             + (size_t)(caseIndex * 29U + 5U) % resource->storedSize;
            mutated[pos] ^= 0x5A;
            mutation->mutationOffset = pos;
            writeLE32(mutated + resource->payloadOffset + resource->storedSize,
                      XXH32(mutated + resource->payloadOffset, resource->storedSize, 0));
        }
        mutation->expectError = 1;
        mutation->acceptAnyError = 1;
        break;

    case MUT_KIND_COUNT:
    default:
        return 0;
    }

    return 1;
}

static void reportMutationFailure(const Mutation* mutation, const DecodeResult* result,
                                  const char* format, ...)
{
    va_list args;
    fprintf(stderr, "gamepatch: FAIL malformed %u kind=%s patch=%u ",
            mutation->caseIndex + 1, mutation->name, mutation->patchIndex);
    if (mutation->hasResource) {
        fprintf(stderr, "resourceIndex=%u block=%lu blockOffset=%lu ",
                mutation->resourceIndex,
                (unsigned long)mutation->blockIndex,
                (unsigned long)mutation->blockOffset);
    } else {
        fprintf(stderr, "resourceIndex=frame-header block=0 blockOffset=0 ");
    }
    fprintf(stderr, "mutationOffset=%lu frameSize=%lu consumed=%lu produced=%lu ",
            (unsigned long)mutation->mutationOffset,
            (unsigned long)mutation->frameSize,
            (unsigned long)result->consumed,
            (unsigned long)result->produced);
    if (result->isError)
        fprintf(stderr, "error=%s ", LZ4F_getErrorName(result->returnValue));
    else
        fprintf(stderr, "return=%lu ", (unsigned long)result->returnValue);
    fprintf(stderr, "\n  ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}

static int checkMalformedCase(const Patch* patch, const Mutation* mutation,
                              const unsigned char* decodedBase,
                              const DecodeResult* result)
{
    size_t guard;
    size_t prefix;

    if (result->creationFailed) {
        reportMutationFailure(mutation, result, "decompression context creation failed");
        return 0;
    }
    if (result->leaked) {
        reportMutationFailure(mutation, result, "context leaked allocations");
        return 0;
    }
    guard = guardMismatch(decodedBase, patch->plainSize);
    if (guard != 0) {
        reportMutationFailure(mutation, result,
                              "output guard changed at +%lu", (unsigned long)(guard - 1));
        return 0;
    }
    if (result->produced > patch->plainSize) {
        reportMutationFailure(mutation, result,
                              "produced %lu bytes for a %lu-byte patch",
                              (unsigned long)result->produced,
                              (unsigned long)patch->plainSize);
        return 0;
    }

    if (mutation->expectError) {
        if (!result->isError) {
            reportMutationFailure(mutation, result, "malformed frame was not rejected");
            return 0;
        }
        if (!mutation->acceptAnyError && result->errorCode != mutation->expectedError) {
            reportMutationFailure(mutation, result,
                                  "error code %s, expected %s",
                                  LZ4F_getErrorName(result->returnValue),
                                  errorCodeName(mutation->expectedError));
            return 0;
        }
    } else {
        if (result->finished) {
            reportMutationFailure(mutation, result, "truncated frame was reported complete");
            return 0;
        }
        if (!result->isError && result->consumed != mutation->frameSize) {
            reportMutationFailure(mutation, result,
                                  "truncated frame left %lu input bytes unconsumed",
                                  (unsigned long)(mutation->frameSize - result->consumed));
            return 0;
        }
    }

    /* Output before the damaged block must be intact.  A damaged raw block may
     * have been copied before its checksum is verified, so only compare the
     * prefix ending before that block. */
    if (!mutation->hasResource && result->produced != 0) {
        reportMutationFailure(mutation, result,
                              "invalid frame header produced %lu bytes",
                              (unsigned long)result->produced);
        return 0;
    }
    prefix = mutation->hasResource
           ? patch->resource[mutation->resourceIndex].srcOffset
           : 0;
    if (prefix > result->produced) prefix = result->produced;
    if (prefix > 0
        && memcmp(decodedBase + GAMEPATCH_CANARY_SIZE, patch->plain, prefix) != 0) {
        size_t diff;
        for (diff = 0; diff < prefix
                    && decodedBase[GAMEPATCH_CANARY_SIZE + diff] == patch->plain[diff]; diff++) {}
        reportMutationFailure(mutation, result,
                              "output before damaged block differs at +%lu",
                              (unsigned long)diff);
        return 0;
    }

    return 1;
}


/*-************************************
*  Main
**************************************/
static void usage(const char* exeName)
{
    printf("Usage : %s [-v] [-n valid] [-m malformed]\n", exeName);
    printf("  -v : print each valid patch and each malformed case\n");
    printf("  -n : number of valid patches (default %u)\n", g_defaultValidPatches);
    printf("  -m : number of malformed frames (default %u)\n", g_defaultMalformedCases);
}

int main(int argc, char** argv)
{
    unsigned validPatches = g_defaultValidPatches;
    unsigned malformedCases = g_defaultMalformedCases;
    int verbose = 0;
    int i;
    Patch patch;
    unsigned char* mutated;
    unsigned char* decodedBase;
    unsigned char* reference;
    unsigned validOk = 0;
    unsigned malformedOk = 0;
    unsigned rawBlocks = 0;
    unsigned compressedBlocks = 0;
    unsigned resourceHashes = 0;
    unsigned long long corpusHash = 0;
    int failed = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
            validPatches = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
            malformedCases = (unsigned)strtoul(argv[++i], NULL, 10);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!patchInit(&patch)) {
        fprintf(stderr, "gamepatch: allocation failure\n");
        return 1;
    }
    mutated = (unsigned char*)malloc(GAMEPATCH_MAX_FRAME);
    decodedBase = (unsigned char*)malloc(GAMEPATCH_MAX_PLAIN + 2 * GAMEPATCH_CANARY_SIZE);
    reference = (unsigned char*)malloc(GAMEPATCH_MAX_PLAIN);
    if (mutated == NULL || decodedBase == NULL || reference == NULL) {
        fprintf(stderr, "gamepatch: allocation failure\n");
        free(mutated);
        free(decodedBase);
        free(reference);
        patchFree(&patch);
        return 1;
    }

    for (i = 0; i < (int)validPatches; i++) {
        unsigned r;
        if (!buildPatch(&patch, (unsigned)i)) {
            fprintf(stderr, "gamepatch: valid patch %i : generation failed\n", i);
            failed = 1;
            break;
        }
        if (!checkValidPatch(&patch, (unsigned)i, decodedBase, reference, verbose)) {
            failed = 1;
            break;
        }
        validOk++;
        corpusHash ^= patch.hash;
        resourceHashes += patch.nbResources;
        for (r = 0; r < patch.nbResources; r++) {
            if (patch.resource[r].raw) rawBlocks++;
            else compressedBlocks++;
        }
    }

    if (!failed) {
        for (i = 0; i < (int)malformedCases; i++) {
            Mutation mutation;
            DecodeResult result;
            unsigned const chunked = (i & 1) != 0;
            unsigned const patchIndex = (unsigned)i % g_defaultValidPatches;

            if (!buildPatch(&patch, patchIndex)) {
                fprintf(stderr, "gamepatch: malformed %i : patch generation failed\n", i);
                failed = 1;
                break;
            }
            if (!prepareMutation(&patch, (unsigned)i, mutated, GAMEPATCH_MAX_FRAME, &mutation)) {
                fprintf(stderr, "gamepatch: malformed %i : mutation generation failed\n", i);
                failed = 1;
                break;
            }

            memset(decodedBase, GAMEPATCH_CANARY_BYTE,
                   GAMEPATCH_MAX_PLAIN + 2 * GAMEPATCH_CANARY_SIZE);
            if (!decodeFrame(mutated, mutation.frameSize,
                             decodedBase + GAMEPATCH_CANARY_SIZE, patch.plainSize,
                             chunked ? 5 : 0, chunked ? 13 : 0, &result)) {
                if (result.creationFailed)
                    reportMutationFailure(&mutation, &result, "decompression context creation failed");
                else
                    reportMutationFailure(&mutation, &result, "context leaked allocations");
                failed = 1;
                break;
            }
            if (!checkMalformedCase(&patch, &mutation, decodedBase, &result)) {
                failed = 1;
                break;
            }
            malformedOk++;
            if (verbose) {
                printf("malformed %03u/%u : %-24s blockOffset=%lu mutationOffset=%lu result=%s\n",
                       (unsigned)i + 1, malformedCases, mutation.name,
                       (unsigned long)mutation.blockOffset,
                       (unsigned long)mutation.mutationOffset,
                       result.isError ? LZ4F_getErrorName(result.returnValue) : "incomplete");
            }
        }
    }

    if (failed) {
        fprintf(stderr, "gamepatch: FAILED\n");
    } else {
        printf("gamepatch: malformed corpus: %u/%u safely rejected "
               "(0 crashes, 0 output overflows, 0 leaks)\n",
               malformedOk, malformedCases);
        printf("gamepatch: valid corpus: %u/%u byte-identical to reference "
               "(%u resources, %u hashes, %u compressed blocks, %u raw blocks, digest=%016llx)\n",
               validOk, validPatches, resourceHashes, resourceHashes,
               compressedBlocks, rawBlocks, corpusHash);
    }

    free(mutated);
    free(decodedBase);
    free(reference);
    patchFree(&patch);
    return failed;
}
