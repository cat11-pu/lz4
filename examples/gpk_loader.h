#ifndef GPK_LOADER_H
#define GPK_LOADER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GPK_TYPE_TEXTURE 1u
#define GPK_TYPE_MESH    2u
#define GPK_TYPE_AUDIO   3u

typedef enum {
    GPK_OK = 0,
    GPK_ERR_ARGUMENT,
    GPK_ERR_TRUNCATED,
    GPK_ERR_BAD_MAGIC,
    GPK_ERR_BAD_VERSION,
    GPK_ERR_BAD_CHUNK_COUNT,
    GPK_ERR_BAD_CHUNK_TYPE,
    GPK_ERR_RESERVED_FLAGS,
    GPK_ERR_SIZE_LIMIT,
    GPK_ERR_SIZE_OVERFLOW,
    GPK_ERR_FRAME_HEADER,
    GPK_ERR_FRAME_TYPE,
    GPK_ERR_CONTENT_SIZE,
    GPK_ERR_UNSUPPORTED_FRAME,
    GPK_ERR_DECOMPRESSION,
    GPK_ERR_TRUNCATED_FRAME,
    GPK_ERR_TRAILING_DATA,
    GPK_ERR_OUTPUT_SIZE,
    GPK_ERR_ALLOCATION
} gpk_status;

typedef struct {
    unsigned type;
    unsigned flags;
    size_t record_offset;
    size_t payload_offset;
    size_t compressed_size;
    size_t uncompressed_size;
    size_t capacity;
    size_t produced;
    unsigned char* data;
} gpk_chunk;

typedef struct {
    unsigned version;
    unsigned chunk_count;
    gpk_chunk* chunks;
} gpk_archive;

typedef struct {
    gpk_status status;
    unsigned chunk_index;
    size_t record_offset;
    size_t payload_offset;
    const char* message;
} gpk_error;

typedef struct {
    size_t max_chunk_size;
    size_t max_total_size;
    unsigned max_chunks;
} gpk_limits;

#define GPK_DEFAULT_MAX_CHUNK_SIZE (64u * 1024u * 1024u)
#define GPK_DEFAULT_MAX_TOTAL_SIZE (256u * 1024u * 1024u)
#define GPK_DEFAULT_MAX_CHUNKS     65536u

/* Decode a GPK1 archive.
 *
 * Every size, count, offset and LZ4 frame field is treated as untrusted.
 * Output is grown only as bytes are actually produced, and never beyond
 * min(chunk.uncompressed_size, limits.max_chunk_size).
 *
 * On failure, *error describes the rejection and the archive is left empty.
 * The error always carries a chunk index and offsets; file-level errors use
 * chunk_index 0 and record_offset 0.
 */
int gpk_load(const void* file_data, size_t file_size,
             const gpk_limits* limits,
             gpk_archive* archive, gpk_error* error);

void gpk_free(gpk_archive* archive);

const char* gpk_status_name(gpk_status status);
const char* gpk_type_name(unsigned type);

#ifdef __cplusplus
}
#endif

#endif
