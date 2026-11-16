#include "gpk_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lz4frame.h"

#define GPK_HEADER_SIZE 12u
#define GPK_RECORD_SIZE 16u
#define GPK_SCRATCH_SIZE (64u * 1024u)

static unsigned long long gpk_read32(const unsigned char* src)
{
    return (unsigned long long)src[0]
         | ((unsigned long long)src[1] << 8)
         | ((unsigned long long)src[2] << 16)
         | ((unsigned long long)src[3] << 24);
}

static int gpk_table_fits(size_t count, size_t element_size)
{
    return element_size == 0 || count <= (size_t)-1 / element_size;
}

static void gpk_clear_error(gpk_error* error)
{
    if (error == NULL) return;
    memset(error, 0, sizeof(*error));
    error->status = GPK_OK;
    error->message = "ok";
}

static int gpk_fail(gpk_error* error, gpk_status status, unsigned chunk_index,
                    size_t record_offset, size_t payload_offset,
                    const char* message)
{
    if (error != NULL) {
        error->status = status;
        error->chunk_index = chunk_index;
        error->record_offset = record_offset;
        error->payload_offset = payload_offset;
        error->message = message;
    }
    return (int)status;
}

static void gpk_free_chunks(gpk_chunk* chunks, unsigned count)
{
    unsigned i;
    if (chunks == NULL) return;
    for (i = 0; i < count; i++) free(chunks[i].data);
    free(chunks);
}

void gpk_free(gpk_archive* archive)
{
    if (archive == NULL) return;
    gpk_free_chunks(archive->chunks, archive->chunk_count);
    archive->chunks = NULL;
    archive->chunk_count = 0;
    archive->version = 0;
}

const char* gpk_status_name(gpk_status status)
{
    switch (status) {
    case GPK_OK: return "OK";
    case GPK_ERR_ARGUMENT: return "ARGUMENT";
    case GPK_ERR_TRUNCATED: return "TRUNCATED";
    case GPK_ERR_BAD_MAGIC: return "BAD_MAGIC";
    case GPK_ERR_BAD_VERSION: return "BAD_VERSION";
    case GPK_ERR_BAD_CHUNK_COUNT: return "BAD_CHUNK_COUNT";
    case GPK_ERR_BAD_CHUNK_TYPE: return "BAD_CHUNK_TYPE";
    case GPK_ERR_RESERVED_FLAGS: return "RESERVED_FLAGS";
    case GPK_ERR_SIZE_LIMIT: return "SIZE_LIMIT";
    case GPK_ERR_SIZE_OVERFLOW: return "SIZE_OVERFLOW";
    case GPK_ERR_FRAME_HEADER: return "FRAME_HEADER";
    case GPK_ERR_FRAME_TYPE: return "FRAME_TYPE";
    case GPK_ERR_CONTENT_SIZE: return "CONTENT_SIZE";
    case GPK_ERR_UNSUPPORTED_FRAME: return "UNSUPPORTED_FRAME";
    case GPK_ERR_DECOMPRESSION: return "DECOMPRESSION";
    case GPK_ERR_TRUNCATED_FRAME: return "TRUNCATED_FRAME";
    case GPK_ERR_TRAILING_DATA: return "TRAILING_DATA";
    case GPK_ERR_OUTPUT_SIZE: return "OUTPUT_SIZE";
    case GPK_ERR_ALLOCATION: return "ALLOCATION";
    default: return "UNKNOWN";
    }
}

const char* gpk_type_name(unsigned type)
{
    switch (type) {
    case GPK_TYPE_TEXTURE: return "texture";
    case GPK_TYPE_MESH: return "mesh";
    case GPK_TYPE_AUDIO: return "audio";
    default: return "unknown";
    }
}

static int gpk_grow(gpk_chunk* chunk, size_t needed, gpk_error* error,
                    unsigned chunk_index)
{
    size_t new_capacity;
    unsigned char* new_data;

    if (needed <= chunk->capacity) return 0;
    if (needed > chunk->uncompressed_size) {
        return gpk_fail(error, GPK_ERR_OUTPUT_SIZE, chunk_index,
                        chunk->record_offset, chunk->payload_offset,
                        "decompressed data exceeds the declared size");
    }

    new_capacity = chunk->capacity ? chunk->capacity : 4096u;
    if (new_capacity > chunk->uncompressed_size)
        new_capacity = chunk->uncompressed_size;
    while (new_capacity < needed) {
        size_t next = new_capacity * 2u;
        if (next < new_capacity || next > chunk->uncompressed_size)
            next = chunk->uncompressed_size;
        if (next <= new_capacity)
            return gpk_fail(error, GPK_ERR_OUTPUT_SIZE, chunk_index,
                            chunk->record_offset, chunk->payload_offset,
                            "decompressed data exceeds the declared size");
        new_capacity = next;
    }

    new_data = (unsigned char*)malloc(new_capacity ? new_capacity : 1u);
    if (new_data == NULL) {
        return gpk_fail(error, GPK_ERR_ALLOCATION, chunk_index,
                        chunk->record_offset, chunk->payload_offset,
                        "output allocation failed");
    }
    if (chunk->data != NULL) {
        if (chunk->produced != 0)
            memcpy(new_data, chunk->data, chunk->produced);
        free(chunk->data);
    }
    chunk->data = new_data;
    chunk->capacity = new_capacity;
    return 0;
}

static int gpk_decode_frame(gpk_chunk* chunk,
                            const unsigned char* payload,
                            gpk_error* error, unsigned chunk_index)
{
    LZ4F_dctx* dctx = NULL;
    LZ4F_frameInfo_t frame_info;
    unsigned char* scratch = NULL;
    size_t consumed = 0;
    size_t produced = 0;
    size_t hint;
    int result = 0;

    memset(&frame_info, 0, sizeof(frame_info));
    scratch = (unsigned char*)malloc(GPK_SCRATCH_SIZE);
    if (scratch == NULL) {
        return gpk_fail(error, GPK_ERR_ALLOCATION, chunk_index,
                        chunk->record_offset, chunk->payload_offset,
                        "scratch allocation failed");
    }
    if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION))) {
        free(scratch);
        return gpk_fail(error, GPK_ERR_ALLOCATION, chunk_index,
                        chunk->record_offset, chunk->payload_offset,
                        "decompression context allocation failed");
    }

    if (chunk->compressed_size < LZ4F_HEADER_SIZE_MIN) {
        result = gpk_fail(error, GPK_ERR_TRUNCATED_FRAME, chunk_index,
                          chunk->record_offset, chunk->payload_offset,
                          "truncated LZ4 frame header");
        goto _cleanup;
    }

    consumed = chunk->compressed_size;
    hint = LZ4F_getFrameInfo(dctx, &frame_info, payload, &consumed);
    if (LZ4F_isError(hint)) {
        result = gpk_fail(error, GPK_ERR_FRAME_HEADER, chunk_index,
                          chunk->record_offset, chunk->payload_offset,
                          LZ4F_getErrorName(hint));
        goto _cleanup;
    }
    if (frame_info.frameType != LZ4F_frame) {
        result = gpk_fail(error, GPK_ERR_FRAME_TYPE, chunk_index,
                          chunk->record_offset, chunk->payload_offset,
                          "skippable frames are not resource data");
        goto _cleanup;
    }
    if (frame_info.dictID != 0) {
        result = gpk_fail(error, GPK_ERR_UNSUPPORTED_FRAME, chunk_index,
                          chunk->record_offset, chunk->payload_offset,
                          "dictionary frames are not supported");
        goto _cleanup;
    }
    if (frame_info.contentSize != 0
     && frame_info.contentSize != (unsigned long long)chunk->uncompressed_size) {
        result = gpk_fail(error, GPK_ERR_CONTENT_SIZE, chunk_index,
                          chunk->record_offset, chunk->payload_offset,
                          "frame content size differs from the record");
        goto _cleanup;
    }
    if (consumed > chunk->compressed_size
     || chunk->compressed_size - consumed < 4) {
        result = gpk_fail(error, GPK_ERR_TRUNCATED_FRAME, chunk_index,
                          chunk->record_offset, chunk->payload_offset,
                          "LZ4 frame has no end mark");
        goto _cleanup;
    }

    for (;;) {
        size_t src_available = chunk->compressed_size - consumed;
        size_t dst_capacity = GPK_SCRATCH_SIZE;
        size_t src_size = src_available;
        size_t dst_size = dst_capacity;
        size_t remaining = chunk->uncompressed_size - produced;

        if (dst_size > remaining) dst_size = remaining;
        if (src_available == 0) {
            result = gpk_fail(error, GPK_ERR_TRUNCATED_FRAME, chunk_index,
                              chunk->record_offset, chunk->payload_offset,
                              "LZ4 frame ends before its end mark");
            goto _cleanup;
        }

        hint = LZ4F_decompress(dctx, scratch, &dst_size,
                               payload + consumed, &src_size, NULL);
        if (LZ4F_isError(hint)) {
            result = gpk_fail(error, GPK_ERR_DECOMPRESSION, chunk_index,
                              chunk->record_offset, chunk->payload_offset,
                              LZ4F_getErrorName(hint));
            goto _cleanup;
        }
        if (src_size > src_available || dst_size > dst_capacity) {
            result = gpk_fail(error, GPK_ERR_DECOMPRESSION, chunk_index,
                              chunk->record_offset, chunk->payload_offset,
                              "LZ4 decompressor reported an invalid size");
            goto _cleanup;
        }

        if (dst_size != 0) {
            size_t needed = produced + dst_size;
            if (needed < produced || needed > chunk->uncompressed_size) {
                result = gpk_fail(error, GPK_ERR_OUTPUT_SIZE, chunk_index,
                                  chunk->record_offset, chunk->payload_offset,
                                  "decompressed data exceeds the declared size");
                goto _cleanup;
            }
            chunk->produced = produced;
            result = gpk_grow(chunk, needed, error, chunk_index);
            if (result != 0) goto _cleanup;
            memcpy(chunk->data + produced, scratch, dst_size);
            produced += dst_size;
            chunk->produced = produced;
        }
        consumed += src_size;

        if (hint == 0) {
            if (consumed != chunk->compressed_size) {
                result = gpk_fail(error, GPK_ERR_TRAILING_DATA, chunk_index,
                                  chunk->record_offset,
                                  chunk->payload_offset,
                                  "bytes remain after the LZ4 frame");
                goto _cleanup;
            }
            if (produced != chunk->uncompressed_size) {
                result = gpk_fail(error, GPK_ERR_OUTPUT_SIZE, chunk_index,
                                  chunk->record_offset,
                                  chunk->payload_offset,
                                  "decompressed size differs from the record");
                goto _cleanup;
            }
            break;
        }

        if (src_size == 0 && dst_size == 0) {
            result = gpk_fail(error, GPK_ERR_DECOMPRESSION, chunk_index,
                              chunk->record_offset, chunk->payload_offset,
                              "LZ4 decompressor made no progress");
            goto _cleanup;
        }
        if (consumed == chunk->compressed_size && src_size == 0) {
            result = gpk_fail(error, GPK_ERR_TRUNCATED_FRAME, chunk_index,
                              chunk->record_offset, chunk->payload_offset,
                              "LZ4 frame ends before its end mark");
            goto _cleanup;
        }
    }

_cleanup:
    LZ4F_freeDecompressionContext(dctx);
    free(scratch);
    chunk->produced = produced;
    return result;
}

int gpk_load(const void* file_data, size_t file_size,
             const gpk_limits* limits,
             gpk_archive* archive, gpk_error* error)
{
    const unsigned char* data = (const unsigned char*)file_data;
    gpk_limits default_limits;
    gpk_limits const* lim = limits;
    gpk_chunk* chunks = NULL;
    size_t offset = GPK_HEADER_SIZE;
    size_t total_size = 0;
    unsigned count;
    unsigned i;
    int result;

    gpk_clear_error(error);
    if (archive == NULL) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "archive output is required");
    }
    memset(archive, 0, sizeof(*archive));
    if (data == NULL) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "input buffer is required");
    }

    if (lim == NULL) {
        default_limits.max_chunk_size = GPK_DEFAULT_MAX_CHUNK_SIZE;
        default_limits.max_total_size = GPK_DEFAULT_MAX_TOTAL_SIZE;
        default_limits.max_chunks = GPK_DEFAULT_MAX_CHUNKS;
        lim = &default_limits;
    }
    if (lim->max_chunk_size == 0 || lim->max_total_size == 0
     || lim->max_chunks == 0) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "limits must be non-zero");
    }

    if (file_size < GPK_HEADER_SIZE) {
        return gpk_fail(error, GPK_ERR_TRUNCATED, 0, 0, 0,
                        "truncated GPK header");
    }
    if (memcmp(data, "GPK1", 4) != 0) {
        return gpk_fail(error, GPK_ERR_BAD_MAGIC, 0, 0, 0,
                        "bad GPK magic");
    }
    if (gpk_read32(data + 4) != 1) {
        return gpk_fail(error, GPK_ERR_BAD_VERSION, 0, 4, 0,
                        "unsupported GPK version");
    }

    count = (unsigned)gpk_read32(data + 8);
    if (count == 0) {
        return gpk_fail(error, GPK_ERR_BAD_CHUNK_COUNT, 0, 8, 0,
                        "archive declares no chunks");
    }
    if (count > lim->max_chunks) {
        return gpk_fail(error, GPK_ERR_SIZE_LIMIT, 0, 8, 0,
                        "chunk count exceeds the configured limit");
    }
    if ((size_t)count > (file_size - GPK_HEADER_SIZE) / GPK_RECORD_SIZE) {
        return gpk_fail(error, GPK_ERR_TRUNCATED, 0, 8, 0,
                        "chunk count does not fit in the file");
    }
    if (!gpk_table_fits((size_t)count, sizeof(gpk_chunk))) {
        return gpk_fail(error, GPK_ERR_SIZE_OVERFLOW, 0, 8, 0,
                        "chunk table size overflow");
    }

    chunks = (gpk_chunk*)calloc(count, sizeof(gpk_chunk));
    if (chunks == NULL) {
        return gpk_fail(error, GPK_ERR_ALLOCATION, 0, 8, 0,
                        "chunk table allocation failed");
    }

    for (i = 0; i < count; i++) {
        gpk_chunk* const chunk = &chunks[i];
        size_t record_offset = offset;
        size_t payload_offset;
        unsigned long long compressed_size;
        unsigned long long uncompressed_size;

        if (offset > file_size || file_size - offset < GPK_RECORD_SIZE) {
            gpk_free_chunks(chunks, count);
            return gpk_fail(error, GPK_ERR_TRUNCATED, i, record_offset, 0,
                            "truncated chunk record");
        }
        chunk->type = (unsigned)gpk_read32(data + offset);
        chunk->flags = (unsigned)gpk_read32(data + offset + 4);
        compressed_size = gpk_read32(data + offset + 8);
        uncompressed_size = gpk_read32(data + offset + 12);
        offset += GPK_RECORD_SIZE;
        payload_offset = offset;
        chunk->record_offset = record_offset;
        chunk->payload_offset = payload_offset;

        if (chunk->type < GPK_TYPE_TEXTURE || chunk->type > GPK_TYPE_AUDIO) {
            gpk_free_chunks(chunks, count);
            return gpk_fail(error, GPK_ERR_BAD_CHUNK_TYPE, i, record_offset,
                            payload_offset, "unknown chunk type");
        }
        if (chunk->flags != 0) {
            gpk_free_chunks(chunks, count);
            return gpk_fail(error, GPK_ERR_RESERVED_FLAGS, i, record_offset,
                            payload_offset, "reserved chunk flags are set");
        }
        if (compressed_size > (unsigned long long)(file_size - offset)) {
            gpk_free_chunks(chunks, count);
            return gpk_fail(error, GPK_ERR_TRUNCATED, i, record_offset,
                            payload_offset, "truncated chunk payload");
        }
        if (uncompressed_size > (unsigned long long)lim->max_chunk_size) {
            gpk_free_chunks(chunks, count);
            return gpk_fail(error, GPK_ERR_SIZE_LIMIT, i, record_offset,
                            payload_offset,
                            "declared chunk size exceeds the configured limit");
        }
        if ((size_t)uncompressed_size > lim->max_total_size - total_size) {
            gpk_free_chunks(chunks, count);
            return gpk_fail(error, GPK_ERR_SIZE_LIMIT, i, record_offset,
                            payload_offset,
                            "total declared size exceeds the configured limit");
        }

        chunk->compressed_size = (size_t)compressed_size;
        chunk->uncompressed_size = (size_t)uncompressed_size;
        result = gpk_decode_frame(chunk, data + payload_offset, error, i);
        if (result != 0) {
            gpk_free_chunks(chunks, count);
            return result;
        }

        total_size += chunk->uncompressed_size;
        offset += chunk->compressed_size;
    }

    if (offset != file_size) {
        gpk_free_chunks(chunks, count);
        return gpk_fail(error, GPK_ERR_TRAILING_DATA, count - 1,
                        offset, offset,
                        "bytes remain after the last chunk");
    }

    archive->version = 1;
    archive->chunk_count = count;
    archive->chunks = chunks;
    return 0;
}

static int gpk_read_file(const char* path, unsigned char** data, size_t* size,
                         gpk_error* error)
{
    FILE* file;
    long length;
    unsigned char* buffer;

    *data = NULL;
    *size = 0;
    file = fopen(path, "rb");
    if (file == NULL) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "cannot open input file");
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "cannot seek input file");
    }
    length = ftell(file);
    if (length < 0) {
        fclose(file);
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "cannot size input file");
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return gpk_fail(error, GPK_ERR_ARGUMENT, 0, 0, 0,
                        "cannot rewind input file");
    }
    buffer = (unsigned char*)malloc((size_t)length ? (size_t)length : 1u);
    if (buffer == NULL) {
        fclose(file);
        return gpk_fail(error, GPK_ERR_ALLOCATION, 0, 0, 0,
                        "input allocation failed");
    }
    if (length != 0
     && fread(buffer, 1, (size_t)length, file) != (size_t)length) {
        free(buffer);
        fclose(file);
        return gpk_fail(error, GPK_ERR_TRUNCATED, 0, 0, 0,
                        "cannot read input file");
    }
    fclose(file);
    *data = buffer;
    *size = (size_t)length;
    return 0;
}

static int gpk_write_chunk(const char* directory, unsigned index,
                           const gpk_chunk* chunk, gpk_error* error)
{
    char path[4096];
    FILE* file;
    int length;

    length = snprintf(path, sizeof(path), "%s/%04u-%s.bin", directory, index,
                      gpk_type_name(chunk->type));
    if (length < 0 || (size_t)length >= sizeof(path)) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, index, chunk->record_offset,
                        chunk->payload_offset, "output path is too long");
    }
    file = fopen(path, "wb");
    if (file == NULL) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, index, chunk->record_offset,
                        chunk->payload_offset, "cannot open output file");
    }
    if (chunk->produced != 0
     && fwrite(chunk->data, 1, chunk->produced, file) != chunk->produced) {
        fclose(file);
        return gpk_fail(error, GPK_ERR_ARGUMENT, index, chunk->record_offset,
                        chunk->payload_offset, "cannot write output file");
    }
    if (fclose(file) != 0) {
        return gpk_fail(error, GPK_ERR_ARGUMENT, index, chunk->record_offset,
                        chunk->payload_offset, "cannot close output file");
    }
    return 0;
}

static void gpk_usage(const char* program)
{
    fprintf(stderr,
            "usage: %s check FILE\n"
            "       %s list FILE\n"
            "       %s extract FILE OUTPUT_DIRECTORY\n",
            program, program, program);
}

static int gpk_report_error(const char* program, const gpk_error* error)
{
    fprintf(stderr,
            "%s: error=%s code=%d chunk=%u offset=%lu payload=%lu detail=%s\n",
            program, gpk_status_name(error->status), (int)error->status,
            error->chunk_index, (unsigned long)error->record_offset,
            (unsigned long)error->payload_offset,
            error->message ? error->message : "unknown");
    return 1;
}

int main(int argc, char** argv)
{
    const char* command;
    const char* path;
    const char* output_directory = NULL;
    unsigned char* data = NULL;
    size_t size = 0;
    gpk_archive archive;
    gpk_error error;
    size_t total = 0;
    unsigned i;
    int result;

    if (argc < 3 || argc > 4) {
        gpk_usage(argv[0]);
        return 2;
    }
    command = argv[1];
    path = argv[2];
    if (strcmp(command, "extract") == 0) {
        if (argc != 4) {
            gpk_usage(argv[0]);
            return 2;
        }
        output_directory = argv[3];
    } else if (strcmp(command, "check") != 0 && strcmp(command, "list") != 0) {
        gpk_usage(argv[0]);
        return 2;
    } else if (argc != 3) {
        gpk_usage(argv[0]);
        return 2;
    }

    result = gpk_read_file(path, &data, &size, &error);
    if (result != 0) {
        free(data);
        return gpk_report_error(argv[0], &error);
    }
    result = gpk_load(data, size, NULL, &archive, &error);
    if (result != 0) {
        free(data);
        return gpk_report_error(argv[0], &error);
    }

    for (i = 0; i < archive.chunk_count; i++) {
        const gpk_chunk* const chunk = &archive.chunks[i];
        total += chunk->produced;
        if (strcmp(command, "list") == 0) {
            printf("chunk=%u type=%s offset=%lu payload=%lu compressed=%lu "
                   "uncompressed=%lu\n",
                   i, gpk_type_name(chunk->type),
                   (unsigned long)chunk->record_offset,
                   (unsigned long)chunk->payload_offset,
                   (unsigned long)chunk->compressed_size,
                   (unsigned long)chunk->produced);
        }
        if (output_directory != NULL) {
            result = gpk_write_chunk(output_directory, i, chunk, &error);
            if (result != 0) {
                gpk_free(&archive);
                free(data);
                return gpk_report_error(argv[0], &error);
            }
        }
    }

    if (strcmp(command, "list") != 0) {
        printf("ok chunks=%u bytes=%lu\n", archive.chunk_count,
               (unsigned long)total);
    }
    gpk_free(&archive);
    free(data);
    return 0;
}
