/*
 * S3 Storage Plugin - Extended API
 *
 * This header provides additional S3-specific functions beyond the
 * standard storage_t interface defined in storage.h.
 */

#ifndef S3_STORAGE_H
#define S3_STORAGE_H

#include "storage.h"
#include <sys/types.h>

/*
 * Callback function type for streaming uploads.
 * Called repeatedly by the upload function to pull data.
 *
 * @param buf      Buffer to fill with data
 * @param len      Maximum bytes to write to buf
 * @param userdata User-provided context
 * @return Number of bytes written to buf, 0 for EOF, -1 for error
 */
typedef ssize_t (*s3_read_callback_t)(void *buf, size_t len, void *userdata);

/*
 * Upload data to S3 using streaming PutObject with a single HTTP request.
 *
 * This function uses UNSIGNED-PAYLOAD signing, which allows true streaming
 * without needing to hash the entire payload upfront. Data is pulled from
 * the provided callback in chunks and sent over a single HTTP connection.
 *
 * Use cases:
 *   - Files < 5GB where you want minimal overhead (single HTTP request)
 *   - Streaming from a pipe, socket, or other data source
 *   - When memory efficiency is critical (only ~64KB buffer needed)
 *
 * For files > 5GB, compile with -DS3_UPLOAD_MODE=MULTIPART to enable
 * multipart uploads via the standard open/write/close interface.
 *
 * @param s              Storage handle (must be S3 storage)
 * @param key            Object key to upload to
 * @param read_cb        Callback that provides data chunks
 * @param userdata       User context passed to read_cb
 * @param content_length Total size if known, or -1 for chunked transfer
 * encoding
 * @return STORAGE_OK on success, error code on failure
 *
 * Example (streaming from file):
 *
 *   ssize_t file_reader(void *buf, size_t len, void *userdata) {
 *       FILE *f = userdata;
 *       size_t n = fread(buf, 1, len, f);
 *       if (ferror(f)) return -1;
 *       return (ssize_t)n;
 *   }
 *
 *   FILE *f = fopen("data.bin", "rb");
 *   fseek(f, 0, SEEK_END);
 *   int64_t size = ftell(f);
 *   fseek(f, 0, SEEK_SET);
 *
 *   int rc = s3_put_streaming(storage, "mykey", file_reader, f, size);
 *   fclose(f);
 *
 * Example (streaming with unknown size):
 *
 *   int rc = s3_put_streaming(storage, "mykey", pipe_reader, pipe_ctx, -1);
 */
int s3_put_streaming(storage_t *s, const char *key, s3_read_callback_t read_cb,
                     void *userdata, int64_t content_length);

/*
 * Set expected upload size for streaming mode with storage API (optional).
 *
 * When using S3_UPLOAD_STREAMING mode with the standard storage API
 * (open/write/close), you can optionally call this function after open()
 * but before the first write() to set the expected total file size.
 *
 * Benefits of setting size:
 *   - S3 can optimize storage allocation
 *   - Better compatibility with some S3-compatible backends
 *   - Avoids chunked transfer encoding overhead
 *
 * If not called, the upload uses chunked transfer encoding:
 *   Transfer-Encoding: chunked
 *   x-amz-content-sha256: UNSIGNED-PAYLOAD
 *
 * @param f    File handle from storage_open()
 * @param size Expected total size in bytes
 * @return STORAGE_OK on success, error code on failure
 *
 * Example (with known size):
 *
 *   storage_file_t *f = storage_open(s, "mykey", STORAGE_MODE_WRITE);
 *   s3_set_upload_size(f, file_size);  // Optional, before first write
 *   storage_write(f, data, len);
 *   storage_close(f);
 *
 * Example (unknown size - uses chunked encoding):
 *
 *   storage_file_t *f = storage_open(s, "mykey", STORAGE_MODE_WRITE);
 *   while ((n = read(fd, buf, sizeof(buf))) > 0)
 *     storage_write(f, buf, n);
 *   storage_close(f);
 */
int s3_set_upload_size(storage_file_t *f, int64_t size);

#endif // S3_STORAGE_H
