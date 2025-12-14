/*
 * nf_pngdecode - Simplified PNG decoder for NeuroFuzz research
 * 
 * This target demonstrates complex parsing logic with:
 * - Magic byte validation (symbolic execution benefit)
 * - CRC32 checksum verification (constraint solving)
 * - Multiple vulnerability paths (buffer overflow, integer overflow, format string)
 * - Nested conditions requiring hybrid fuzzing approach
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define PNG_SIGNATURE_SIZE 8
#define CHUNK_HEADER_SIZE 8
#define MAX_CHUNK_SIZE 65536
#define MAX_WIDTH 4096
#define MAX_HEIGHT 4096

// PNG file signature
static const uint8_t PNG_SIGNATURE[PNG_SIGNATURE_SIZE] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

// Chunk types
#define IHDR_TYPE 0x49484452
#define PLTE_TYPE 0x504C5445
#define IDAT_TYPE 0x49444154
#define IEND_TYPE 0x49454E44
#define tEXt_TYPE 0x74455874

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t bit_depth;
    uint8_t color_type;
    uint8_t compression;
    uint8_t filter;
    uint8_t interlace;
} IHDR;

// Simplified CRC32 (vulnerable by design for symbolic execution)
uint32_t simple_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

// Read 32-bit big-endian
uint32_t read_be32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

// VULNERABILITY 1: Buffer overflow in palette processing
int process_palette(const uint8_t *data, uint32_t length) {
    char palette_buffer[256];  // Fixed size
    
    // Missing bounds check - buffer overflow
    if (length > 100) {  // Weak check, can still overflow
        memcpy(palette_buffer, data, length);  // BUG: No proper size validation
        return 1;
    }
    return 0;
}

// VULNERABILITY 2: Integer overflow in dimension calculation
int validate_dimensions(IHDR *header) {
    uint32_t total_pixels = header->width * header->height;  // Integer overflow possible
    
    // This check can be bypassed with overflow
    if (total_pixels > MAX_WIDTH * MAX_HEIGHT) {
        return 0;
    }
    
    // Allocate based on overflowed value (heap overflow)
    uint8_t *image_data = malloc(total_pixels);
    if (!image_data) {
        return 0;
    }
    
    // Use the buffer (simplified)
    memset(image_data, 0, total_pixels);
    free(image_data);
    return 1;
}

// VULNERABILITY 3: Format string in text chunk processing
void process_text_chunk(const uint8_t *data, uint32_t length) {
    char keyword[80];
    char text[256];
    
    if (length < 1 || length > 300) return;
    
    // Extract keyword (null-terminated)
    size_t keyword_len = 0;
    while (keyword_len < length && keyword_len < 79 && data[keyword_len] != 0) {
        keyword[keyword_len] = data[keyword_len];
        keyword_len++;
    }
    keyword[keyword_len] = 0;
    
    // Extract text
    if (keyword_len + 1 < length) {
        size_t text_len = length - keyword_len - 1;
        if (text_len < 255) {
            memcpy(text, data + keyword_len + 1, text_len);
            text[text_len] = 0;
            
            // VULNERABILITY: Format string bug
            if (strcmp(keyword, "Comment") == 0) {
                printf(text);  // BUG: User-controlled format string
                fflush(stdout);
            }
        }
    }
}

// VULNERABILITY 4: Use-after-free in chunk processing
typedef struct chunk_cache {
    uint8_t *data;
    uint32_t size;
    uint32_t type;
} chunk_cache_t;

chunk_cache_t *global_cache = NULL;

void cache_chunk(uint32_t type, const uint8_t *data, uint32_t size) {
    if (global_cache) {
        free(global_cache->data);
        free(global_cache);
    }
    
    global_cache = malloc(sizeof(chunk_cache_t));
    global_cache->data = malloc(size);
    global_cache->size = size;
    global_cache->type = type;
    memcpy(global_cache->data, data, size);
}

void use_cached_chunk() {
    if (global_cache) {
        // Simulate processing
        for (uint32_t i = 0; i < global_cache->size; i++) {
            global_cache->data[i] ^= 0xFF;
        }
    }
}

void free_cache() {
    if (global_cache) {
        free(global_cache->data);
        free(global_cache);
        global_cache = NULL;  // Proper cleanup
    }
}

// Main PNG parsing logic
int parse_png(const uint8_t *data, size_t size) {
    size_t offset = 0;
    
    // Check PNG signature (symbolic execution target)
    if (size < PNG_SIGNATURE_SIZE) {
        return -1;
    }
    
    if (memcmp(data, PNG_SIGNATURE, PNG_SIGNATURE_SIZE) != 0) {
        return -1;
    }
    offset += PNG_SIGNATURE_SIZE;
    
    int ihdr_found = 0;
    int idat_count = 0;
    IHDR header = {0};
    
    // Process chunks
    while (offset + CHUNK_HEADER_SIZE + 4 <= size) {
        // Read chunk length
        uint32_t chunk_length = read_be32(data + offset);
        offset += 4;
        
        // Read chunk type
        uint32_t chunk_type = read_be32(data + offset);
        offset += 4;
        
        // Validate chunk size
        if (chunk_length > MAX_CHUNK_SIZE || offset + chunk_length + 4 > size) {
            break;
        }
        
        const uint8_t *chunk_data = data + offset;
        offset += chunk_length;
        
        // Read CRC
        uint32_t stored_crc = read_be32(data + offset);
        offset += 4;
        
        // Verify CRC (symbolic execution can find valid CRCs)
        uint8_t crc_input[MAX_CHUNK_SIZE + 4];
        memcpy(crc_input, data + offset - chunk_length - 8, 4);  // Type
        if (chunk_length > 0 && chunk_length < MAX_CHUNK_SIZE) {
            memcpy(crc_input + 4, chunk_data, chunk_length);
        }
        uint32_t computed_crc = simple_crc32(crc_input, 4 + chunk_length);
        
        if (stored_crc != computed_crc) {
            // Lenient: continue anyway for fuzzing
            // fprintf(stderr, "CRC mismatch\n");
        }
        
        // Process chunk by type
        switch (chunk_type) {
            case IHDR_TYPE:
                if (chunk_length != 13) break;
                
                header.width = read_be32(chunk_data);
                header.height = read_be32(chunk_data + 4);
                header.bit_depth = chunk_data[8];
                header.color_type = chunk_data[9];
                header.compression = chunk_data[10];
                header.filter = chunk_data[11];
                header.interlace = chunk_data[12];
                
                // Trigger integer overflow vulnerability
                if (!validate_dimensions(&header)) {
                    // Continue anyway
                }
                
                ihdr_found = 1;
                cache_chunk(chunk_type, chunk_data, chunk_length);
                break;
                
            case PLTE_TYPE:
                // Trigger buffer overflow vulnerability
                process_palette(chunk_data, chunk_length);
                cache_chunk(chunk_type, chunk_data, chunk_length);
                break;
                
            case IDAT_TYPE:
                idat_count++;
                
                // Deep condition: trigger use-after-free
                if (idat_count == 3 && ihdr_found) {
                    use_cached_chunk();
                    free_cache();  // Free
                    use_cached_chunk();  // Use-after-free
                }
                break;
                
            case tEXt_TYPE:
                // Trigger format string vulnerability
                process_text_chunk(chunk_data, chunk_length);
                break;
                
            case IEND_TYPE:
                free_cache();
                return 0;  // Success
        }
        
        // Secret backdoor: specific sequence triggers crash
        if (chunk_type == 0xDEADBEEF && chunk_length == 16) {
            if (chunk_data[0] == 'N' && chunk_data[1] == 'F' && 
                chunk_data[2] == 'U' && chunk_data[3] == 'Z') {
                // Hidden crash path
                char *null_ptr = NULL;
                *null_ptr = 42;  // Crash
            }
        }
    }
    
    free_cache();
    return ihdr_found ? 0 : -1;
}

int main(int argc, char **argv) {
    uint8_t buffer[65536];
    size_t total_read = 0;
    
    // Read from stdin
    ssize_t n;
    while ((n = read(STDIN_FILENO, buffer + total_read, sizeof(buffer) - total_read)) > 0) {
        total_read += n;
        if (total_read >= sizeof(buffer)) break;
    }
    
    if (total_read < PNG_SIGNATURE_SIZE) {
        return 1;
    }
    
    // Parse PNG
    int result = parse_png(buffer, total_read);
    
    return result == 0 ? 0 : 1;
}
