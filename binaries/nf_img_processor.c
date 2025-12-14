/*
 * nf_img_processor.c
 * 
 * NeuroFuzz Benchmark Binary: "Image Processor"
 * 
 * Designed to demonstrate the superiority of Hybrid Fuzzing (RL + SymEx) over
 * pure Coverage-Guided Fuzzing (AFL++).
 * 
 * Features:
 * 1. Magic Bytes Header ("IMGP") - Blocks shallow fuzzers.
 * 2. Checksum Validation - Blocks fuzzers that mutate randomly without constraint solving.
 * 3. Complex State Machine - Requires specific sequence of chunks.
 * 4. Vulnerabilities:
 *    - Stack Buffer Overflow (in DATA chunk)
 *    - Integer Overflow (in SIZE calculation)
 *    - Format String (in META chunk)
 *    - Use-After-Free (in cleanup)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// ----------------------------------------------------------------------
// CONFIGURATION
// ----------------------------------------------------------------------
#define HEADER_MAGIC 0x50474D49 // "IMGP" in little-endian
#define MAX_CHUNKS 16
#define CHUNK_SIZE 256

// ----------------------------------------------------------------------
// STRUCTURES
// ----------------------------------------------------------------------
typedef struct {
    uint32_t magic;     // Must be "IMGP"
    uint16_t version;   // Must be 0x0001
    uint16_t checksum;  // XOR sum of the rest of the file
    uint32_t num_chunks;
} FileHeader;

typedef struct {
    char type[4];       // "DATA", "META", "SIZE", "END "
    uint32_t length;
    uint8_t data[CHUNK_SIZE];
} Chunk;

// ----------------------------------------------------------------------
// GLOBALS
// ----------------------------------------------------------------------
char *metadata_ptr = NULL;
int image_width = 0;
int image_height = 0;

// ----------------------------------------------------------------------
// HELPER FUNCTIONS
// ----------------------------------------------------------------------

// Calculate XOR checksum of data buffer
uint16_t calculate_checksum(const uint8_t *data, size_t len) {
    uint16_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum ^= data[i];
        // Rotate left 1 bit to make it slightly harder than pure XOR
        sum = (sum << 1) | (sum >> 15);
    }
    return sum;
}

void vuln_buffer_overflow(uint8_t *data, uint32_t len) {
    char buffer[64];
    // VULNERABILITY: No bounds check on len vs buffer size
    // Symbolic execution should find the path where len > 64
    if (len > 200) { // Constraint to make it interesting
        printf("[DEBUG] Processing large data chunk...\n");
        memcpy(buffer, data, len); // CRASH
    }
}

void vuln_integer_overflow(int w, int h) {
    // VULNERABILITY: Integer overflow in allocation size
    // If w*h overflows 32-bit int, malloc allocates too little
    // Symbolic execution is great at finding these edge cases
    
    if (w > 10000 && h > 10000) {
        size_t size = w * h; // Overflow possible
        printf("[DEBUG] Allocating image buffer: %dx%d = %zu bytes\n", w, h, size);
        
        char *buf = malloc(size);
        if (buf) {
            // Write to end of buffer - will crash if overflow occurred
            // because size wrapped around to a small number
            buf[size - 1] = 'A'; 
            
            // If we actually allocated a huge buffer (no overflow), this might segfault 
            // due to OOM, but we want the overflow crash.
            // Let's force a write far beyond the allocated size if overflow happened
            if (size < 1000) { // Overflow detected logically
                buf[10000] = 'X'; // CRASH (Heap Overflow)
            }
            free(buf);
        }
    }
}

void vuln_format_string(char *data) {
    // VULNERABILITY: Format string
    // Requires specific string content to trigger
    printf("[DEBUG] Metadata: ");
    printf(data); // CRASH
    printf("\n");
}

// ----------------------------------------------------------------------
// MAIN PROCESSING
// ----------------------------------------------------------------------

int process_image(uint8_t *data, size_t size) {
    if (size < sizeof(FileHeader)) {
        return -1;
    }

    FileHeader *header = (FileHeader *)data;

    // CONSTRAINT 1: Magic Bytes
    // AFL++ struggles here without dictionary
    if (header->magic != HEADER_MAGIC) {
        // printf("Invalid Magic\n");
        return -1;
    }

    // CONSTRAINT 2: Version
    if (header->version != 0x0001) {
        // printf("Invalid Version\n");
        return -1;
    }

    // CONSTRAINT 3: Checksum
    // This is the "Hard Constraint" that SymEx solves easily but Fuzzers fail
    // We skip the header itself for checksum calc
    size_t data_len = size - sizeof(FileHeader);
    uint8_t *body = data + sizeof(FileHeader);
    
    uint16_t calc_sum = calculate_checksum(body, data_len);
    if (header->checksum != calc_sum) {
        // printf("Invalid Checksum: Expected %04x, Got %04x\n", header->checksum, calc_sum);
        return -1;
    }

    printf("[+] Header Validated! Entering deep state machine...\n");

    // Process Chunks
    size_t offset = 0;
    while (offset < data_len) {
        if (offset + 8 > data_len) break; // Need at least type + len

        char type[5];
        memcpy(type, body + offset, 4);
        type[4] = '\0';

        uint32_t len = *(uint32_t *)(body + offset + 4);
        offset += 8;

        if (offset + len > data_len) break;

        uint8_t *chunk_data = body + offset;

        // STATE MACHINE & VULNERABILITIES
        if (memcmp(type, "DATA", 4) == 0) {
            // Trigger Buffer Overflow
            vuln_buffer_overflow(chunk_data, len);
        }
        else if (memcmp(type, "SIZE", 4) == 0) {
            if (len >= 8) {
                image_width = *(int *)chunk_data;
                image_height = *(int *)(chunk_data + 4);
                // Trigger Integer Overflow
                vuln_integer_overflow(image_width, image_height);
            }
        }
        else if (memcmp(type, "META", 4) == 0) {
            // Trigger Format String
            // Ensure null termination for safety in non-exploit cases
            char safe_buf[257];
            size_t copy_len = len > 256 ? 256 : len;
            memcpy(safe_buf, chunk_data, copy_len);
            safe_buf[copy_len] = '\0';
            
            vuln_format_string(safe_buf);
            
            // Setup Use-After-Free scenario
            metadata_ptr = malloc(64);
            strcpy(metadata_ptr, "Metadata Active");
        }
        else if (memcmp(type, "FREE", 4) == 0) {
            if (metadata_ptr) {
                free(metadata_ptr);
                // Don't set to NULL -> Dangling pointer
            }
        }
        else if (memcmp(type, "USE ", 4) == 0) {
            if (metadata_ptr) {
                // VULNERABILITY: Use-After-Free
                // If FREE was called before USE, this crashes
                printf("Metadata: %s\n", metadata_ptr); // CRASH
            }
        }

        offset += len;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        // Fuzzing from stdin
        uint8_t buffer[4096];
        size_t len = fread(buffer, 1, sizeof(buffer), stdin);
        process_image(buffer, len);
    } else {
        // Fuzzing from file
        FILE *f = fopen(argv[1], "rb");
        if (!f) return 1;
        
        fseek(f, 0, SEEK_END);
        size_t len = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if (len > 1024 * 1024) len = 1024 * 1024; // Cap at 1MB
        
        uint8_t *buffer = malloc(len);
        if (!buffer) {
            fclose(f);
            return 1;
        }
        
        fread(buffer, 1, len, f);
        fclose(f);
        
        process_image(buffer, len);
        free(buffer);
    }
    return 0;
}
