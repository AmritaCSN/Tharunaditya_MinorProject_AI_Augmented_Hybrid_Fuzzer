/*
 * nf_demo.c
 * 
 * NeuroFuzz Demonstration Binary
 * 
 * A simplified binary designed to reliably demonstrate Hybrid Fuzzing capabilities.
 * It contains a "Magic Number" check that blocks pure fuzzers, followed by a 
 * buffer overflow that is easy for symbolic execution to find once the check is passed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Magic value that pure fuzzers struggle to guess (1 in 2^32 chance)
#define MAGIC_VALUE 0xDEADBEEF

void vulnerable_function(char *input, int len) {
    char buffer[64];
    
    // VULNERABILITY: Classic stack buffer overflow
    // If input length > 64, this will crash
    if (len > 64) {
        printf("[+] Triggering buffer overflow!\n");
        memcpy(buffer, input, len);
    }
}

int main(int argc, char **argv) {
    uint32_t magic;
    char data[128];
    
    // Read input
    if (read(STDIN_FILENO, &magic, sizeof(magic)) != sizeof(magic)) {
        return 0;
    }
    
    // Check 1: Magic Number (The "Wall" for AFL++)
    // AFL++ will get stuck here because it can't easily guess 0xDEADBEEF
    // Symbolic Execution will solve this constraint instantly
    if (magic == MAGIC_VALUE) {
        printf("[+] Magic value correct! Entering vulnerable region...\n");
        
        // Read remaining data
        int len = read(STDIN_FILENO, data, sizeof(data));
        if (len > 0) {
            vulnerable_function(data, len);
        }
    } else {
        // Most fuzzing inputs end up here
        // printf("[-] Wrong magic value: 0x%08x\n", magic);
    }
    
    return 0;
}
