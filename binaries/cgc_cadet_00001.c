/*
 * CADET_00001 - Palindrome (Linux port)
 * Original: CGC Summer Intern 2014
 * 
 * Vulnerability: CWE-121 Stack-based Buffer Overflow
 * Description: Reads up to 128 bytes into 64-byte buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HI "\nWelcome to Palindrome Finder\n\n"
#define ASK "\tPlease enter a possible palindrome: "
#define YES "\t\tYes, that's a palindrome!\n\n"
#define NO "\t\tNope, that's not a palindrome\n\n"
#define EASTEREGG "\n\nEASTER EGG!\n\n"

// Linux replacement for CGC transmit_all
int transmit_all(int fd, const char *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t written = write(fd, buf + total, count - total);
        if (written <= 0) return -1;
        total += written;
    }
    return 0;
}

// Linux replacement for CGC receive_delim
int receive_delim(int fd, char *buf, size_t count, char delim) {
    size_t i = 0;
    while (i < count - 1) {
        ssize_t n = read(fd, &buf[i], 1);
        if (n <= 0) return -1;
        if (buf[i] == delim) {
            buf[i] = '\0';
            return 0;
        }
        i++;
    }
    buf[i] = '\0';
    return 0;
}

int check();

int main(void) {
    int r;

    if (transmit_all(STDOUT_FILENO, HI, sizeof(HI)-1) != 0) {
        exit(0);
    }
    
    while(1){
        if (transmit_all(STDOUT_FILENO, ASK, sizeof(ASK)-1) != 0) {
            exit(0);
        }
        r = check();
        if (r == -1){
            break;
        }
        else if (r == 0){
            if (transmit_all(STDOUT_FILENO, NO, sizeof(NO)-1) != 0) {
                exit(0);
            }
        }
        else{
            if (transmit_all(STDOUT_FILENO, YES, sizeof(YES)-1) != 0) {
                exit(0);
            }
        }
    }
    return 0;
}

int check(){
    int len = -1;
    int i;
    int pal = 1;
    char string[64];  // 64-byte buffer
    
    for (i = 0; i < sizeof(string); i++)
        string[i] = '\0';
    
    // VULNERABILITY: Reads up to 128 bytes into 64-byte buffer
    if (receive_delim(STDIN_FILENO, string, 128, '\n') != 0)
        return -1;
    
    for(i = 0; string[i] != '\0'; i++){
        len++;
    }
    
    int steps = len;
    if(len % 2 == 1){
        steps--;
    }
    
    for(i = 0; i <= steps/2; i++){
        if(string[i] != string[len-1-i]){
            pal = 0;
        }
    }
    
    // Easter egg trigger (potential symex target)
    if(string[0] == '^'){
        if (transmit_all(STDOUT_FILENO, EASTEREGG, sizeof(EASTEREGG)-1) != 0) {
            exit(0);
        }
    }    
    
    return pal;
}
