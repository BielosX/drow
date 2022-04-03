#include <stdio.h>

void very_important_function(void) {
    printf("Hello from very important function\n");
}

int my_strlen(const char *string) {
    int result = 0;
    char* ptr = string;
    while (*ptr != 0) {
        ptr++;
        result++;
    }
    return result;
}