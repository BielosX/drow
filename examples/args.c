#include <string.h>

int main(int argc, char** argv) {
    if (argc > 1) {
        return strlen(argv[1]);
    } else {
        return -1;
    }
}