// hello.c
#include <stdio.h>

// Constructor function that runs when the library is loaded
__attribute__((constructor))
void init_library() {
    printf("Library loaded: Hello from the constructor!\n");
}

// Function that can be called explicitly after loading
void hello() {
    printf("Hello from the shared library!\n");
}
