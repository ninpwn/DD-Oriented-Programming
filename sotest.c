#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void init_library() {
    printf("Library loaded: Hello from the constructor!\n");
    system("date >> /tmp/win");
}
