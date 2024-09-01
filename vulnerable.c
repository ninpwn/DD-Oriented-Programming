#include <stdio.h>
#include <sys/mman.h>


#define PAGE_LENGTH 0x1000

int main()
{
	puts("[*] welcome to my vulnerable binary, it will map executable memory for you to abuse!");
	getchar();
	puts("[*] my original puts call!");
}
