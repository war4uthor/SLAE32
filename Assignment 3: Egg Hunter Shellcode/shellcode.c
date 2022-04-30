#include<stdio.h>
#include<string.h>

unsigned char egghunter[] = \
"EGGHUNTER";

unsigned char code[] = \
"SHELLCODE";

int main()
{
	printf("Egg hunter Length: %d\n", strlen(egghunter));
	printf("Shellcode Length: %d\n", strlen(code));

        int (*ret)() = (int(*)())egghunter;

        ret();
}
