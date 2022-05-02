; custom-decoder.nasm
; Author: Jack McBride (PA-6483)
; Website:  https://jacklgmcbride.co.uk
;
; Purpose: SLAE32 exam assignment
;
;
; Assignment 4: Custom Encoder

global _start

section .text

_start:

        jmp short call_shellcode;               Jump to the call_shellcode label

decoder:

        pop esi;                                POP the location of our shellcode into ESI
        lea edi, [esi];                         Load the ESI register into EDI so both are pointing to the shellcode
        xor ebx, ebx;				Clear EBX register
	xor eax, eax;                           Clear EAX register

decode:

        mov bl, byte[esi + eax];                Move byte of encoded shellcode into BL
        mov dl, bl;                             Copy byte to DL
        xor dl, 0xbb;                           Check if at end of shellcode
        jz EncodedShellcode;                    If at the end, jump to the decoded shellcode
        test al, 1;                             Check if at an odd byte (padding)
        jnz decode_loop_inc;
        not bl;                                 Perform NOT decoding on BL
        xor bl, 0x7;                            XOR BL with 0x7
        mov byte [edi], bl;                     Move decoded BL byte into EDI
        inc edi;                                Point EDI at next byte
        inc eax;                                Increment EAX by one
        jmp short decode;                       Decode next byte

decode_loop_inc:

        add al, 1;                              Increment AL by 1
        jmp short decode;                       Decode next byte

call_shellcode:

        call decoder;                           Call the decoder label
	EncodedShellcode: db SHELLCODE
