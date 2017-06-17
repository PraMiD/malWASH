global _start
section .text

_start:
	mov eax, 120
	; eax contains number of sys_clone
	; ebx contains the clone flags
	; ecx the new stack
	; edx, edi, esi are NULL/0 as we do not need those parameters
	int 80h
	cmp eax, 0
	jne short 0x0d	; Jump to _orig

_new:
	;add esp, 36
	mov eax, 1
	mov ebx, 0
	int 80h
	;ret

_orig:
	pop edi
	pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax
	pop ebp
	pop esp
	push 0x01020304 ; This address will be replaced by the LKM
	ret
