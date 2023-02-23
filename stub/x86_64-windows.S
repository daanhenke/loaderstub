bits 64
entrypoint:
    push rdi                        ; push registers
    push rcx
    push rdx

    call find_LoadLibraryA          ; rdi = pointer to LoadLibraryA
    mov rdi, rax    

    lea rcx, [rel aTargetDll]       ; rcx = pointer to target DLL path

    sub rsp, 0x30                   ; LoadLibraryA(targetDllPath)
    call rdi
    add rsp, 0x30

                                    ; rax = offset to original entrypoint
    xor rax, rax
    mov eax, [rel oOriginalEntrypoint]
    cmp rax, 0                      ; if(rax == 0) goto _skip_find_base
    je _skip_find_base

    lea rdi, [rel entrypoint]       ; rdi = pointer to entrypoint
    and rdi, 0xFFFFFFFFFFFFF000     ; rdi = pointer to the page entrypoint resides in
    xor rcx, rcx                    ; rcx = 0

    ; mov rax, rdi
    ; pop rcx
    ; pop rdi
    ; ret
_find_base:
    mov cx, [rdi]                   ; rcx = first word in page
    sub rdi, 0x1000                 ; rdi = previous page
    cmp rcx, 0x5A4D                 ; if(rcx != "MZ") goto _find_base
    jne _find_base
    add rdi, 0x1000                 ; rdi = current module base

_skip_find_base:
    pop rdx
    pop rcx                         ; restore rcx, but keep rdi it contains module base

    cmp rax, 0                      ; if(rax == 0) goto _skip_ep_call
    je _skip_ep_call

    add rax, rdi                    ; rax = pointer to original entrypoint
    pop rdi                         ; restore rdi
    jmp rax                         ; jmp to the entrypoint so the entrypoint doesn't return here

_skip_ep_call:
    pop rdi                         ; restore rdi
    mov rax, 1
    ret                             ; no entrypoint, return ourselves

find_Kernel32:
    push rcx                        ; store registers we're about to polute
    push rdi

    xor rcx, rcx                    ; rcx = 0
    mov rax, [gs:rcx + 0x60]        ; rax = PEB
    mov rax, [rax + 0x18]           ; rax = PEB->Ldr
    mov rsi, [rax + 0x20]           ; rsi = PEB->Ldr.InMemOrder[0]
    lodsq                           ; rax = PEB->Ldr.InMemOrder[1]
    xchg rax, rsi                   ; std::swap(rax, rsi)
    lodsq                           ; rax = PEB->Ldr.InMemOrder[2]
    mov rax, [rax + 0x20]           ; rax = PEB->Ldr.InMemOrder[2].BaseAddress

    pop rdi                         ; restore registers to original value and return
    pop rcx
    ret

find_GetProcAddress:
    push r8                         ; store unpoluted registers
    push rsi
    push rcx
    push rdx
    push rbx
    push r9

    call find_Kernel32
    mov rbx, rax                    ; rbx = Kernel32.dll+0

    xor r8, r8                      ; r8 = 0
    mov r8d, [rbx + 0x3c]           ; r8 = 32 bit offset to NT headers
    mov rdx, r8
    add rdx, rbx                    ; rdx = NT headers pointer
    mov r8d, [rdx + 0x88]           ; r8 = 32 bit offset to export table
    add r8, rbx                     ; r8 = export table pointer
    xor rsi, rsi                    ; rsi = 0
    mov esi, [r8 + 0x20]            ; rsi = 32 bit offset to name table
    add rsi, rbx                    ; rsi = name table pointer

    xor rcx, rcx                    ; rcx = 0
    mov r9, [rel aGetProcAddress]   ; r9 = "GetProcA"
_enumerate_exports:
    inc rcx                         ; rcx++
    xor rax, rax                    ; rax = 0
    mov eax, [rsi + rcx * 4]        ; rax = 32 bit offset to name
    add rax, rbx                    ; rax = library name pointer
    cmp rcx, 1400                   ; if(rcx == 1400) goto _end
    je _end
    cmp [rax], r9                   ; if(*rax != "GetProcA") goto _enumerate_exports
    jnz _enumerate_exports

    xor rsi, rsi                    ; rsi = 0
    mov esi, [r8 + 0x24]            ; rsi = 32 bit offset to oridinal table
    add rsi, rbx                    ; rsi = ordinal table
    mov cx, [rsi + rcx * 2]         ; rcx = function number
    xor rsi, rsi                    ; rsi = 0
    mov esi, [r8 + 0x1c]            ; rsi = 32 bit offset to address table
    add rsi, rbx                    ; rsi = adress table pointer
    xor rdx, rdx                    ; rdx = 0
    mov edx, [rsi + rcx * 4]        ; rdx = 32 bit offset of GetProcAddress
    add rdx, rbx                    ; rax = GetProcAddress
    mov rax, rdx                    

_end:
    pop r9                          ; restore registers and return
    pop rbx
    pop rdx
    pop rcx
    pop rsi
    pop r8
    ret

find_LoadLibraryA:
    push rdi                        ; push used registers
    push rcx
    push rdx

    call find_GetProcAddress        ; rdi = GetProcAddress
    mov rdi, rax

    call find_Kernel32              ; rcx = Kernel32.dll+0
    mov rcx, rax

    lea rdx, [rel aLoadLibraryA]    ; rdx = pointer to "LoadLibraryA"

    sub rsp, 0x30                   ; GetProcAddress(rcx, rdx)
    call rdi
    add rsp, 0x30

    pop rdx                         ; restore regisers and return
    pop rcx
    pop rdi
    ret


aGetProcAddress: db "GetProcA"
aLoadLibraryA: db "LoadLibraryA", 0
oOriginalEntrypoint: dd 0           ; Filled during patch
aTargetDll: db 0                    ; Filled during patch