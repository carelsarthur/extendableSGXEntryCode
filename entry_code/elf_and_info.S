/* ###################################################################### */
/* ################### Build info & ELF section ######################### */
/* ###################################################################### */
.section ".note.x86_64-fortanix-unknown-sgx", "", @note
    .align 4
    .long 1f - 0f              /* name length (not including padding) */
    .long 3f - 2f              /* desc length (not including padding) */
    .long 1                    /* type = NT_VERSION */
0:  .asciz "toolchain-version" /* name */
1:  .align 4
2:  .long 1                    /* desc - toolchain version number, 32-bit LE */
3:  .align 4

// ELF = executable & linkable format
/* We place the ELF entry point in a separate section so it can be removed by
   elf2sgxs */
.section .text_no_sgx, "ax"
.Lelf_entry_error_msg:
    .ascii "Error: This file is an SGX enclave which cannot be executed as a standard Linux binary.\nSee the installation guide at https://edp.fortanix.com/docs/installation/guide/ on how to use 'cargo run' or follow the steps at https://edp.fortanix.com/docs/tasks/deployment/ for manual deployment.\n"
.Lelf_entry_error_msg_end:

.global elf_entry
.type elf_entry,function
elf_entry:
/* print error message */
    movq $2,%rdi                      /* write to stderr (fd 2) */
    lea .Lelf_entry_error_msg(%rip),%rsi 
    movq $.Lelf_entry_error_msg_end-.Lelf_entry_error_msg,%rdx
.Lelf_entry_call:
    movq $1,%rax                      /* write() syscall        */
    syscall
    test %rax,%rax
    jle .Lelf_exit                    /* exit on error          */
    add %rax,%rsi
    sub %rax,%rdx                     /* all chars written?     */
    jnz .Lelf_entry_call

.Lelf_exit:    
    movq $60,%rax                     /* exit() syscall         */
    movq $1,%rdi                      /* exit code 1            */
    syscall
    ud2                               /* should not be reached  */
/*  end elf_entry */

.text
.global get_tcs_addr
get_tcs_addr:
    mov %gs:tcsls_tcs_addr,%rax
    pop %r11
    lfence
    jmp *%r11

.global get_tls_ptr
get_tls_ptr:
    mov %gs:tcsls_tls_ptr,%rax
    pop %r11
    lfence
    jmp *%r11

.global set_tls_ptr
set_tls_ptr:
    mov %rdi,%gs:tcsls_tls_ptr
    pop %r11
    lfence
    jmp *%r11

.global take_debug_panic_buf_ptr
take_debug_panic_buf_ptr:
    xor %rax,%rax
    xchg %gs:tcsls_debug_panic_buf_ptr,%rax
    pop %r11
    lfence
    jmp *%r11

