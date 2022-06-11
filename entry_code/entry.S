/* Note: the .S filetype means this is a GAS (Gnu ASsembly file )
More info about the instructions can be found on: https://en.wikibooks.org/wiki/X86_Assembly/GNU_assembly_syntax /* 
/* Note: the Xsave documentation referenced can be found here:
https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf */

/*  This symbol is used at runtime to figure out the virtual address that the */
/*  enclave is loaded at. */
.section absolute
.global IMAGE_BASE
IMAGE_BASE:

  /* ------------------------------------------ */
  /* |              Read-only data            | */
  /* ------------------------------------------ */
.section .rodata /* This data can not be changed! */

/*  Xsave area below: responsible for "resetting" the CPU state */
/*  We do not store anything in it --> can be read-only memory
/*  The XSAVE area needs to be a large chunk of readable memory, but since we are */
/*  going to restore everything to its initial state (XSTATE_BV=0), only certain */
/*  parts need to have a defined value. In particular: */
/*    -* MXCSR in the legacy area. This register is always restored if RFBM[1] or */
/*      RFBM[2] is set, regardless of the value of XSTATE_BV, see 13.7 */
/*    - * XSAVE header */
.align 64 /* align to a multiple of 64 bytes (otherwise error, see 13.7) */
.Lxsave_ro_clear:
.org .+24 
.Lxsave_ro_mxcsr: /* See table 13-1  */
    /* MXCSR register contains control and status information for the SSE registers */
    .short 0x1f80  /* .short is 2 bytes! (and 0x1f80 is also 2 bytes!)

/*  We can store a bunch of data in the gap between MXCSR and the XSAVE header */
/*  The following symbols point at read-only data that will be filled in by the */
/*  post-linker. */

/*  When using this macro, don't forget to adjust the linker version script! */
.macro globvar name:req size:req
    .global \name
    .protected \name
    .align \size
    .size \name , \size
    \name :
        .org .+\size
.endm

    /* Declaring a lot of global variables:  */
    /* information see: https://github.com/fortanix/rust-sgx/blob/master/doc/FORTANIX-SGX-ELF.md */
    /*  The base address (relative to enclave start) of the heap area */
    globvar HEAP_BASE 8
    /*  The heap size in bytes */
    globvar HEAP_SIZE 8
    /*  Value of the RELA entry in the dynamic table */
    globvar RELA 8
    /*  Value of the RELACOUNT entry in the dynamic table */
    globvar RELACOUNT 8
    /*  The enclave size in bytes */
    globvar ENCLAVE_SIZE 8
    /*  The base address (relative to enclave start) of the enclave configuration area */
    globvar CFGDATA_BASE 8
    /*  Non-zero if debugging is enabled, zero otherwise */
    globvar DEBUG 1
    /*  The base address (relative to enclave start) of the enclave text section */
    globvar TEXT_BASE 8
    /*  The size in bytes of enclave text section */
    globvar TEXT_SIZE 8
    /*  The base address (relative to enclave start) of the enclave .eh_frame_hdr section */
    globvar EH_FRM_HDR_OFFSET 8
    /*  The size in bytes of enclave .eh_frame_hdr section */
    globvar EH_FRM_HDR_LEN 8
    /*  The base address (relative to enclave start) of the enclave .eh_frame section */
    globvar EH_FRM_OFFSET 8
    /*  The size in bytes of enclave .eh_frame section */
    globvar EH_FRM_LEN 8

 /* Located at a 512 bytes offset from the Legacy_xsave area referenced above */
.org .Lxsave_ro_clear+512  /* Size of legacy xsave area = 512 bytes */
.Lxsave_ro_header:   /* Xsave headers area (64 bytes) */
    /* Huge impact on what gets (re)stored
    /* See 13.4.2 */
    .int 0, 0 /*  XSTATE_BV: all 0? --> all values are "reset" to their "initial state" (see 13.8) */
    .int 0, 0 /*  XCOMP_BV:  all 0? --> no support for compaction extensions */
    .org .+48 /*  reserved bytes (63:16) (64 - 2 * 8) */

  /* ------------------------------------------ */
  /* |          Writable data area            | */
  /* ------------------------------------------ */
.section .data 
.aborted:   /* Cannot be placed on gs segment since this is shared accross all threads! */
    .byte 0 /* Initialized to 0 */

/* ---------------------- gs segment ------------------------ */
/* NOTE: this segment is aligned to a 1 page boundary! (by ftxsgx-elf2sgx) */
.gs_segment:
  /*  TCS local storage section */
  // ".equ" gives a symbolic name to a numeric constant (= the offset from start of gs segment)
  .equ tcsls_tos,                 0x00 /*  initialized by loader to *offset* from image base to TOS */
  .equ tcsls_flags,               0x08 /*  initialized by loader */
  .equ tcsls_flag_secondary,      0    /*  initialized by loader; 0 = standard TCS, 1 = secondary TCS */
  .equ tcsls_flag_init_once,      1    /*  initialized by loader to 0 */
  /*  14 unused bits: we're working in bits, not in bytes! */  
  .equ tcsls_last_rsp,            0x0a /*  initialized by loader to 0 */
  .equ tcsls_panic_last_rsp,      0x12 /*  initialized by loader to 0 */
  .equ tcsls_debug_panic_buf_ptr, 0x1A /*  initialized by loader to 0 */
  .equ tcsls_tls_ptr,             0x22
  .equ tcsls_tcs_addr,            0x2A
  /* Storage space for the callee-saved registers */
  .equ callee_saved_fcw,           0x32
  .equ callee_saved_mxcsr,         0x34
  .equ callee_saved_rsp,           0x38
  .equ callee_saved_retip,         0x40
  .equ callee_saved_rbp,           0x48
  .equ callee_saved_r12,           0x50
  .equ callee_saved_r13,           0x58
  .equ callee_saved_r14,           0x60
  .equ callee_saved_r15,           0x68
  /* Usercall vars */
  .equ usercall_rbx,              0x70
  .equ usercall_rbp,              0x78        
  .equ usercall_r12,              0x80 
  .equ usercall_r13,              0x88
  .equ usercall_r14,              0x90
  .equ usercall_r15,              0x98
  .equ usercall_mxcsr,            0xa0
  .equ usercall_cw,               0xa4
  .equ usercall_rip,              0xa8 /* The rip to jump to after returning from a usercall */
  /* future_processor_state registers (following Ulviya's C model order (p. 70-71)) */
  .equ rust_rsp,                  0xb0
  .equ rust_rax,                  0xb8 
  .equ rust_rbx,                  0xc0 
  .equ rust_rcx,                  0xc8
  .equ rust_rdx,                  0xd0
  .equ rust_rdi,                  0xd8
  .equ rust_rsi,                  0xe0
  .equ rust_rbp,                  0xe8
  .equ rust_r8,                   0xf0
  .equ rust_r9,                   0xf8
  .equ rust_r10,                  0x100
  .equ rust_r11,                  0x108
  .equ rust_r12,                  0x110
  .equ rust_r13,                  0x118
  .equ rust_r14,                  0x120
  .equ rust_r15,                  0x128
  .equ rust_rflags,               0x130
  .equ rust_cw,                   0x138
  .equ rust_mxcsr,                0x13c
  /* Custom vars */  
  .equ real_tos,                  0x140
  .equ xsave_addr_choice,         0x148

  /* Add the xsave_segments here! (Need to be 64-bit aligned !!) */
  /* NOTE: upon location update, change the corresponding constant in mod.rs! */
  .equ entry_xsave,               0x180 /* Size needed: 576 bytes */
  .equ entry_xsave_header,        0x380 /* entry_xsave + 512 */
  .equ usercall_xsave,            0x3c0 /* Size needed: 576 bytes */
  .equ usercall_xsave_header,     0x5c0 /* usercall_xsave + 512 */
  .equ end_of_usercall_xsave_seg, 0x600 /* Do not write until byte 0x5c0 + 64 = 0x600 */

  /* Thread-local stack (must be page-aligned!) */
  /*   Ok: gs-segment is page aligned & 0x1000 offset */
  .equ Rust_stack,                0x1000 /* Rust stack has a size of 10,000 */
  .equ Rust_stack_top,            0x2000 /* Only 1 page needed, found via angr */

.macro save_extra_regs
    mov %rsp, %gs:rust_rsp  /* Can be skipped */
    mov %rax, %gs:rust_rax
    mov %rbx, %gs:rust_rbx
    mov %rcx, %gs:rust_rcx
    mov %rdx, %gs:rust_rdx
    mov %rdi, %gs:rust_rdi
    mov %rsi, %gs:rust_rsi
    mov %rbp, %gs:rust_rbp   /* Can be skipped */
    mov %r8 , %gs:rust_r8 
    mov %r9 , %gs:rust_r9
    mov %r10, %gs:rust_r10
    mov %r11, %gs:rust_r11
    mov %r12, %gs:rust_r12
    mov %r13, %gs:rust_r13
    mov %r14, %gs:rust_r14
    mov %r15, %gs:rust_r15
    stmxcsr   %gs:rust_mxcsr 
    fnstcw    %gs:rust_cw  
.endm

.macro load_extra_regs
    mov %gs:rust_rax,  %rax 
    mov %gs:rust_rbx,  %rbx 
    mov %gs:rust_rcx,  %rcx 
    mov %gs:rust_rdx,  %rdx 
    mov %gs:rust_rdi,  %rdi 
    mov %gs:rust_rsi,  %rsi 
    mov %gs:rust_r8 ,  %r8  
    mov %gs:rust_r9 ,  %r9  
    mov %gs:rust_r10,  %r10  
    mov %gs:rust_r11,  %r11  
    mov %gs:rust_r12,  %r12 
    mov %gs:rust_r13,  %r13 
    mov %gs:rust_r14,  %r14 
    mov %gs:rust_r15,  %r15 
    push %gs:rust_rflags
    popfq 
    fldcw   %gs:rust_cw
    ldmxcsr %gs:rust_mxcsr
    /* Only reset stack after flags register has been cleared! */
    /* NOTE:  this assumes that a trusted stack is being used before calling this macro! */
    mov %gs:rust_rsp,  %rsp
    mov %gs:rust_rbp,  %rbp 
.endm

.macro save_calling_convention_regs  
    mov %rcx,%gs:callee_saved_retip
    mov %rsp,%gs:callee_saved_rsp
    mov %rbp,%gs:callee_saved_rbp
    mov %r12,%gs:callee_saved_r12
    mov %r13,%gs:callee_saved_r13
    mov %r14,%gs:callee_saved_r14
    mov %r15,%gs:callee_saved_r15
    mov %rbx,%gs:tcsls_tcs_addr
    stmxcsr  %gs:callee_saved_mxcsr
    fnstcw   %gs:callee_saved_fcw 
.endm

.macro save_all_registers
  /* Saves:
  - registers needed for calling conventions
  - future_processor_state registers 
  - FPU registers
  - SSE State
  */ 
    save_calling_convention_regs
    save_extra_regs 

    /* Xsave related things (part of the "xsave headers area"): */
    /* - Set XSTATE_BV= "int 3, 0" --> xmm & sse registers are stored/reset 
    /*      Note: from 13.2: these features are supported by every processor that supports the XSAVE feature set
    /* - Set XCOMP_BV = 0 --> processor does not support compaction (compatibility reasons!) */
    /* Nothing is stored in the "extended xsave area"! */
    movl $3, %gs:entry_xsave_header  
    movl $3, %gs:usercall_xsave_header

    /* Value of 3 ==> only store floating point & xmm/sse registers */
    mov $0x0, %rdx
    mov $0x3, %rax
    xsave %gs:entry_xsave
.endm

.macro restore_all_registers
    /* Restore from xsave segment (sse & fpu registers!) */
    /* NOTE: need to do "xrstor" before reloading gprs!
      Otherwise mxcsr & fcw won't be correct! */
    mov $-1, %rdx
    mov $-1, %rax
    mov %gs:xsave_addr_choice, %r11 
    xrstor (%r11)  

    /* Set right values for GPRs */
    load_extra_regs
.endm

.text
.global sgx_entry
.type sgx_entry,function
sgx_entry:
  /* Instruction Operand Encoding (=convention):
  - RAX: Content of RBX.CSSA 
  - RBX: Address of TCS
  - RCX: Address of IP following EENTER 
  Source: https://cdrdv2.intel.com/v1/dl/getContent/671200, Vol. 3D 37-99
  */

    /* ###################################################################### */
    /* ##################### Store & reset state ############################ */
    /* ###################################################################### */

    /* Save all required registers */
    save_all_registers

    /* value of -1 ==> all supported registers are reset to "initial values" (= 0xffffffffff...) */
    mov $-1, %rax
    mov $-1, %rdx
    xrstor .Lxsave_ro_clear(%rip)

.stored_and_reset_registers:
 /* We calculate the "real tos" here and pass it on as the first argument to Rust code */
    mov %gs:tcsls_tos, %rdi
    lea IMAGE_BASE(%rip), %r10
    add %r10, %rdi
    mov %rdi, %gs:rust_rsp  
    mov %rdi, %gs:rust_rbp  
    mov %rdi, %gs:real_tos
    /* We pass the "aborted" value as a second argument to Rust code */
    movzbq .aborted(%rip), %rsi  /* Zero extend the 1 byte Laborted value into rsi */
    /* We pass the "DEBUG(%rip)" register as a third argument to Rust code */
    movzbq DEBUG(%rip), %rdx /* Zero extend the 1 byte DEBUG value into rdx */

    /* We switch untrusted stack to "temporary (trusted!) rust stack" */
    /* Gs segment address == tcsls_tos */
    /* --> Address of stack = tcsls_tos (=gs segment addr) + Rust_stack_top offset */
    lea %gs:Rust_stack_top, %r10
    add %gs:real_tos, %r10
    mov %r10, %rsp
    mov %r10, %rbp

    /* Stack is safe (i.e. in-enclave & thread-local) here! --> allowed to push things to it */
    /* Now: sanitize rflags received from user */
    /*    - DF flag: x86-64 ABI requires DF to be unset at function entry/exit */
    /*    - AC flag: AEX on misaligned memory accesses leaks side channel info */
    pushq $0
    /* Note: we can simply popfq an all-zero value, as system flags and
    reserved bits are not writable from the user-space enclave */
    movq $0, %gs:rust_rflags 
    popfq 

.well_defined_state:
    /* ###################################################################### */
    /* ##################### "Well"-defined state ########################### */
    /* ###################################################################### */
    /* Note: at this point we have a well-defined state:
      - Using in-enclave stack (that is unique to each thread)
      - AC & DF flags sanitized
      - Registers stored & reset
    */

/*  We bootstrap the enclave (different actions e.g. depending on usercall_ret / first_time / ...) */
enclave_bootstrap_point:
    call enclave_bootstrapper 

/* 
r11 can contain two different "types" of values
Option 1: enclu: 
   This gets called when we want to exit the enclave
   There are two moments when this happens:
   - after the "entry" function has completed
   - when a "usercall" is performed  (also when "abort")
Option 2: jump to return address  (= return rip):
   This gets called when we return from a usercall (--> enter enclave again!) */
after_enclave_bootstrap:
    restore_all_registers
    lfence 
    jmp *%r11

/* ###################################################################### */
/* ########################## Usercall ################################## */
/* ###################################################################### */
/*  This *MUST* be called with 6 parameters, otherwise register information */
/*  might leak!
/*  Params: rdi, rsi, rdx, r8, r9, (?) 
    More info see: https://github.com/rust-lang/rust/blob/352e621368c31d7b4a6362e081586cdb931ba020/library/std/src/sys/sgx/abi/usercalls/raw.rs#L36 */
/* NOTE: this gets called from within the enclave --> stack is set correctly  */
.global usercall
usercall:
    pushq $0 
    popfq
    popq %gs:usercall_rip /* First pop --> correct stack location is saved in next instruction! */

    save_extra_regs
    /* Value of 3 ==> only store floating point & xmm/sse registers */
    mov $0x0, %rdx
    mov $0x3, %rax
    xsave %gs:usercall_xsave

    mov %gs:real_tos, %rdi    /* First argument */
    movzbq DEBUG(%rip), %rsi  /* Second argument */
    call rust_usercall 
    /* Rust_usercall will then call a function that performs the "enclu" call */

/*
The following functions need to be defined externally (in Rust):
```
// Bootstrapper for the enclave (will "set up/bootstrap" the enclave)
extern "C" fn enclave_bootstrapper(gs_address: u64, debug: u64); 

// Gets called when a usercall happens
extern "C" fn rust_usercall(address: usize, debug: usize) 

// A "wrapper" that calls the entry code and is responsible for setting the "future_processor_state"
extern "C" fn entry_wrapper(gs_address: usize) -> ! 
```
*/

entry_from_rust:
    /* Load arguments for entry function */
    mov %gs:rust_rdi, %rdi
    mov %gs:rust_rsi, %rsi
    mov %gs:rust_rdx, %rdx
    mov %gs:rust_rcx, %rcx
    mov %gs:rust_r8, %r8
    mov %gs:rust_r9, %r9
    /* Clear flags (for certainty) */
    pushq $0
    popfq
    /* Switch stack */
go_to_real_stack:
    xchgq %rsp, %gs:rust_rsp
    xchgq %rbp, %gs:rust_rbp
    call entry
using_temp_stack_again:  /* Switch back to temp stack */
    xchgq %rsp, %gs:rust_rsp
    xchgq %rbp, %gs:rust_rbp
    /* Save return arguments */
    mov %rdx, %gs:rust_rdx
    mov %rax, %gs:rust_rsi
    /* Set function argument */ 
    mov %gs:real_tos, %rdi
    call entry_state_scrubber

exit_call:
    xor %r11, %r11 /* Still need to zero the r11 register!! */
enclu_call:
    enclu
