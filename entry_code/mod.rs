#![cfg_attr(test, allow(unused))] // RT initialization logic is not compiled for test
#![cfg_attr(asm, allow(used))]
//#![feature(asm)] // needed for asembly code embedded in Rust file

use crate::io::Write;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::mem::size_of;

// runtime features
pub(super) mod panic;
mod reloc;

// library features
pub mod mem;
pub mod thread;
pub mod tls;
pub mod usercalls;

#[cfg(not(test))]
global_asm!(include_str!("entry.S"), options(att_syntax));
#[cfg(not(test))]
global_asm!(include_str!("elf_and_info.S"), options(att_syntax));

#[repr(C)]
struct EntryReturn(usize, usize);

#[cfg(not(test))]
#[no_mangle] // Needed for angr to find the symbol
unsafe extern "C" fn tcs_init(secondary: bool) {
    // Be very careful when changing this code: it runs before the binary has been
    // relocated. Any indirect accesses to symbols will likely fail.
    const UNINIT: usize = 0;
    const BUSY: usize = 1;
    const DONE: usize = 2;
    // Three-state spin-lock
    static RELOC_STATE: AtomicUsize = AtomicUsize::new(UNINIT);

    if secondary && RELOC_STATE.load(Ordering::Relaxed) != DONE {
        rtabort!("Entered secondary TCS before main TCS!")
    }

    // Try to atomically swap UNINIT with BUSY. The returned state can be:
    match RELOC_STATE.compare_exchange(UNINIT, BUSY, Ordering::Acquire, Ordering::Acquire) {
        // This thread just obtained the lock and other threads will observe BUSY
        Ok(_) => {
            reloc::relocate_elf_rela();
            RELOC_STATE.store(DONE, Ordering::Release);
        }
        // We need to wait until the initialization is done.
        Err(BUSY) => {
            while RELOC_STATE.load(Ordering::Acquire) == BUSY {
                core::hint::spin_loop();
            }
        }
        // Initialization is done.
        Err(DONE) => {}
        _ => unreachable!(),
    }
}

// FIXME: this item should only exist if this is linked into an executable
// (main function exists). If this is a library, the crate author should be
// able to specify this
#[cfg(not(test))]
#[no_mangle]  // Needed for angr to find the symbol
fn entry(p1: usize, p2: usize, p3: usize, secondary: bool, p4: usize, p5: usize) -> EntryReturn{
    // FIXME: how to support TLS in library mode?
    let tls = Box::new(tls::Tls::new());
    let tls_guard = unsafe { tls.activate() };

    if secondary {
        let join_notifier = super::thread::Thread::entry();
        drop(tls_guard);
        drop(join_notifier);
        EntryReturn(0, 0)
    } else {
        extern "C" {
            fn main(argc: isize, argv: *const *const u8) -> isize;
        }

        // check entry is being called according to ABI
        rtassert!(p3 == 0);
        rtassert!(p4 == 0);
        rtassert!(p5 == 0);

        unsafe {
            // The actual types of these arguments are `p1: *const Arg, p2:
            // usize`. We can't currently customize the argument list of Rust's
            // main function, so we pass these in as the standard pointer-sized
            // values in `argc` and `argv`.
            let ret = main(p2 as _, p1 as _);
            exit_with_code(ret)
        }
    }
}

pub(super) fn exit_with_code(code: isize) -> ! {
    if code != 0 {
        if let Some(mut out) = panic::SgxPanicOutput::new() {
            let _ = write!(out, "Exited with status code {}", code);
        }
    }
    usercalls::exit(code != 0);
}

#[cfg(not(test))]
#[no_mangle]
extern "C" fn abort_reentry() -> ! {
    usercalls::exit(false)
}

// |--------------------------------------------------------------------------|
// |------------------------------- Added functions  -------------------------|
// |--------------------------------------------------------------------------|
#[cfg(not(test))]
#[no_mangle]
extern "C" fn enclave_bootstrapper(gs_address: usize, aborted: usize, debug: usize) -> ! {
    let thread_control_state = get_thread_control_state_struct(gs_address);
    let future_processor_state = get_future_processor_state_struct(gs_address);

    // If debug option is chosen, we set pointer to a region where the debug variables can be written
    if debug != 0 { // ~= Testb instruction
        thread_control_state.tcsls_debug_panic_buf_ptr = future_processor_state.r10; // Set location to pointer of debug buffer
    }

    if aborted != 0 {
        future_processor_state.xsave_addr_choice = ENTRY_XSAVE_OFFSET + gs_address;
        abort_reentry();
    } else if thread_control_state.tcsls_last_rsp != 0 {
        rust_usercall_ret(gs_address, thread_control_state, future_processor_state);

        future_processor_state.xsave_addr_choice = USERCALL_XSAVE_OFFSET + gs_address;
        unsafe{after_enclave_bootstrap()};
    } else {
        no_usercall(thread_control_state, future_processor_state);

        future_processor_state.xsave_addr_choice = ENTRY_XSAVE_OFFSET + gs_address;
        // Call the entry function & "exit" afterwards
        unsafe{entry_from_rust()};
    }
}

#[cfg(not(test))]
#[no_mangle]  // Needed for angr to find the symbols
fn no_usercall(thread_control_state: &mut ThreadControlState, future_processor_state: &mut RustVars) {
    // Check for "thread init"
    // "bts check" (< Ulviya's C model)
    // Note: we can use "1" instead of (a variable bitoffset) because "$tcsls_flag_init_once" 
    // is always 1 !! (This has been checked!)
    let cf: u16 = (thread_control_state.tcsls_flags >> (TCSLS_FLAGS_INIT_ONCE_OFFSET % 16)) & 1;

    let di_bool: bool = load_tcls_flag_secondary_bool_rust(&{thread_control_state.tcsls_flags}); // "{..}" to fix https://github.com/rust-lang/rust/issues/82523

    if cf == 0 { // Thread has not been initialized yet!
        unsafe { tcs_init(di_bool); } 
        thread_control_state.tcsls_flags |= 0b10; // Set value!
    } // else: ".Lskip_init", but this is not used anymore!

    // Entering .Lafter_init now!
    let cx: bool = load_tcls_flag_secondary_bool_rust(&{thread_control_state.tcsls_flags});
    let cx_num: usize = if cx == true {1} else {0};
    future_processor_state.rcx = cx_num;  // Is this what I want? Probably always want 0, right?
}

#[cfg(not(test))]
#[no_mangle]
extern "C" fn entry_state_scrubber(gs_address: usize) -> ! {
    let callee_saved_state = get_callee_saved_vars_struct(gs_address);
    let future_processor_state = get_future_processor_state_struct(gs_address);
    
    future_processor_state.rdi = 0; // normal exit

    // perform actions of ".Lexit"
    future_processor_state.r8 = 0;
    future_processor_state.r9 = 0;
    future_processor_state.r10 = 0;
    // future_processor_state.r11 = 0; // Still needs to be set in assembly!

    future_processor_state.rax = 4; // EEXIT

    // Set jump address:
    future_processor_state.r11 = exit_call as usize; // get location of "enclu" instruction 

    // perform some actions of ".Lsgxexit"
    // Restores the callee_saved registers
    restore_user_registers(callee_saved_state, future_processor_state);

    unsafe{after_enclave_bootstrap()};
}

#[cfg(not(test))]
#[no_mangle]
extern "C" fn rust_usercall(address: usize, debug: usize) {
    let thread_control_state = get_thread_control_state_struct(address);
    let callee_saved_state = get_callee_saved_vars_struct(address);
    let future_processor_state = get_future_processor_state_struct(address);

    // We check the 'abort' function argument 
    if future_processor_state.rcx == 0 {  // Non-aborting usercall
        let usercall_state = get_usercall_state_struct(address);
        save_usercall_vars(thread_control_state, future_processor_state, usercall_state);
    } else { // Aborting usercall 
        // Set abort bit
        unsafe{asm!(
            "movb $1, .aborted(%rip)",
            options(att_syntax, nostack)
        )}

        // If debug mode? --> save variables --> debugger can reconstruct the stack!
        if debug & 0xff != 0 {
            let usercall_state = get_usercall_state_struct(address);
            save_usercall_vars(thread_control_state, future_processor_state, usercall_state);
        }
    }

    // Start clearing & restoring registers in preparation of sgx-exit 
    future_processor_state.r10 = 0;
    // future_processor_state.r11 = 0; // Still needs to be set in assembly!

    future_processor_state.rax = 4; // EEXIT

    future_processor_state.r11 = exit_call as usize;
    restore_user_registers(callee_saved_state, future_processor_state);
    unsafe{after_enclave_bootstrap()}
}

#[cfg(not(test))]
#[no_mangle] // Needed for angr to find the symbol
fn rust_usercall_ret(gs_address: usize, thread_control_state: &mut ThreadControlState, future_processor_state: &mut RustVars) {
    let usercall_state = get_usercall_state_struct(gs_address);

    future_processor_state.rsp = thread_control_state.tcsls_last_rsp;

    thread_control_state.tcsls_last_rsp = 0; // Last stack pointer -> 0

    /* Reload all variables stored before usercall */
    future_processor_state.mxcsr = usercall_state.mxcsr;
    future_processor_state.cw = usercall_state.cw;
    future_processor_state.rbp = usercall_state.rbp;
    future_processor_state.rbx = usercall_state.rbx;
    future_processor_state.r12 = usercall_state.r12;
    future_processor_state.r13 = usercall_state.r13;
    future_processor_state.r14 = usercall_state.r14;
    future_processor_state.r15 = usercall_state.r15;

    future_processor_state.r11 = usercall_state.rip; // jump to correct rip after returning from usercall

    // rax (& rdx) are the return values 
    future_processor_state.rax = future_processor_state.rsi; 
}


// |--------------------------------------------------------------------------|
// |------------------------------- Helper functions -------------------------|
// |--------------------------------------------------------------------------|
// NOTE: these functions are only called internally (from within Rust), so no 'extern "C"' annotation is needed!

fn load_tcls_flag_secondary_bool_rust(tcsls_flags: &u16) -> bool {
    let shift_val: u16 = 1 << TCSLS_FLAGS_SECONDARY_OFFSET; 
    let anded_result: usize = (tcsls_flags & shift_val) as usize; // ! Single "&" (bitwise comparison)
    anded_result != 0  // Convert to a bool
}

fn save_usercall_vars(thread_control_state: &mut ThreadControlState, future_processor_state: &mut RustVars, usercall_state: &mut RustCallVars) {
    // NOTE: duplicated code from above!
    usercall_state.rbx = future_processor_state.rbx;
    usercall_state.rbp = future_processor_state.rbp;
    usercall_state.r12 = future_processor_state.r12;
    usercall_state.r13 = future_processor_state.r13;
    usercall_state.r14 = future_processor_state.r14;
    usercall_state.r15 = future_processor_state.r15;
    usercall_state.mxcsr = future_processor_state.mxcsr;
    usercall_state.cw = future_processor_state.cw;
    thread_control_state.tcsls_last_rsp = future_processor_state.rsp;
}

fn get_thread_control_state_struct(gs_address: usize) -> &'static mut ThreadControlState {
    let raw_ptr = gs_address as *mut ThreadControlState;
    unsafe { raw_ptr.as_mut().unwrap() }
}

fn get_callee_saved_vars_struct(gs_address: usize) -> &'static mut CalleeSavedVars {
    let raw_ptr = (gs_address + size_of::<ThreadControlState>()) as *mut CalleeSavedVars;
    unsafe { raw_ptr.as_mut().unwrap() }
}

fn get_usercall_state_struct(gs_address: usize) -> &'static mut RustCallVars {
    let usercall_offset: usize = size_of::<ThreadControlState>() + size_of::<CalleeSavedVars>();

    let raw_usercall_ptr = (gs_address + usercall_offset) as *mut RustCallVars;
    unsafe { raw_usercall_ptr.as_mut().unwrap() }
}

fn get_future_processor_state_struct(gs_address: usize) -> &'static mut RustVars {
    let gs_rustvars_offset: usize = size_of::<ThreadControlState>() + size_of::<CalleeSavedVars>() + size_of::<RustCallVars>();

    let raw_rustvars_ptr = (gs_address + gs_rustvars_offset) as *mut RustVars;
    unsafe { raw_rustvars_ptr.as_mut().unwrap() }
}

fn restore_user_registers(callee_saved_state: &mut CalleeSavedVars, future_processor_state: &mut RustVars) {
    future_processor_state.r12 = callee_saved_state.tcsls_user_r12;
    future_processor_state.r13 = callee_saved_state.tcsls_user_r13;
    future_processor_state.r14 = callee_saved_state.tcsls_user_r14;
    future_processor_state.r15 = callee_saved_state.tcsls_user_r15;
    future_processor_state.rbx = callee_saved_state.tcsls_user_retip;
    future_processor_state.rsp = callee_saved_state.tcsls_user_rsp;
    future_processor_state.rbp = callee_saved_state.tcsls_user_rbp;
    future_processor_state.rcx = callee_saved_state.tcsls_user_retip; // This does not leak anything!
    future_processor_state.cw  = callee_saved_state.tcsls_user_fcw;
    future_processor_state.mxcsr = callee_saved_state.tcsls_user_mxcsr;
    future_processor_state.rflags = 0;  // Note: Just for "safety": should be ok, see "movq $0, %gs:rust_rflags" in entry.S
}

// External functions (< assembly)
extern "C" {fn entry_from_rust() -> ! ;}
extern "C" {fn after_enclave_bootstrap() -> ! ;}
extern "C" {fn exit_call() -> ! ;}

// |--------------------------------------------------------------------------|
// |---------------------- Custom variables & constants ----------------------|
// |--------------------------------------------------------------------------|
const ENTRY_XSAVE_OFFSET: usize = 0x180;
const USERCALL_XSAVE_OFFSET: usize = 0x3c0;
const TCSLS_FLAGS_SECONDARY_OFFSET: u16 = 0;
const TCSLS_FLAGS_INIT_ONCE_OFFSET: u16 = 1;

#[repr(C, packed)] // Need to add this, or Rust may change the order of the fields/add padding!
struct ThreadControlState {
    tcsls_tos: usize,                   /*  initialized by loader to *offset* from image base to TOS */
    tcsls_flags: u16,                   /*  initialized by loader */
    tcsls_last_rsp: usize,              /*  initialized by loader to 0 */
    tcsls_panic_last_rsp: usize,        /*  initialized by loader to 0 */ 
    tcsls_debug_panic_buf_ptr: usize,   /*  initialized by loader to 0 */ /* Saved at the start of sgx_entry code */
    tcsls_tls_ptr: usize,
    tcsls_tcs_addr: usize,
}

#[repr(C, packed)] // Need to add this, or Rust may change the order of the fields/add padding!
struct CalleeSavedVars {
    /* Storage space for the callee-saved registers */
    tcsls_user_fcw: u16,
    tcsls_user_mxcsr: u32,
    tcsls_user_rsp: usize,
    tcsls_user_retip: usize,
    tcsls_user_rbp: usize,
    tcsls_user_r12: usize,
    tcsls_user_r13: usize,
    tcsls_user_r14: usize,
    tcsls_user_r15: usize,
}

#[repr(C, packed)] // Need to add this, or Rust may change the order of the fields/add padding!
struct RustCallVars {
    rbx: usize,
    rbp: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    mxcsr: u32,
    cw: u16,
    padding: u16, // Might want to fix this in the future!
    rip: usize,  
}

#[repr(C, packed)] // Need to add this, or Rust may change the order of the fields/add padding!
struct RustVars {
    rsp: usize, 
    rax: usize, 
    rbx: usize, 
    rcx: usize, 
    rdx: usize, 
    rdi: usize, 
    rsi: usize, 
    rbp: usize, 
    r8 : usize,
    r9 : usize,
    r10: usize, 
    r11: usize, 
    r12: usize, 
    r13: usize, 
    r14: usize, 
    r15: usize, 
    rflags: usize, 
    cw: u16,  
    padding: u16, // Might want to fix this in the future!
    mxcsr: u32,
    real_tos: usize, // Does not need to be included?
    xsave_addr_choice: usize,
}
