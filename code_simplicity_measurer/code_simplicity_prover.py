# NOTE:
# Before running this file, the following conditions need to be met:
# - Need to have installed the CLOC tool
#     https://github.com/AlDanial/cloc
#     This tool has to be installed (available in a lot of package registries (e.g. Ubuntu))
# - Need a copy of the new Rust entry code (in rust std lib) in the current working directory
# - Need an internet connection to download the assembly files
#
# This file was tested with Python 3.8.10, no promises are made for other versions

import os
import requests
import subprocess
from typing import List, Set, Dict, Optional
import json  # For pretty printing
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd


def delete_given_files(directory, list_of_files_to_remove: List[str]):
    for asm_file in list_of_files_to_remove:
        # Custom installed --> do not want to remove this one (can't be installed from internet...)
        if asm_file != "fortanix_edp_new.S":
            os.remove(os.path.join(directory, asm_file))


def download_files(runtimes: Dict[str, List[str]]):
    # Download new files
    for [enclave_runtime_name, enclave_runtime_urls] in runtimes.items():
        print(enclave_runtime_name)
        with open(enclave_runtime_name + ".S", "wb") as out_file:
            for ABI_file_url in enclave_runtime_urls:
                content = requests.get(ABI_file_url, stream=True).content
                out_file.write(content)


def analyze_commentless_abi_files(runtimes: Dict[str, Optional[List[str]]], UncondAnalysis=True) -> Dict[str, Dict[str, int]]:
    # We want to both count the conditional & unconditional assembly instructions
    # We first want to remove all the "commented lines", for  this we'll be using "cloc" library:
    jumpStats: Dict[str, Dict[str, int]] = {}

    # We list all the "labels/function" that are are jumped to / called
    # This list has been verified *manually* to contain only the "safe" jump addresses
    # These are addresses that do not depend on e.g. being loaded into a register
    # Since this register can contain any address, it is vulnerable to LVI ...
    OPEN_ENCLAVE = {".nested_entry", ".return", ".state_machine_check", ".check_host_signal_request",
                    ".call_function", ".construct_stack_frame", "__oe_handle_main", ".eexit",
                    ".prepare_eexit", "oe_asm_exit", ".forever", "oe_snap_current_context",
                    "oe_real_exception_dispatcher", ".forever_loop", ".restore_host_registers", "1f","2f"}
    INTEL_SGX_SDK = {"restore_xregs", "enter_enclave", ".lswitch_stack", "save_xregs",
                     "update_ocall_lastsp", "do_ocall"}
    GRAMINE = {".lfail_loop\\@", "\\label_on_stack", ".lcssa0_ecall", ".lcssa1_exception_eexit",
               ".lcssa1_exception_rewire_ssa0_to_handler", "__restore_xregs",
               "__save_xregs", ".lcssa0_ocall_or_cssa1_exception_eexit",
               ".lcssa0_ocall_eexit_prepare", "2f", "_restore_sgx_context"}
    ENARX = {"{reloc}", "{clearx}", "{entry}", "{dyn_reloc}", "{clearp}", "3f"}
    GOTEE = {"runtime·sgxsettls(sb)", "setup", "runtime·stackcheck(sb)",
             "runtime·mstart", "nonsim", "runtime·check(sb)", "runtime·args(sb)",
             "nonsim", "runtime·check(sb)", "runtime·args(sb)", "runtime·osinit(sb)",
             "runtime·schedinit(sb)", "runtime·newproc(sb)", "runtime·mstart(sb)",
             "cleanup"}
    SGX_LKL = {"__initialize\\n", "__sgx_lkl_entry\\n", "__resume\\n",
               "__enclave_signal_handler\\n"}
    FORTANIX_EDP_ORIGINAL = {"tcs_init", ".lafter_init", "entry", "abort_reentry",
                             ".lusercall_save_state", ".lsgx_exit"}
    FORTANIX_EDP_NEW = {"enclave_bootstrapper", "entry_wrapper", "entry",
                        "rust_usercall", "entry_wrapper_test"}

    for enclave_runtime_name in runtimes.keys():
        print("analyzing: ", enclave_runtime_name)
        # Called via the command line
        file_to_strip: str = enclave_runtime_name + ".S"
        subprocess.run(["cloc", "--strip-comments=stripped", file_to_strip])

        cond_counter = 0
        uncond_counter = 0
        safe_uncond_counter = 0
        unsafe_uncond_counter = 0
        with open(os.path.join(os.getcwd(), file_to_strip + ".stripped"), "r") as f:
            lines = f.readlines()
            for line in lines:
                # First: strip each line from "leading signs" such as ", ', ...
                # Then split line on whitespaces & take first non-empty sequence of chars
                # Then strip this sequence of any ending signs such as comma, ", ', ...
                line = line.strip("\"',")
                cleaned_instruction_word = line.split(
                    maxsplit=1)[0].lower().strip("\"',")
                # print(line[:-1], "----->", line.split(maxsplit=1), "-->", cleaned_instruction_word)
                if cleaned_instruction_word in CONDITIONAL_JUMP_INSTRUCTIONS:
                    # print("-------------------------")
                    # print(line.split(maxsplit=1))
                    # print("conditional instruction: ", line.split(maxsplit=1)[0] in CONDITIONAL_JUMP_INSTRUCTIONS)
                    cond_counter += 1
                if cleaned_instruction_word in UNCONDITIONAL_JUMP_INSTRUCTIONS:
                    # print("-------------------------")
                    # print(line.split(maxsplit=1))
                    uncond_counter += 1
                    if UncondAnalysis:
                        # Note: we split twice to overcome "strange instruction" such as in Enarx,
                        # E.g.:  '"call   {RELOC}                     ",'
                        splitLine = line.lower().strip().strip("\"',").split(maxsplit=2)
                        # print(splitLine)
                        if len(splitLine) == 1 and splitLine[0] == "ret" or '"ret"' in splitLine[0]:
                            safe_uncond_counter += 1
                        elif splitLine[1].startswith("*%"):
                            unsafe_uncond_counter += 1
                        elif (enclave_runtime_name == "open_enclave" and splitLine[1] in OPEN_ENCLAVE) or (enclave_runtime_name == "intel_sgx_sdk" and splitLine[1] in INTEL_SGX_SDK) or (enclave_runtime_name == "gramine" and splitLine[1] in GRAMINE) or (enclave_runtime_name == "enarx" and splitLine[1] in ENARX) or (enclave_runtime_name == "gotee" and splitLine[1] in GOTEE) or (enclave_runtime_name == "sgx_lkl" and splitLine[1] in SGX_LKL) or (enclave_runtime_name == "fortanix_edp_original" and splitLine[1] in FORTANIX_EDP_ORIGINAL) or (enclave_runtime_name == "fortanix_edp_new" and splitLine[1] in FORTANIX_EDP_NEW):
                            safe_uncond_counter += 1
                        else:
                            print(
                                splitLine, "<<<<-------", "Still needs to be refiled! ; (considered \"dangerous\" for now!")
                            # We'll consider this as unsafe!
                            unsafe_uncond_counter += 1

        print("cond counter: ", cond_counter)
        current_file_stats = {}
        current_file_stats["Conditional jumps"] = cond_counter

        print("uncond counter: ", uncond_counter)
        if UncondAnalysis:
            print("   safe unconditional counter: ", safe_uncond_counter)
            print("   unsafe unconditional counter: ", unsafe_uncond_counter)
            current_file_stats["Unconditional Jumps to register"] = unsafe_uncond_counter
            current_file_stats["Unconditional Jumps to label"] = safe_uncond_counter
        else: 
            current_file_stats["Unconditional jumps"] = uncond_counter
        jumpStats[file_to_strip] = current_file_stats
    return jumpStats

# Now, let's go over each line and see if the first word/instruction/... matches one of the instruction we are looking for!

def jump_counter():

  
    # We'll count the amount of "conditional" and "unconditional" jumps in the given code
    runtime_stats = analyze_commentless_abi_files(runtimes)
    print(json.dumps(runtime_stats, indent=4, sort_keys=True))

    palette = sns.color_palette("Paired")
    pd.DataFrame(runtime_stats).T.plot(kind="bar", stacked=True, color={"Conditional jumps": "red", "Unconditional Jumps to register": "orange", "Unconditional Jumps to label": "green"}) # Or "color=palette"
    plt.title("The frequency count of conditional and unconditional jumps in popular Intel SGX runtimes.", fontsize="xx-large")
    plt.legend(fontsize="x-large") # See: https://stackoverflow.com/a/29694950/7767558
    plt.xlabel("Runtimes", fontsize="x-large")
    plt.ylabel("Frequency count", fontsize="x-large")
    y_pos = range(len(PRINTABLENAMES))
    plt.xticks(y_pos, PRINTABLENAMES, rotation=0, fontsize="large")
    plt.subplots_adjust(left=0.03, right=0.97, top=0.95, bottom=0.07)
    plt.show()

def count_unique_instructions():
    files_to_analyze = list(runtimes.keys())  

    unique_instructions_per_file = {}
    for enclave_runtime_name in files_to_analyze:
        print("analyzing: ", enclave_runtime_name)
        # Called via the command line
        file_to_strip: str = enclave_runtime_name + ".S"
        subprocess.run(["cloc", "--strip-comments=stripped", file_to_strip])


        unique_instructions = set() 

        with open(os.path.join(os.getcwd(), file_to_strip + ".stripped"), "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip("\"',")
                cleaned_instruction_word = line.split(
                    maxsplit=1)[0].lower().strip("\"',")

                # Only considered with "real asm instructions" 
                # Note: all lines starting with "." are considered as directives, not instructions
                # This is in line with  
                # print(cleaned_instruction_word, " : ", cleaned_instruction_word[-1])
                if (cleaned_instruction_word[-1] in {"l", "b", "w", "q"} and cleaned_instruction_word[:-1] in {"mov", "xor", "or", "add", "sub", "and", "push", "pop", "test", "cmp", "lea", "call", "ret", "xchg", "inc"}):
                    # print(cleaned_instruction_word, " : ", cleaned_instruction_word[-1])
                    unique_instructions.add(cleaned_instruction_word[:-1])
                elif (cleaned_instruction_word in {"jz", "je", "jnz", "jne", "jc", "jnc", "jo", "jcno", "js", "jns", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz", "jg", "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng", "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna"}):
                    unique_instructions.add("j" + "-instruction") # We consider all conditional jumps equal since has already been accounted in the "jump counter figure" in this file! 
                elif (not line.strip().endswith(":") and not line.strip().startswith(".") and not cleaned_instruction_word in {"globvar"}   
                    # Open Enclave
                    and not cleaned_instruction_word in {"oe_cleanup_registers", "oe_cleanup_xstates"}
                    # Intel SGX SDK
                    and not cleaned_instruction_word in {"declare_local_func", "lea_pic", "read_td_data", "get_stack_base", "clean_xflags", "se_prolog", "se_epilog", "declare_global_func"}
                    # Gramine
                    and not cleaned_instruction_word in {"fail_loop", "check_if_signal_stack_is_used", "(sgx_cpu_context_size"}
                    # Enarx
                    and not cleaned_instruction_word in {"extern", "use", "fn", "pub", "unimplemented!();", "}", "noted!", "static", "unsafe", "options(noreturn)", "size", "dyn_reloc", "asm!(", "4:", "rspo", "exto", "clearx", "clearp", "reloc", "entry", "eexit", "ssas[cssa].extra[0]", "match", "0", "1", "n", ")"}
                    # GoTEE
                    and not cleaned_instruction_word in {"get_tls(cx)", "get_tls(bx)", "get_tls(ax)"}
                    # Sgx-LKL
                    and not cleaned_instruction_word in {"_thread_initialized:", "void", ");", "{", ":::", "int"} and not line.strip().startswith("__") and not cleaned_instruction_word.strip().endswith("\\n")
                    # Old Fortanix
                    and not cleaned_instruction_word in {"0:", "1:", "2:", "3:", "load_tcsls_flag_secondary_bool" ,"entry_sanitize_final"}
                    # Modified Fortanix
                    and not cleaned_instruction_word in {"save_calling_convention_regs", "save_extra_regs", "load_extra_regs", "save_all_registers", "restore_all_registers"}):  
                    # print(cleaned_instruction_word, " : ", cleaned_instruction_word[-1])
                    unique_instructions.add(cleaned_instruction_word)
                # else:
                #     print("----", end=" ")
                # print(cleaned_instruction_word)

        print(len(unique_instructions))
        print(unique_instructions)

        unique_instructions_per_file[file_to_strip] = len(unique_instructions) 

    
    pd.DataFrame(unique_instructions_per_file, index=[0]).T.plot(kind="bar", legend=None) # , stacked=True, color={"Conditional jumps": "red", "Dangerous Unconditional Jumps": "orange", "Safe Unconditional Jumps": "green"}) # Or "color=palette"
    plt.title("The amount of different assembly instructions used in popular Intel SGX runtimes.", fontsize="xx-large")
    plt.xlabel("Runtimes", fontsize="x-large")
    plt.ylabel("Amount of different assembly instructions", fontsize="x-large")
    y_pos = range(len(PRINTABLENAMES))
    plt.xticks(y_pos, PRINTABLENAMES, rotation=0, fontsize="large")
    plt.subplots_adjust(left=0.03, right=0.97, top=0.95, bottom=0.07)
    plt.show()


# Global variables:
# Note: used the following pdf file to get all the conditional branch instructions in assembly
# https://www.philadelphia.edu.jo/academics/qhamarsheh/uploads/Lecture%2018%20Conditional%20Jumps%20Instructions.pdf
CONDITIONAL_JUMP_INSTRUCTIONS: Set[str] = {"jz", "je", "jnz", "jne", "jc", "jnc", "jo", "jcno", "js", "jns", "jp", "jpe", "jnp", "jpo",
                                            "jcxz", "jecxz", "jg", "jnle", "jge", "jnl", "jl", "jnge", "jle", "jng", "ja", "jnbe", "jae", "jnb", "jb", "jnae", "jbe", "jna"}
UNCONDITIONAL_JUMP_INSTRUCTIONS: Set[str] = {
    "call", "jmp", "ret"}  # TODO: probably more of these?!

if __name__ == "__main__":
    # NOTE: maybe we should consider only the production-quality runtimes?
    # Check e.g. OpenSGX which has been listed in the "sgx-abi-comparison" paper & which contains lots of mistakes (but no branching ..)
    # Or maybe, we could say that implementing this has never been done in a "correct" way?
    runtimes: Dict[str, Optional[List[str]]] = {
        "open_enclave": ["https://raw.githubusercontent.com/openenclave/openenclave/7249aa685d8faad177bd2096f07a70d26e9ab1c0/enclave/core/sgx/enter.S", "https://raw.githubusercontent.com/openenclave/openenclave/7249aa685d8faad177bd2096f07a70d26e9ab1c0/enclave/core/sgx/exit.S", "https://raw.githubusercontent.com/openenclave/openenclave/7249aa685d8faad177bd2096f07a70d26e9ab1c0/enclave/core/sgx/asmcommon.inc"],
        "intel_sgx_sdk": ["https://raw.githubusercontent.com/intel/linux-sgx/2ee53db4e8fd25437a817612d3bcb94b66a28373/sdk/trts/linux/trts_pic.S"],
        "gramine": ["https://raw.githubusercontent.com/gramineproject/gramine/65822f9bdf2dc8a9cde1c81cfc17b9166bb65ebb/Pal/src/host/Linux-SGX/enclave_entry.S"],
        "enarx": ["https://raw.githubusercontent.com/enarx/enarx/99352a16ff0e0f070d8492c5deb8b173050e17bc/internal/shim-sgx/src/main.rs"],
        "gotee": ["https://raw.githubusercontent.com/epfl-dcsl/gotee/014b35f5e5e9d11da880580cc654e2093ac8ad7a/src/runtime/asmsgx_amd64.s"],
        "sgx_lkl": ["https://raw.githubusercontent.com/lsds/sgx-lkl-musl/22c91c211aaf4048a4f034084bb7fa202bd6071c/crt/sgxcrt.c"],
        "fortanix_edp_original": ["https://raw.githubusercontent.com/rust-lang/rust/74fbbefea8d13683cca5eee62e4740706cb3144a/library/std/src/sys/sgx/abi/entry.S"],
    }

    PRINTABLENAMES = ["Open Enclave", "Intel SGX SDK", "Gramine", "Enarx",
                      "GoTEE", "SGX LKL", "Fortanix EDP (original)", "Fortanix EDP (modified)"]

    # Start by listing all files with ".S" or ".stripped" extensions
    all_files_in_dir = os.listdir(os.getcwd())
    all_assembly_files_in_dir: List[str] = [file for file in all_files_in_dir if file.endswith(".S") or file.endswith(".inc") or file.endswith(".stripped")]  # .inc for OpenEnclave case
    print("All files in {} with \".S\"  or \".inc\" or \".stripped\" extension: ", os.getcwd())
    for asm_file in all_assembly_files_in_dir:
        print("   - ", asm_file)

    # Request if user wants listed files deleted & redownloaded
    val: str = input("Enter 'y' if you want old files removed & redownloaded: ")

    # If answer is yes, then first delete files and afterwards download files
    if val == "y":
        delete_given_files(os.getcwd(), all_assembly_files_in_dir)
        download_files(runtimes)

    # Now, we can do the actual analysis:
    # But first, we need to add the "new" fortanix code to verify this as well!
    runtimes["fortanix_edp_new"] = [None]
    

    # jump_counter()

    # We'll count different instructions here, to see how much "simpler" the code has become
    count_unique_instructions()
    
    