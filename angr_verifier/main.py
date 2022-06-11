""" Guardian
    Copyright (C) 2021  The Blockhouse Technology Limited (TBTL)
    Copyright (C) 2022  Arthur Carels

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>."""

import angr
# Note: this code is heavily based on the "guardian code" that was provided (from project.py)
# I added some optimizations & changes where necessary
# TODO: still need to check the licences!!!

# import "top-level structure" to avoid name clashes between the module namespaces
import claripy
from angr.calling_conventions import SimCCSystemVAMD64
from cle.backends.elf.relocation.amd64 import arch

import layout
import hooker
import breakpoints
import plugins
from explorer import EnclaveExploration

from typing import List, Dict
import argparse

import logging, sys
log = logging.getLogger(__name__)

class Project:
    def __init__(self, angr_project, full_analysis: bool):
        self.angr_project = angr_project

        # Define some of the addresses we are interested in:
        self.enter_addr = self.angr_project.loader.find_symbol("sgx_entry").rebased_addr
        self.bootstrap_point_address = self.angr_project.loader.find_symbol("enclave_bootstrap_point").rebased_addr
        self.after_bootstrap_point_address = self.angr_project.loader.find_symbol("after_enclave_bootstrap").rebased_addr
        self.entry_main_address = self.angr_project.loader.find_symbol("entry").rebased_addr
        self.exit_call_addr = self.angr_project.loader.find_symbol("exit_call").rebased_addr
        self.exit_addr = self.angr_project.loader.find_symbol("enclu_call").rebased_addr
        # Some extra "intermediary addresses"
        self.usercall_addr = self.angr_project.loader.find_symbol("usercall").rebased_addr
        self.reentry_panic_addr = self.angr_project.loader.find_symbol("abort_reentry").rebased_addr
        self.usercall_ret_function_addr = self.angr_project.loader.find_symbol("rust_usercall_ret").rebased_addr
        self.entry_wrapper_function_addr = self.angr_project.loader.find_symbol("entry_state_scrubber").rebased_addr
        self.well_defined_state_addr = self.angr_project.loader.find_symbol(".well_defined_state").rebased_addr
        self.stored_and_reset_registers = self.angr_project.loader.find_symbol(".stored_and_reset_registers").rebased_addr

        # Define the lay-out of the enclave:
        self.layout = layout.EnclaveMemoryLayout(self.angr_project)
        self.layout.get_layout(self.angr_project)

        # Initialize the enclave state
        self.init_enclave_state()
        self.entry_state.register_plugin('heap',
                                         angr.SimHeapBrk(
                                             heap_base=self.layout.heap_start,
                                             heap_size=self.layout.HEAP_SIZE))
        self.entry_state.register_plugin('enclave',
                                         plugins.EnclaveState(self.angr_project, entry_state=self.entry_state))
        self.entry_state.libc.max_memcpy_size = 0x100   # TODO: Set other limits here? + understand meaning of this?!
        self.entry_state.libc.max_buffer_size = 0x100
        self.entry_state.enclave.init_trace_and_stack()

        # Set up a simulation factory
        self.simgr = self.angr_project.factory.simgr(self.entry_state)  #, veritesting=True)

        # Setting up hooks!
        self.angr_project, self.simgr = hooker.Hooker().setup(
            self.angr_project, self.simgr, self.enter_addr, self.well_defined_state_addr, self.after_bootstrap_point_address, self.exit_addr, self.entry_state, full_analysis)

        # Set up breakpoints!
        if full_analysis:
            self.angr_project, self.simgr = breakpoints.Breakpoints().setup(
                self.angr_project, self.simgr, self.layout)
            self.simgr.use_technique(EnclaveExploration())

    def init_enclave_state(self) -> None:
        """
        This function initializes the enclave state.
        It initializes the general purpose registers with a unique symbolic value.
            This can be used for taint analysis.
        Additionally, it also gives some symbolic values to variables that control branching.
            Example: tcsls_flags is made symbolic to either call tcs_init or not.
        Lastly, some global and thread-specific data is set
        """""
        self.entry_state = self.angr_project.factory.blank_state(cc=SimCCSystemVAMD64(arch),
                                add_options={"SYMBOL_FILL_UNCONSTRAINED_MEMORY", "SYMBOLIC_WRITE_ADDRESSES",
                                             "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"})
        self.entry_state.regs.rip = self.enter_addr  
        assert self.entry_state.solver.eval(self.entry_state.regs.rip) == self.enter_addr

        # Set all GPRs
        self.init_registers("init_")  # Set the registers to some default state
        # Source: https://cdrdv2.intel.com/v1/dl/getContent/671200, Vol. 3D 37-99
        self.entry_state.regs.rax = 0x0  # RBX.CSSA
        self.entry_state.regs.rbx = self.layout.tcs_addr

        #̉ NOTE: we make the assumption that debug bit has not been set!
        # This is also what happens for production use, so proving this is most important!
        # 0 is the default value! --> debug bit not set
        # This assumptions is made because enabling the line below gives following error:
        #   AttributeError: 'ELFSymbol' object has no attribute 'symbolic'
        # self.entry_state.mem[self.angr_project.loader.find_symbol("DEBUG")].uint8_t = self.entry_state.solver.BVS("init_" + "DEBUG", 8)  # ELF symbols not allowed to be symbolic ...

        # NOTE: Below some values on the gs segment (+ .aborted) are set to cover more execution paths. 
        # Two extra branches are added for "tcs_init" (and abort within tcs_init!)
        self.entry_state.mem[self.entry_state.regs.gs + 0x08].uint16_t = self.entry_state.solver.BVS("init_" + "tcsls_flags", 16)  # --> + 2 states found

        # Note this one gives some "out of bounds" errors! Still need to fix these! TODO:
        # Reason: the stack pointer is "random" and should point to some area within the stack!
        # self.entry_state.mem[self.entry_state.regs.gs + 0x0a].uint64_t = self.entry_state.solver.BVS("init_" + "tcsls_last_rsp", 64)  # --> + 1 state found

        # If abort bit is set, execution is immediately aborted!
        self.entry_state.mem[self.angr_project.loader.find_symbol(".aborted").rebased_addr].uint8_t = self.entry_state.solver.BVS("init_" + "aborted", 8)  # --> + 1 state found

        self.layout.set_global_data(self.angr_project, self.entry_state)
        self.layout.set_thread_data(self.entry_state)

    def init_registers(self, distinct_name: str) -> None:
        """
        Initializes registers:
        - general purpose registers: get unique symbolic value (startsing with "init_")
        - gs segment registers: gets value as calculated by layout.py
        """
        self.entry_state.regs.rsp  =  self.entry_state.solver.BVS(distinct_name + "rsp", 64)
        self.entry_state.regs.rax  =  self.entry_state.solver.BVS(distinct_name + "rax", 64)
        self.entry_state.regs.rbx  =  self.entry_state.solver.BVS(distinct_name + "rbx", 64)
        self.entry_state.regs.rcx  =  self.entry_state.solver.BVS(distinct_name + "rcx", 64)
        self.entry_state.regs.rdx  =  self.entry_state.solver.BVS(distinct_name + "rdx", 64)
        self.entry_state.regs.rdi  =  self.entry_state.solver.BVS(distinct_name + "rdi", 64)
        self.entry_state.regs.rsi  =  self.entry_state.solver.BVS(distinct_name + "rsi", 64)
        self.entry_state.regs.rbp  =  self.entry_state.solver.BVS(distinct_name + "rbp", 64)
        self.entry_state.regs.r8   =   self.entry_state.solver.BVS(distinct_name + "r8", 64)
        self.entry_state.regs.r9   =   self.entry_state.solver.BVS(distinct_name + "r9", 64)
        self.entry_state.regs.r10  =  self.entry_state.solver.BVS(distinct_name + "r10", 64)
        self.entry_state.regs.r11  =  self.entry_state.solver.BVS(distinct_name + "r11", 64)
        self.entry_state.regs.r12  =  self.entry_state.solver.BVS(distinct_name + "r12", 64)
        self.entry_state.regs.r13  =  self.entry_state.solver.BVS(distinct_name + "r13", 64)
        self.entry_state.regs.r14  =  self.entry_state.solver.BVS(distinct_name + "r14", 64)
        self.entry_state.regs.r15  =  self.entry_state.solver.BVS(distinct_name + "r15", 64)
        self.entry_state.regs.dflag  = self.entry_state.solver.BVS(distinct_name + "dflag", 64)
        self.entry_state.regs.acflag = self.entry_state.solver.BVS(distinct_name + "acflag", 64)
        self.entry_state.regs.gs   = self.layout.gs_addr  # This cannot be a symbolic value!

    @staticmethod
    def verify_exit_correctness(state, entry_state) -> None:
        """
        This function verifies the correctness of the exit part written in *assembly*.
        Things checked:
        - The callee_saved registers are correctly restored
        - Values are correctly restored from the gs segment (into the corresponding registers)
        - Flags register correctly cleared (AC & DF flag especially!)
        """
        # We start by verifying that the "calling convention" registers have been correctly restored
        # NOTE: will only work when "restore_user_registers()" is called!
        # Format of  the dictionary: "input" reg : "output" reg
        restored_registers: Dict[str, str] = {
            "rsp": "rsp",
            "rcx": "rbx",  # input(rcx) = user_retip = output(rbx) (see below!)
            "rbp": "rbp",
            "r12": "r12",
            "r13": "r13",
            "r14": "r14",
            "r15": "r15",}
        for reg, loc in restored_registers.items():
            # print(reg, ": ", entry_state.registers.load(reg), " =?= ", state.registers.load(loc))
            if type(state.registers.load(loc)) == angr.state_plugins.sim_action_object.SimActionObject:
                assert(claripy.is_true(entry_state.registers.load(reg) == state.registers.load(loc).to_claripy()))
            else:
                assert(claripy.is_true(entry_state.registers.load(reg) == state.registers.load(loc)))

        # Verify whether all values on the "future-processor" state part of the gs segment have been restored
        # to the corresponding registers
        custom_vars_dict: Dict[str, int] = {
            "rsp": 0xb0,  
            "rax": 0xb8,
            "rbx": 0xc0,
            "rcx": 0xc8,
            "rdx": 0xd0,
            "rdi": 0xd8,
            "rsi": 0xe0,
            "rbp": 0xe8,  
            "r8":  0xf0,
            "r9":  0xf8,
            "r10": 0x100,
            # "r11": 0x108,  # r11 on gs-segment contains "enclu_call" address, at end it is zero!
            "r12": 0x110,
            "r13": 0x118,
            "r14": 0x120,
            "r15": 0x128,
            # "cw": 0x130,  # Not supported by angr ...
            # "mxcsr": 0x134,  # Not supported by angr ...
        }
        for reg, loc in custom_vars_dict.items():
            if type(state.registers.load(reg)) == angr.state_plugins.sim_action_object.SimActionObject:
                assert(claripy.is_true(state.registers.load(reg).to_claripy() == state.mem[state.registers.load("gs") + loc].uint64_t.resolved))
            else:
                assert(claripy.is_true(state.registers.load(reg) == state.mem[state.registers.load("gs") + loc].uint64_t.resolved))

        # Verify if the flags register has been correctly set (same requirements as for "verify_entry_requirements()" )
        if state.solver.satisfiable(extra_constraints=[state.regs.dflag != 0x1]):
            log.error("######### EXITING ZEROED_REG ERROR %s %s ###############", "dflag", state.regs.dflag)
        if state.solver.satisfiable(extra_constraints=[state.regs.acflag != 0x0]):
            log.error("######### EXITING ZEROED_REG ERROR %s %s ###############", "acflag", state.regs.acflag)

    @staticmethod
    def print_out_register_values(state) -> None:
        """
        This function is used to get tables as in Ulviyya's thesis.
        It prints the name of the register together with its value.

        :param state: The state of which the register values need to be printed

        Note: this is a static function!
        """
        registers_to_print: List[str] = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                  "rax", "rip", "rcx", "rbx", "rbp", "rsi", "rdi", "rdx", "rsp", "acflag", "dflag"]
        for reg in registers_to_print:
            # NOTE: important if you want to "concretize the bitvectors, a symbolic vector will be turned into zero!
            # Therefore we have "to live" with the "ugly" print-out we get
            # print('{:<8} : {}'.format(reg, hex(self.simgr.found[state_nr].solver.eval(self.simgr.found[state_nr].registers.load(reg)))))
            print('{:<8} : {}'.format(reg, state.registers.load(reg)))

    @staticmethod
    def verify_entry_correctness(current_state, entry_state) -> None:
        """
        This (static!) function verifies the correctness of the entry part written in *assembly*.
        Things checked:
        - Register values correctly saved on the gs segment
        - Flags register correctly cleared (AC & DF flag especially!)
        -
        Note: this is a static function!
        """

        # We check that the initial register state has been saved succesfully on the gs segment
        # There are two places where this has to happen:
        #  - On the "callee_saved-state" part of the gs segment
        #  - On the "future-state" part of the gs segment
        # This is reflected by the two dicts below!
        callee_saved_values_dict: Dict[str, int] = {
            "rbx": 0x2A,
            "rsp": 0x38,
            "rcx": 0x40,
            "rbp": 0x48,
            "r12": 0x50,
            "r13": 0x58,
            "r14": 0x60,
            "r15": 0x68,
            # "mxcsr": 0x32,
        }
        custom_vars_dict: Dict[str, int] = {
            # "rsp": 0xa8, # NOTE: ofcourse not, was using wrong stack before!!!
            "rax": 0xb8,
            "rbx": 0xc0,
            "rcx": 0xc8,
            "rdx": 0xd0,
            "rdi": 0xd8,
            "rsi": 0xe0,
            # "rbp": 0xe8, # NOTE: ofcourse not, was using wrong stack before!!!
            "r8" : 0xf0,
            "r9" : 0xf8,
            "r10": 0x100,
            "r11": 0x108,
            "r12": 0x110,
            "r13": 0x118,
            "r14": 0x120,
            "r15": 0x128,
            # "cw": 0x130,  # Not supported by angr ...
            # "mxcsr": 0x134,  # Not supported by angr ...
        }
        for reg, loc in {**callee_saved_values_dict, **custom_vars_dict}.items():  # We merge both dicts
            # print(reg, " : ", entry_state.registers.load(reg), " =?= ", current_state.mem[current_state.registers.load("gs") + loc].uint64_t.resolved)
            assert(claripy.is_true(entry_state.registers.load(reg) ==
                                   current_state.mem[current_state.registers.load("gs") + loc].uint64_t.resolved))

        # Next, we check whether the "flags registers" have been set correctly
        #  - DF: Should be 0x1
        #       (--> this is ok, despite "tale of 2 worlds saying it should be 0 ?!
        #       Maybe this has to do with fact that it's a virtual register?)
        #  - AC: Should always be 0x0
        if current_state.solver.satisfiable(extra_constraints=[current_state.regs.dflag != 0x1]):
            log.error("######### ENTERING ZEROED_REG ERROR %s %s ###############", "dflag", current_state.regs.dflag)
        if current_state.solver.satisfiable(extra_constraints=[current_state.regs.acflag != 0x0]):
            log.error("######### ENTERING ZEROED_REG ERROR %s %s ###############", "acflag", current_state.regs.acflag)

        # TODO: check the xsave & xrstor working!
        # NOTE: do I just have to implement this myself? (This is not provided by angr, but won't know if my implementation is fully correct? )
         

if __name__ == '__main__':
    """
    Note this function can be called in two ways:
    - simple analysis: only verifies that the entry and exit sequence written in *assembly* satisfy some checks.
    - full analysis: covers all code paths of the ABI code and tries to find security violations.
    -
    Note: by default the simple analysis is done (because it is less time consuming).
    Requesting full analysis can be done as follows:
    python3 main.py -f True 
    """
    # Set up logging; The lower you set this level, the more logging you'll get!
    angr_logging_level = logging.ERROR  # CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
    logging.getLogger('guardian').setLevel(angr_logging_level)
    logging.getLogger('angr').setLevel(angr_logging_level)
    logging.getLogger('cle.loader').setLevel(angr_logging_level)

    # Initialize the argparser (which checks if full analysis is requested)
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--full", "--full-analysis", help="Set \"True\" if you want full analysis of the binary")
    args = parser.parse_args()
    full_analysis: bool = args.full and args.full.lower() == "true"  # True? --> request "full analysis" later on!

    enclave_path: str = "/tmp/app/target/x86_64-fortanix-unknown-sgx/debug/app"
    proj = angr.Project(enclave_path, load_options={'auto_load_libs': False}, main_opts={"base_addr": 0})#, engine=angr.engines.unicorn.SimEngineUnicorn)
    guard = Project(proj, full_analysis)

    if not full_analysis:
        # This analysis is mainly concerned with verifiying the correctness of the entry and exit blocks
        # Entry:
        #   - Registers have been stored at the correct location on the gs segment
        #   - Flags register cleared (DF & AC) 
        #   - Stack has been correctly set (& no writing/reading to/from stack before that)
        # Exit:
        #   - Registers correctly restored from their location on the gs segment (=future-processor_state)
        #   - Flags register (DF) cleared
        #   - Callee-saved registers restored
        #   - Rsp & Rbp restored to their initial values
        #
        # NOTE: a bit of "cheating" occurs for this check
        #   We still run through the whole binary (with exception of "entry")
        #   But, the checks for e.g. "out-of-enclave" reads etc. are skipped
        #   An initial attempt changed the "rip" in the userhook below, but then we got complaints about "jmp *%r11" being unbounded
        #   There seems to be some issue with angr around this, it did not seem worth it to fix as the validity
        #       of the checks is just the same using this approach!
        #   Initial appraoch was a follows (within "verify_correctness hook):
        #   - state.regs.rip = guard.after_bootstrap_point_address
        #   - state.regs.r11 = guard.exit_call_addr

        # We hook the verify_entry_correctness function to the "well-defined_state" address
        # When this address is reached, the entry correctness will be verified
        @proj.hook(guard.well_defined_state_addr, length=0)  # length = 0 --> we continue immediately after this!
        def verify_correctness_hook(state):
            print("######### Verifying correct entry procedure: #########")
            Project.verify_entry_correctness(state, guard.entry_state)
            print("######### Entry procedure verification done: #########")

        # We'll walk through the binary until we find the exit address
        guard.simgr.explore(find=guard.exit_addr,
                        avoid=[guard.usercall_addr, guard.reentry_panic_addr, guard.usercall_ret_function_addr])

        # But first, we'll reach the user hook as defined above
        # The entry correctness is verified at that point with "verify_entry_correctness"

        # Now, that these tests have passed, it's time to test the exit procedure
        # This corresponds to the "after_enclave_bootstrap" label in entry.S
        print("######### Verifying correct exit procedure: ##########")
        Project.verify_exit_correctness(guard.simgr.found[0], guard.entry_state)
        print("######### Exit procedure verification done: ##########")

    else:
        # We do a full analysis here:
        # We start at "sgx_entry" and continue analyzing the code until "enclu_call"
        #
        # At the moment 5 states are discovered when doing "guard.simgr.run()":
        # 1. - Exit after entry (without TCS init)
        # 2. - Exit after entry (with TC init)
        # 3. - Return from usercall (this errors! Probably because "wrong" values are restored from gs segment!)
        # 4. - Aborting usercall 
        # 5. - Non-Abort usercall    
        #

        # Note: assumption: we "skip" the debugging possibility (since symbolic ELF values are not allowed apparently..)
        print(guard.simgr.explore()) # find=guard.exit_call_addr))

# Some useful commands: 
# - guard.simgr.exited[2].enclave.print_trace()
# - Project.print_out_register_values(guard.simgr.exited[2]
