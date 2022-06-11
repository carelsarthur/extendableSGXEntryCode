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

import logging, sys
import angr
import sys
import pyvex
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from simulation_procedures import malloc, Empty, TransitionToTrusted, TransitionToExiting, TransitionToOcall, TransitionToTrusted, OcallAbstraction, TransitionToExited, EnteringEnclave, SimEnclu, Nop, Rdrand, UD2, Entry, SwitchToTemporaryStack, SwitchToRealStack #, TransitionToEnclaveBootstrapperRust
from controlstate import ControlState
from typing import Optional

log = logging.getLogger(__name__)


class Hooker:
    # def setup(self, proj, simgr, ecalls, ocalls, exited_addr, enter_addr, old_sdk):
    def setup(self, proj, simgr, entry_addr, well_defined_state_addr, exiting_addr, exited_addr, init_state, full_analysis: bool):
        self.instruction_hooker(proj, self.instruction_replacement(exited_addr, proj))
        print("instruction hooker setup!")
        self.libc_functions_hooker(proj)
        print("libc hooker setup!")
        # self.transitions_hooker(proj, ecalls, ocalls, exited_addr, enter_addr, old_sdk)
        if full_analysis:
            self.test_transitions_hooker(proj, entry_addr, well_defined_state_addr, exiting_addr, exited_addr)
            print("own transitions set up!")
        # self.custom_transitions_hooker(proj, init_state, simgr)
        return proj, simgr

    def instruction_hooker(self, angr_proj, ins_to_sim_proc):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = True  # If invalid instruction is found, search for next valid one instead of aborting
        for section in angr_proj.loader.main_object.sections:
            if section.is_executable:
                section_bytes = angr_proj.loader.memory.load(
                    section.vaddr, section.memsize)
                for i in md.disasm(section_bytes, section.vaddr):
                    sim_proc = ins_to_sim_proc(i)
                    if sim_proc is not None:
                        logging.debug("0x%x:\t%s\t%s\t%s" %
                                      (i.address, i.mnemonic, i.op_str,
                                       i.size))
                        angr_proj.hook(i.address, hook=sim_proc, length=i.size)

    def libc_functions_hooker(self, proj):
        # TODO: this errors if I leave these functions here !?
        # If I remove/comment them, everything seems to work just fine ...
        proj.hook_symbol("dlmalloc", malloc())
        proj.hook_symbol("dlfree", angr.SIM_PROCEDURES['libc']['free']())
        proj.hook_symbol("printf", Empty())
        proj.hook_symbol("memcpy", angr.SIM_PROCEDURES['libc']['memcpy']())
        proj.hook_symbol("memset", angr.SIM_PROCEDURES['libc']['memset']())
        proj.hook_symbol("dlrealloc", angr.SIM_PROCEDURES['libc']['realloc']())

    def transitions_hooker(self, proj, ecalls, ocalls, exit_addr, enter_addr,
                           old_sdk):
        if ecalls is not None:
            for (ecall_index, ecall_name, ecall_addr, ecall_rets) in ecalls:
                for (call_addr, ret_addr) in ecall_rets:
                    proj.hook(call_addr, hook=TransitionToTrusted())
                    proj.hook(ret_addr, hook=TransitionToExiting())
        if ocalls is not None:
            for (ocall_name, ocall_addr, sgx_ocalls, ocall_rets) in ocalls:
                proj.hook(ocall_addr, hook=TransitionToOcall())
                for ret_addr in ocall_rets:
                    proj.hook(ret_addr, hook=TransitionToTrusted())
        sgx_ocall_addr = proj.loader.find_symbol("sgx_ocall").rebased_addr
        proj.hook(sgx_ocall_addr, hook=OcallAbstraction())
        proj.hook(exit_addr, hook=TransitionToExited(no_sanitisation=old_sdk))
        proj.hook(
            enter_addr,
            hook=RegisterEnteringValidation(no_sanitisation=old_sdk))

    def test_transitions_hooker(self, proj, entry_addr, trusted_state_addr, exiting_addr, exit_addr):
        proj.hook(entry_addr, hook=EnteringEnclave())
        proj.hook(trusted_state_addr, hook=TransitionToTrusted())
        proj.hook(exiting_addr, hook=TransitionToExiting())
        proj.hook(exit_addr, hook=TransitionToExited())
        proj.hook(proj.loader.find_symbol("go_to_real_stack").rebased_addr, hook=SwitchToRealStack())
        proj.hook(proj.loader.find_symbol("using_temp_stack_again").rebased_addr, hook=SwitchToTemporaryStack())

    def instruction_replacement(self, exit_addr, angr_project):
        def replace(capstone_instruction) -> Optional[angr.SimProcedure]:
            # print(capstone_instruction, " : ", capstone_instruction.mnemonic)
            if capstone_instruction.mnemonic == "enclu" and capstone_instruction.address != exit_addr:
                # exit_addr = address of the "enclu" call at label "exit_call" in entry.S
                return SimEnclu()
            elif "xsave" in capstone_instruction.mnemonic:
                return Nop(bytes_to_skip=capstone_instruction.size)  # NOTE: the original "guardian code" contained a mistake here!
            elif "xrstor" in capstone_instruction.mnemonic:
                return Nop(bytes_to_skip=capstone_instruction.size)
            elif capstone_instruction.mnemonic == "fxrstor64":
                return Nop(bytes_to_skip=capstone_instruction.size)
            elif capstone_instruction.mnemonic == "rdrand":
                return Rdrand()
            elif capstone_instruction.mnemonic == "ud2":
                return UD2()
            # TODO: remove this later on: we want to skip the "entry" function for now!
            elif capstone_instruction.mnemonic == "call" and capstone_instruction.op_str == str(hex(angr_project.loader.find_symbol("entry").rebased_addr)):
                print("found the entry instruction, we are not doing this call here!")
                return Entry(bytes_to_skip=capstone_instruction.size)
            else:
                None
        return replace