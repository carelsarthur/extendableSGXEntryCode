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
import angr, claripy
from controlstate import ControlState, Rights
from violation_type import ViolationType
from main import Project
from typing import Dict
import itertools
import collections

log = logging.getLogger(__name__)


class SimEnclu(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self):
        enclu_length_in_bytes = 3
        if self.state.solver.eval(self.state.regs.eax == 0x0):
            log.debug("EREPORT")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x1):
            log.debug("EGETKEY")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x2):
            log.critical("Unexpected EENTER")
            self.exit(1)
        elif self.state.solver.eval(self.state.regs.eax == 0x4):
            log.critical("Unexpected EEXIT")
            self.exit(1)
        else:
            log.critical("Unexpected ENCLU")
            self.exit(1)


# TODO: fix this?            
class AbortReentry(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self):
        self.state.regs.rcx = 0;


class Nop(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')


class Empty(angr.SimProcedure):
    def run(self):
        pass


class UD2(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("UD2 detected! Aborting this branch!")
        log.debug(hex(self.state.addr))
        self.successors.add_successor(self.state, self.state.addr,
                                      self.state.solver.true, 'Ijk_NoHook')
        self.exit(2)


class Rdrand(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.state.regs.flags = 1
        self.successors.add_successor(self.state, self.state.addr + 3,
                                      self.state.solver.true, 'Ijk_Boring')

class SwitchToRealStack(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.state.get_plugin("enclave").temporary_stack = False
        self.successors.add_successor(self.state, self.state.addr,
                                      self.state.solver.true, 'Ijk_NoHook')

class SwitchToTemporaryStack(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.state.get_plugin("enclave").temporary_stack = True
        self.successors.add_successor(self.state, self.state.addr,
                                      self.state.solver.true, 'Ijk_NoHook')


class EnteringEnclave(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.error("######### REGISTER ENTERING VALIDATION ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.SgxEntry:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         "EnteringSanitisation")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        # else:
        #    log.error("kwargs: {}".format(kwargs["no_sanitisation"]))
        #    assert "no_sanitisation" in kwargs
        #    if not kwargs["no_sanitisation"]:
        #        violation = Validation.entering(self.state)
        #        if violation is not None:
        #            self.state.enclave.set_violation(violation)
        #            self.state.enclave.found_violation = True
        self.state.enclave.control_state = ControlState.Entering
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToTrusted(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### TRUSTED ###############")
        assert self.state.has_plugin("enclave")
        if not (self.state.enclave.control_state == ControlState.Entering):
                # or self.state.enclave.control_state == ControlState.Ocall):
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         ControlState.Trusted)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True

        validation_errors = Validation.entering(self.state, self.state.enclave.entry_state)
        if validation_errors is not None:
            self.state.enclave.set_violation(validation_errors)
            self.state.enclave.found_violation = True
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         "Entering Trusted without entry sanitisation")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.NoReadOrWrite
            self.state.enclave.control_state = ControlState.Trusted
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExiting(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITING ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Trusted:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state,
                         ControlState.Exiting)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.Write
            self.state.enclave.control_state = ControlState.Exiting
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExited(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.error("######### EXITED ###############")
        assert self.state.has_plugin("enclave")
        if not (self.state.enclave.control_state == ControlState.Exiting
                or self.state.enclave.control_state == ControlState.Entering
            or self.state.enclave.control_state == ControlState.SgxEntry):  # TODO: correct addition? (Only check for abort in Rust code though...?)
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, ControlState.Exited)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            if self.state.enclave.control_state == ControlState.Exiting:
                violation = Validation.exited(self.state, self.state.enclave.entry_state)
                if violation is not None:
                    self.state.enclave.set_violation(violation)
                    self.state.enclave.found_violation = True
            self.state.enclave.control_state = ControlState.Exited
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToOcall(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### OCALL ###############")
        log.debug(hex(self.state.addr))
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Trusted:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, ControlState.Ocall)
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        else:
            self.state.enclave.ooe_rights = Rights.ReadWrite
            self.state.enclave.control_state = ControlState.Ocall
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class OcallAbstraction(angr.SimProcedure):
    def run(self, **kwargs):
        log.debug("######### OCALL ABSTRACTION ###############")
        assert self.state.has_plugin("enclave")
        if self.state.enclave.control_state != ControlState.Ocall:
            violation = (ViolationType.Transition,
                         ViolationType.Transition.to_msg(),
                         self.state.enclave.control_state, "OcallAbstraction")
            self.state.enclave.set_violation(violation)
            self.state.enclave.found_violation = True
        return self.state.solver.Unconstrained("ocall_ret",
                                               self.state.arch.bits)


class malloc(angr.SimProcedure):
    def run(self, sim_size):
        if self.state.solver.symbolic(sim_size):
            log.warning("Allocating size {}\n".format(sim_size))
            size = self.state.solver.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                log.warning(
                    "Allocation request of %d bytes exceeded maximum of %d bytes; allocating %d bytes",
                    size, self.state.libc.max_variable_size,
                    self.state.libc.max_variable_size)
                size = self.state.libc.max_variable_size
                self.state.add_constraints(sim_size == size)
        else:
            size = self.state.solver.eval(sim_size)
        return self.state.heap._malloc(sim_size)

class Entry(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        # TODO: this needs to be fixed still !!!!
        # self.state.mem[self.state.regs.gs + 0x13a].uint64_t = self.state.solver.BVS("entry_call_" + "rax", 8)
        # self.state.mem[self.state.regs.gs + 0x13a].uint64_t = self.state.solver.BVS("entry_call_" + "rdx", 8)
        state_copy = self.state.copy()
        # self.state.
        # self.project.simgr.stashed[ControlStateName.ExitedStashName] += state_copy

        self.successors.add_successor(state_copy, self.state.addr, self.state.solver.true, "Ijk_Exit")

        self.state.regs.rdx = self.state.solver.BVS("entry_call_" + "rdx", 64)
        self.state.regs.rax = self.state.solver.BVS("entry_call_" + "rax", 64)

        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')

class Validation:
    def entering(state, entry_state):
        log.debug("######### VALIDATION REGS ON ENTRY ###############")
        state.solver.simplify()

        error_regs = []

        Project.verify_entry_correctness(current_state=state, entry_state=entry_state)

        if state.solver.satisfiable(extra_constraints=[state.regs.ac != 0x0]):
            log.debug("######### ENTERING AC ERROR %s ###############",
                      state.regs.ac)
            error_regs.append("ac")
        # DF SET is 0xffffffffffffffff in angr
        # whereas DF CLEAR = 0x1
        if state.solver.satisfiable(
                extra_constraints=[state.regs.dflag != 0x1]):
            log.debug("######### ENTERING DF ERROR %s ###############",
                      state.regs.dflag)
            error_regs.append("df")

        if error_regs:
            return (ViolationType.EntrySanitisation,
                    ViolationType.EntrySanitisation.to_msg(), error_regs)

    def exited(state, entry_state):
        log.debug("######### VALIDATION REGS ON EXIT ###############")
        state.solver.simplify()
        zeroed_regs = ["r8", "r9", "r10", "r11"]
        error_regs = []

        Project.verify_exit_correctness(state, entry_state)

        for reg_name in zeroed_regs:
           if state.solver.satisfiable(extra_constraints=[state.registers.load(reg_name) != 0x0]):
               log.debug(
                   "######### EXITING ZEROED_REG ERROR %s %s ###############",
                   reg_name, state.registers.load(reg_name))
               error_regs.append(reg_name)

        jump_trace_set = set([trace_elem.symbol for trace_elem in state.enclave.jump_trace if trace_elem is not None and trace_elem.symbol is not None])

        if "usercall" not in jump_trace_set and state.solver.satisfiable(extra_constraints=[state.registers.load("rdi") != 0x0]): #  and state.solver.satisfiable(extra_constraints=[state.registers.load("rdi") != entry_state.registers.load("rdi")]):
           log.debug(
               "######### EXITING ZEROED_REG ERROR %s %s ###############",
               "rdi", state.registers.load("rdi"))
           error_regs.append("rdi")

        # In the case of a usercall we want to verify that everything has been correctly set on the gs segment!
        if jump_trace_set is not None and "usercalll" in jump_trace_set:
           usercall_saved_values_dict: Dict[str, int] = {
               "rbx": 0x70,
               "rbp": 0x78,
               "r12": 0x80,
               "r13": 0x88,
               "r14": 0x90,
               "r15": 0x98,
               "rip": 0xa8,
           }
           for reg, loc in usercall_saved_values_dict.items():
               if state.solver.satisfiable(extra_constraints=[entry_state.registers.load(reg) ==
                                       state.mem[state.registers.load("gs") + loc].uint64_t.resolved]):
                   log.error("Usercall register not correctly stored: {}".format(reg))


        if state.solver.satisfiable(extra_constraints=[state.regs.ac != 0x0]):
            log.debug("######### ENTERING AC ERROR %s ###############",
                      state.regs.ac)
            error_regs.append("ac")
        # DF SET is 0xffffffffffffffff in angr
        # whereas DF CLEAR = 0x1
        if state.solver.satisfiable(extra_constraints=[state.regs.dflag != 0x1]):
            log.debug("######### ENTERING DF ERROR %s ###############", state.regs.dflag)
            error_regs.append("df")

        if error_regs:
            return (ViolationType.ExitSanitisation,
                    ViolationType.ExitSanitisation.to_msg(), error_regs)

