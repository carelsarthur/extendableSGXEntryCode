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

import os
from elftools.elf.elffile import ELFFile
from typing import List


class EnclaveMemoryLayout:
    # Set some constants as per SDK & Fortanix (elf2sgx.rs) definitions
    PAGE_SIZE = 0x1000
    SE_PAGE_SHIFT = 12

    # These defaults come from https://github.com/fortanix/rust-sgx/blob/64100155aa8e0e9379fd66c6128e6f1605442e75/intel-sgx/fortanix-sgx-tools/src/bin/ftxsgx-runner-cargo.rs
    HEAP_SIZE = 0x2000000  # Source: https://github.com/fortanix/rust-sgx/blob/64100155aa8e0e9379fd66c6128e6f1605442e75/intel-sgx/fortanix-sgx-tools/src/bin/ftxsgx-runner-cargo.rs#L14
    SSA_FRAME_SIZE = 1
    STACK_SIZE = 0x20000  # Source: https://github.com/fortanix/rust-sgx/blob/64100155aa8e0e9379fd66c6128e6f1605442e75/intel-sgx/fortanix-sgx-tools/src/bin/ftxsgx-runner-cargo.rs#L16
    DEBUG: bool = True
    NUM_THREADS = 1  # We consider single-threading at this moment for ease of analysis!
    # NUM_THREADS = os.cpu_count()  # Amount of cpus available

    # Added myself (based on https://github.com/fortanix/rust-sgx/blob/master/intel-sgx/fortanix-sgx-tools/src/bin/ftxsgx-elf2sgxs.rs)
    THREAD_GUARD_SIZE: int = 0x10000
    TLS_SIZE: int = 0x1000 * 2  # NOTE: change to original elf2sgx file!
    SSA_NUM: int = 1  # overwritten, see above
    FSLIMIT = 0xfff
    GSLIMIT = 0xfff

    TEMPORARY_STACK_BEGIN_OFFSET = 0x1000
    TEMPORARY_STACK_END_OFFSET = 0x2000

    # We are only considering enclaves that do not have a dynamically-sized heap
    def __init__(self, project):
        self.base_addr = self.get_base_addr(project)

        # ------------------------------------------------------------------------------
        self.heap_start = self.round_to_page(self.get_last_section(project) - self.base_addr) \
                          + self.base_addr
        self.heap_end = self.heap_start + self.round_size_for_page(self.HEAP_SIZE)
        assert self.heap_end == self.round_size_for_page(self.heap_start + self.HEAP_SIZE)

        # ------------------------------------------------------------------------------
        self.thread_start = self.heap_end
        self.thread_size = self.THREAD_GUARD_SIZE + self.STACK_SIZE + self.TLS_SIZE \
                           + (1 + self.SSA_NUM * self.SSA_FRAME_SIZE) * 0x1000

        self.memory_size = self.thread_start + (self.NUM_THREADS * self.thread_size)
        self.enclave_size = self.size_fit_natural(self.memory_size)

        # TODO: do we have to do this for every thread? (How?)
        self.stack_start = self.thread_start + self.round_size_for_page(self.THREAD_GUARD_SIZE)
        self.stack_tos = self.stack_start + self.size_fit_natural(self.STACK_SIZE)
        self.tls_addr = self.stack_tos
        self.tcs_addr = self.tls_addr + self.TLS_SIZE
        self.ossa = self.tcs_addr + 0x1000

        self.gs_addr = self.stack_tos
        self.fs_addr = self.tls_addr


        # NOTE: here as well: only one "thread" is assumed at the moment!
        project.loader.memory.add_backer(
            self.heap_start,
            bytearray(self.thread_start + self.round_size_for_page(self.thread_size) -
                      self.heap_start))

        # Atm:ogsbasgx = stack_tos = tls_addr

    def page_count_for_size(self, size) -> int:
        return size >> self.SE_PAGE_SHIFT

    def size_from_page_count(self, count) -> int:
        return count << self.SE_PAGE_SHIFT

    def round_size_for_page(self, size) -> int:
        return self.size_from_page_count(self.page_count_for_size(size))

    def round_to_page(self, size) -> int:
        return ((size + (self.PAGE_SIZE - 1))
                & ~(self.PAGE_SIZE - 1))

    def get_last_section(self, project) -> int:
        # Used to find the "heap start"
        max_section_addr = self.get_base_addr(project)
        for section in project.loader.main_object.sections:
            if section.max_addr > max_section_addr:
                max_section_addr = section.max_addr
        return max_section_addr

    def get_base_addr(self, project) -> int:
        base_addr = project.loader.main_object.mapped_base
        assert base_addr is not None
        return base_addr

    # Source: https://www.geeksforgeeks.org/smallest-power-of-2-greater-than-or-equal-to-n/
    # Given a size in bytes, this function returns the size in bytes of the naturally-aligned structure required to cover the size
    #   = smallest power of two that is >= the input size
    def size_fit_natural(self, n) -> int:
        count = 0
        if (n and not (n & (n - 1))):
            return n
        while (n != 0):
            n >>= 1
            count += 1
        return 1 << count


    def set_global_data(self, project, state) -> None:
        heap_base_addr = project.loader.find_symbol("HEAP_BASE").rebased_addr

        # Fill in some "maybe??? useful information!"
        state.mem[heap_base_addr].uint64_t = self.heap_start
        state.mem[heap_base_addr + 8].uint64_t = self.HEAP_SIZE
        # Rela & Relacount !?
        state.mem[heap_base_addr  + 32].uint64_t = self.enclave_size
        state.mem[heap_base_addr].uint64_t = 1 if self.DEBUG else 0


    def set_thread_data(self, state) -> None:
        # gs and fs
        # TODO: is this correct ?!
        state.regs.gs = self.stack_tos
        state.regs.fs = self.stack_tos
        # self addr TODO
        # state.mem[self.td_start].uint64_t = self.td_start

        state.mem[self.stack_tos].uint64_t = self.stack_tos
        print(self.stack_tos)


    def get_layout(self, angr_project) -> None:
        # TODO: fix this function!
        # OK: so main lesson learned:
        # The layout of the real enclave & the thing loaded via angr is the same, they just differ in the "base address"
        # Angr uses 0x400000 and "the real thing" uses another base address, but that does not really matter because the offsets within the enclave are exactly the same!

        obj = angr_project.loader.main_object
        sections_map = obj.sections_map

        gs_addr = angr_project.loader.find_symbol(".gs_segment").rebased_addr

        # ------ Read-only segment -----------
        print("--------------------------------------------------------------------")
        print("read only data segment: ", hex(sections_map[".rodata"].min_addr), " --> ",
              hex(sections_map[".rodata"].max_addr))
        print("xsave_ro_clear", angr_project.loader.find_symbol(".Lxsave_ro_clear"))  # TODO: why not working?
        print("heap base: ", angr_project.loader.find_symbol("HEAP_BASE"))
        # ------ .data segment ----------------
        print("--------------------------------------------------------------------")
        print("data segment: ", hex(sections_map[".data"].min_addr), " --> ", hex(sections_map[".data"].max_addr))
        # print("entry_xsave_test: ", hex(angr_project.loader.find_symbol("entry_xsave").rebased_addr))
        # print("entry_xsave: ", hex(gs_addr + angr_project.loader.find_symbol("entry_xsave").rebased_addr))
        #print("usercall_xsave: ", hex(angr_project.loader.find_symbol(".usercall_xsave").rebased_addr))
        #print("Temporary stack: ", hex(angr_project.loader.find_symbol(".Rust_stack").rebased_addr), " --> ",
        #      hex(angr_project.loader.find_symbol(".Rust_stack_top").rebased_addr))
        # ------- .gs_segment ------------------
        print("--------------------------------------------------------------------")
        print("gs_segment: ", hex(gs_addr))
        print("tcsls_tos", angr_project.loader.find_symbol("tcsls_tos"))

    def get_loaded_segments(self) -> List[str]:
        # TODO: change this binary here!
        loadable_elf_segments = []
        with open("/tmp/app/target/x86_64-fortanix-unknown-sgx/debug/app", "rb") as elffile:
            for section in ELFFile(elffile).iter_sections():
                if section.header.sh_addr:
                    loadable_elf_segments.append(section.name)
        return loadable_elf_segments
