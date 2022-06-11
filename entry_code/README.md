# Modified entry code
This folder contains the modified Fortanix EDP entry code.
The original entry code can be found [Here](https://github.com/rust-lang/rust/tree/42983a28ab3c70728da7a9b932b667c978dd898d/library/std/src/sys/sgx/abi). 

The process of using these modifications is a bit of a hassle, but it basically consists of the following steps:
- Clone the [rust project](https://github.com/rust-lang/rust).
- Add/replace the 3 files from this folder: *library/std/src/sys/sgx/abi*.

*entry.S*, *mod.rs* and *elf_and_info.S* 

- Install the Fortanix EDP required stuff: [https://edp.fortanix.com/docs/installation/guide/]
- Compile Rust

You can use the helper script provided along: *attempt.sh*

Note: there may be a step missing here. It's been a while for me as well. ;)
