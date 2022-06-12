# Modified entry code
This folder contains the modified Fortanix EDP entry code.
The original entry code can be found [Here](https://github.com/rust-lang/rust/tree/42983a28ab3c70728da7a9b932b667c978dd898d/library/std/src/sys/sgx/abi). 

The process of using these modifications is a bit of a hassle, but it basically consists of the following steps:
- Clone the [rust project](https://github.com/rust-lang/rust).
- Add/replace the 3 files from this folder: *library/std/src/sys/sgx/abi*.

*entry.S*, *mod.rs* and *elf_and_info.S* 

- Install the Fortanix EDP required stuff: [https://edp.fortanix.com/docs/installation/guide/]

- Install a customized version of fortanix-sgx-tools
The required version can be found in the *rust-sgx* folder.
Approach to install it:
```
cargo install --path <path_to_fortanix-sgx-tools>
```

- Compile Rust
You can use the helper script provided along: *attempt.sh*
```
chmod a+x attempt.sh
./attempt.sh
```

- Another potentially useful command is
```
python3 ./x.py build library/std  # Issue this command in the root of the Rust repo 
```

**Note:** there might be a step missing here. It's been a while for me as well. ;)
