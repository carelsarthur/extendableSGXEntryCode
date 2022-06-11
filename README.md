# extendableSGXEntryCode
This is the code for the master's thesis: "Design and Verification of extendable Intel SGX entry code" at KU Leuven.

Promotor: Prof. dr. Ir. Frank Piessens

Supervisors: dr. Raoul Strackx, dr. Ir. Neline van Ginkel, Ir. Kobe Vrancken

## Contributions
- We simplified the Fortanix EDP entry code. This was done by eliminating all conditional branching in the assembly code. By doing this, as much code as possible was translated to the higher-level Rust language.
- We improved the extensibility of the code. The use of the Rust programming language facilitizes code extension. 
- Using a benchmark, we show that the performance of the modified entry code is similar to the original.
- We show that the simplified ABI-layer still provides substantial security guarantees. This is shown by using the Angr binary analysis framework in combination with Rust’s strong security guarantees.
- We give an extensive overview of the current state of Rust verifiers.

# Structure of this repo
This repo has been divided into a few folders.
Each of these folder has its own use case.
More information is available within each folder in the form of a README.

## Angr verifier
This folder contains the files needed to prove certain safety principles about the entry code.
It uses angr, a binary analysis framework written in Python.
## Code Simplicity Prover
This file contains a script that automatically scans the entry code for certain "code simplicity metrics".
## Enclave Timing Tester
This file contains code that was used to create timing benchmarks.
## Entry Code
This file contains the actual entry code.

# License
The standard Rust license (i.e. both the MIT license and the Apache License (Version 2.0)) has been followed where possible.
However: the folder containing the angr code is licensed under the GNU Affero General Public License.
