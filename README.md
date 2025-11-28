# OCaml Capstone

OCaml friendly bindings to [Capstone](https://github.com/capstone-engine/capstone/) disassembly/disassembler framework packaged for use with opam.

Features:

 - ctypes-based FFI (no manual C stubs)
 - Type-safe architecture selection via GADTs
 - Targets Capstone 5 on Linux and macOS (potentially FreeBSD in future)
 - Supports x86 (16/32/64-bit), ARM (32/64-bit), s390x, and Power (potentially more in future)
 - Detailed instruction information (operands, registers, memory refs)
 - Pure OCaml code generation for enum handling

Dependencies

 - OCaml >= 4.14
 - ctypes, ctypes-foreign
 - libcapstone (system library, Capstone 5.x)

This project is a work in progress, I make no claims about backwards compatibility or suitability for any particular use-case. I'm personally using this as a building block for writing a debugger and tooling for DWARF information.

## Acknowlegements

Based off the source in [capstone ocaml bindings](https://github.com/capstone-engine/capstone/tree/next/bindings/ocaml) and [capstone-ocaml](https://github.com/xorpse/capstone-ocaml). I've tried to make this an idiomatic Opam package using ctypes / FFI to rather than C codegen.

Thank you for efforts.
