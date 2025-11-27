(lang dune 3.0)
(formatting (enabled_for dune))
(name capstone)
(generate_opam_files true)
(version 0.1.0)

(maintainers "Tim McGilchrist <timmcgil@gmail.com>")
(authors
 "Tim McGilchrist <timmcgil@gmail.com>"
 "Nguyen Anh Quynh <aquynh@gmail.com>"
 "Chenxu Wu (kabeor) <kabeor@qiling.io>"
 "Sam L. Thomas <m@exo.st>")
(license MIT)
(homepage "https://github.com/tmcgilchrist/capstone-ocaml")
(bug_reports "https://github.com/tmcgilchrist/capstone-ocaml/issues")
(source (github tmcgilchrist/capstone-ocaml))

(package
 (name capstone)
 (synopsis "OCaml bindings to the Capstone disassembly framework")
 (description
  "Modern ctypes-based OCaml bindings for the Capstone disassembler supporting x86 and AArch64 architectures.")
 (depends
  (ocaml (>= 4.14))
  (dune (>= 3.0))
  (ctypes (>= 0.20.0))
  (ctypes-foreign (>= 0.18.0))
  conf-capstone
  (alcotest :with-test)))

(package
 (name conf-capstone)
 (allow_empty)
 (synopsis "Virtual package relying on Capstone 5.x installation")
 (description
  "This package ensures the Capstone disassembly library (libcapstone) version 5.0 or later is installed on the system. Capstone 5.x is required for RISC-V, Power, and SystemZ architecture support."))

