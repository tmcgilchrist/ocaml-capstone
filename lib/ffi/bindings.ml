(* Capstone FFI - Foreign function bindings using ctypes.foreign *)

open Ctypes
open Foreign

(* Force linking with libcapstone on Linux.
   This stub calls cs_version which forces the linker to include
   libcapstone even with --as-needed. Without this, dlsym(RTLD_DEFAULT, ...)
   fails because the library symbols aren't loaded. *)
external force_link : unit -> unit = "capstone_force_link"
let () = force_link ()

(* Core API functions *)

let cs_version =
  foreign "cs_version"
    (ptr_opt int @-> ptr_opt int @-> returning uint)

let cs_support =
  foreign "cs_support"
    (int @-> returning bool)

let cs_open =
  foreign "cs_open"
    (int @-> int @-> ptr size_t @-> returning int)

let cs_close =
  foreign "cs_close"
    (ptr size_t @-> returning int)

let cs_option =
  foreign "cs_option"
    (size_t @-> int @-> size_t @-> returning int)

let cs_errno =
  foreign "cs_errno"
    (size_t @-> returning int)

let cs_strerror =
  foreign "cs_strerror"
    (int @-> returning string)

let cs_disasm =
  foreign "cs_disasm"
    (size_t @->                         (* handle *)
     ptr uint8_t @-> size_t @->         (* code, code_size *)
     uint64_t @->                       (* address *)
     size_t @->                         (* count *)
     ptr (ptr Types.cs_insn) @->        (* insn pointer *)
     returning size_t)

let cs_free =
  foreign "cs_free"
    (ptr Types.cs_insn @-> size_t @-> returning void)

let cs_malloc =
  foreign "cs_malloc"
    (size_t @-> returning (ptr Types.cs_insn))

let cs_disasm_iter =
  foreign "cs_disasm_iter"
    (size_t @->                         (* handle *)
     ptr (ptr uint8_t) @->              (* code pointer *)
     ptr size_t @->                     (* size pointer *)
     ptr uint64_t @->                   (* address pointer *)
     ptr Types.cs_insn @->              (* insn *)
     returning bool)

(* Name lookup functions *)

let cs_reg_name =
  foreign "cs_reg_name"
    (size_t @-> uint @-> returning string_opt)

let cs_insn_name =
  foreign "cs_insn_name"
    (size_t @-> uint @-> returning string_opt)

let cs_group_name =
  foreign "cs_group_name"
    (size_t @-> uint @-> returning string_opt)

(* Instruction analysis functions *)

let cs_insn_group =
  foreign "cs_insn_group"
    (size_t @-> ptr Types.cs_insn @-> uint @-> returning bool)

let cs_reg_read =
  foreign "cs_reg_read"
    (size_t @-> ptr Types.cs_insn @-> uint @-> returning bool)

let cs_reg_write =
  foreign "cs_reg_write"
    (size_t @-> ptr Types.cs_insn @-> uint @-> returning bool)

let cs_op_count =
  foreign "cs_op_count"
    (size_t @-> ptr Types.cs_insn @-> uint @-> returning int)

let cs_op_index =
  foreign "cs_op_index"
    (size_t @-> ptr Types.cs_insn @-> uint @-> uint @-> returning int)
