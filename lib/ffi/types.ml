(* Capstone FFI - Ctypes structure definitions *)

open Ctypes

(* Handle type - size_t in C *)
let csh = size_t

(* Architecture enum values *)
module Arch = struct
  let arm = 0
  let aarch64 = 1
  let mips = 2
  let x86 = 3
  let ppc = 4
  let sparc = 5
  let sysz = 6
  let xcore = 7
  let m68k = 8
  let tms320c64x = 9
  let m680x = 10
  let evm = 11
end

(* Mode enum values *)
module Mode = struct
  let little_endian = 0
  let arm = 0
  let mode_16 = 1 lsl 1
  let mode_32 = 1 lsl 2
  let mode_64 = 1 lsl 3
  let thumb = 1 lsl 4
  let mclass = 1 lsl 5
  let v8 = 1 lsl 6
  let big_endian = 1 lsl 31
end

(* Option types *)
module OptType = struct
  let invalid = 0
  let syntax = 1
  let detail = 2
  let mode = 3
  let mem = 4
  let skipdata = 5
  let skipdata_setup = 6
  let mnemonic = 7
  let unsigned = 8
end

(* Option values - from capstone.h *)
module OptValue = struct
  let off = 0
  let on = 3   (* CS_OPT_ON = 3, not 1! *)
  let syntax_default = 1 lsl 1
  let syntax_intel = 1 lsl 2
  let syntax_att = 1 lsl 3
  let syntax_noregname = 1 lsl 4
  let syntax_masm = 1 lsl 5
end

(* Error codes *)
module Err = struct
  let ok = 0
  let mem = 1
  let arch = 2
  let handle = 3
  let csh = 4
  let mode = 5
  let option = 6
  let detail = 7
  let memsetup = 8
  let version = 9
  let diet = 10
  let skipdata = 11
  let x86_att = 12
  let x86_intel = 13
  let x86_masm = 14
end

(* Maximum sizes from capstone.h *)
let max_impl_w_regs = 47
let max_impl_r_regs = 20
let max_num_groups = 8
let cs_mnemonic_size = 32

(* cs_insn structure - matches Capstone 5.0.x *)
(* Note: cs_detail is defined in Aarch64_types *)
type cs_insn
let cs_insn : cs_insn structure typ = structure "cs_insn"
let insn_id = field cs_insn "id" uint32_t
let insn_address = field cs_insn "address" uint64_t
let insn_size = field cs_insn "size" uint16_t
let insn_bytes = field cs_insn "bytes" (array 24 uint8_t)
let insn_mnemonic = field cs_insn "mnemonic" (array 32 char)
let insn_op_str = field cs_insn "op_str" (array 160 char)
let insn_detail = field cs_insn "detail" (ptr_opt Aarch64_types.cs_detail)
let () = seal cs_insn

(* Helper to convert char array to string *)
let char_array_to_string arr =
  let len = CArray.length arr in
  let buf = Buffer.create len in
  try
    for i = 0 to len - 1 do
      let c = CArray.get arr i in
      if c = '\x00' then raise Exit
      else Buffer.add_char buf c
    done;
    Buffer.contents buf
  with Exit -> Buffer.contents buf

(* Helper to convert uint8 array to bytes *)
let uint8_array_to_bytes arr len =
  let b = Bytes.create len in
  for i = 0 to len - 1 do
    Bytes.set b i (Char.chr (Unsigned.UInt8.to_int (CArray.get arr i)))
  done;
  b
