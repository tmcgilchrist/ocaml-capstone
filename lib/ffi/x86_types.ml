(* Capstone FFI - x86 architecture-specific types *)

open Ctypes

(* x86_op_mem - Memory operand
   Layout from gcc offsetof:
   - offset 0: segment (uint32_t, x86_reg)
   - offset 4: base (uint32_t, x86_reg)
   - offset 8: index (uint32_t, x86_reg)
   - offset 12: scale (int)
   - offset 16: disp (int64_t)
   Total size: 24 bytes
*)
type x86_op_mem
let x86_op_mem : x86_op_mem structure typ = structure "x86_op_mem"
let x86_mem_segment = field x86_op_mem "segment" uint32_t  (* x86_reg *)
let x86_mem_base = field x86_op_mem "base" uint32_t        (* x86_reg *)
let x86_mem_index = field x86_op_mem "index" uint32_t      (* x86_reg *)
let x86_mem_scale = field x86_op_mem "scale" int
let x86_mem_disp = field x86_op_mem "disp" int64_t
let () = seal x86_op_mem

(* cs_x86_op - Single operand
   Layout from gcc offsetof:
   - offset 0: type (x86_op_type, 4 bytes)
   - offset 4: padding (4 bytes)
   - offset 8: union (reg/imm/mem - 24 bytes for mem)
   - offset 32: size (uint8_t)
   - offset 33: access (uint8_t)
   - offset 34: padding (2 bytes)
   - offset 36: avx_bcast (x86_avx_bcast, 4 bytes)
   - offset 40: avx_zero_opmask (bool)
   - padding to 48 bytes
   Total size: 48 bytes
*)
type cs_x86_op
let cs_x86_op : cs_x86_op structure typ = structure "cs_x86_op"
let x86_op_type = field cs_x86_op "type" uint32_t          (* x86_op_type *)
let _x86_op_pad1 = field cs_x86_op "_pad1" uint32_t        (* padding *)
(* Union at offset 8 - reserve 24 bytes *)
let x86_op_union = field cs_x86_op "union" (array 3 int64_t)  (* 24 bytes *)
let x86_op_size = field cs_x86_op "size" uint8_t
let x86_op_access = field cs_x86_op "access" uint8_t
let _x86_op_pad2 = field cs_x86_op "_pad2" uint16_t        (* padding *)
let x86_op_avx_bcast = field cs_x86_op "avx_bcast" uint32_t (* x86_avx_bcast *)
let x86_op_avx_zero_opmask = field cs_x86_op "avx_zero_opmask" bool
let _x86_op_pad3 = field cs_x86_op "_pad3" (array 7 uint8_t) (* padding to 48 *)
let () = seal cs_x86_op

(* Accessor functions for union members *)
let get_x86_op_reg op =
  let union_arr = getf op x86_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_x86_op_imm op =
  let union_arr = getf op x86_op_union in
  CArray.get union_arr 0

let get_x86_op_mem op =
  let union_arr = getf op x86_op_union in
  let w0 = CArray.get union_arr 0 in
  let w1 = CArray.get union_arr 1 in
  let w2 = CArray.get union_arr 2 in
  (* mem struct: segment(4), base(4), index(4), scale(4), disp(8) = 24 bytes *)
  let segment = Int64.to_int (Int64.logand w0 0xFFFFFFFFL) in
  let base = Int64.to_int (Int64.logand (Int64.shift_right_logical w0 32) 0xFFFFFFFFL) in
  let index = Int64.to_int (Int64.logand w1 0xFFFFFFFFL) in
  let scale = Int64.to_int (Int64.logand (Int64.shift_right_logical w1 32) 0xFFFFFFFFL) in
  let disp = w2 in
  (segment, base, index, scale, disp)

(* cs_x86 - x86 instruction detail
   Layout from gcc offsetof:
   - offset 0: prefix[4] (4 bytes)
   - offset 4: opcode[4] (4 bytes)
   - offset 8: rex (uint8_t)
   - offset 9: addr_size (uint8_t)
   - offset 10: modrm (uint8_t)
   - offset 11: sib (uint8_t)
   - offset 12: padding (4 bytes)
   - offset 16: disp (int64_t)
   - offset 24: sib_index (x86_reg, uint32_t)
   - offset 28: sib_scale (int8_t)
   - offset 29: padding (3 bytes)
   - offset 32: sib_base (x86_reg, uint32_t)
   - offset 36: xop_cc (x86_xop_cc, uint32_t)
   - offset 40: sse_cc (x86_sse_cc, uint32_t)
   - offset 44: avx_cc (x86_avx_cc, uint32_t)
   - offset 48: avx_sae (bool)
   - offset 49: padding (3 bytes)
   - offset 52: avx_rm (x86_avx_rm, uint32_t)
   - offset 56: eflags/fpu_flags union (uint64_t)
   - offset 64: op_count (uint8_t)
   - offset 65: padding (7 bytes)
   - offset 72: operands[8] (8 * 48 = 384 bytes)
   Total size: 456 bytes (but reported as 464 with padding)
*)
type cs_x86
let cs_x86 : cs_x86 structure typ = structure "cs_x86"
let x86_prefix = field cs_x86 "prefix" (array 4 uint8_t)
let x86_opcode = field cs_x86 "opcode" (array 4 uint8_t)
let x86_rex = field cs_x86 "rex" uint8_t
let x86_addr_size = field cs_x86 "addr_size" uint8_t
let x86_modrm = field cs_x86 "modrm" uint8_t
let x86_sib = field cs_x86 "sib" uint8_t
let _x86_pad1 = field cs_x86 "_pad1" uint32_t              (* padding to offset 16 *)
let x86_disp = field cs_x86 "disp" int64_t
let x86_sib_index = field cs_x86 "sib_index" uint32_t      (* x86_reg *)
let x86_sib_scale = field cs_x86 "sib_scale" int8_t
let _x86_pad2 = field cs_x86 "_pad2" (array 3 uint8_t)     (* padding *)
let x86_sib_base = field cs_x86 "sib_base" uint32_t        (* x86_reg *)
let x86_xop_cc = field cs_x86 "xop_cc" uint32_t            (* x86_xop_cc *)
let x86_sse_cc = field cs_x86 "sse_cc" uint32_t            (* x86_sse_cc *)
let x86_avx_cc = field cs_x86 "avx_cc" uint32_t            (* x86_avx_cc *)
let x86_avx_sae = field cs_x86 "avx_sae" bool
let _x86_pad3 = field cs_x86 "_pad3" (array 3 uint8_t)     (* padding *)
let x86_avx_rm = field cs_x86 "avx_rm" uint32_t            (* x86_avx_rm *)
let x86_eflags = field cs_x86 "eflags" uint64_t            (* eflags/fpu_flags union *)
let x86_op_count = field cs_x86 "op_count" uint8_t
let _x86_pad4 = field cs_x86 "_pad4" (array 7 uint8_t)     (* padding to offset 72 *)
let x86_operands = field cs_x86 "operands" (array 8 cs_x86_op)
let () = seal cs_x86

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
end

(* Access type constants *)
module Access = struct
  let invalid = 0
  let read = 1
  let write = 2
  let read_write = 3
end
