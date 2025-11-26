(* Capstone FFI - SystemZ (s390x) architecture-specific types *)

open Ctypes

(* sysz_op_mem - Memory operand
   Layout from gcc offsetof:
   - offset 0: base (uint8_t, sysz_reg)
   - offset 1: index (uint8_t, sysz_reg)
   - offset 2-7: padding (6 bytes)
   - offset 8: length (uint64_t)
   - offset 16: disp (int64_t)
   Total size: 24 bytes
*)
type sysz_op_mem
let sysz_op_mem : sysz_op_mem structure typ = structure "sysz_op_mem"
let sysz_mem_base = field sysz_op_mem "base" uint8_t    (* sysz_reg *)
let sysz_mem_index = field sysz_op_mem "index" uint8_t  (* sysz_reg *)
let _sysz_mem_pad = field sysz_op_mem "_pad" (array 6 uint8_t)  (* padding *)
let sysz_mem_length = field sysz_op_mem "length" uint64_t
let sysz_mem_disp = field sysz_op_mem "disp" int64_t
let () = seal sysz_op_mem

(* cs_sysz_op - Single operand
   Layout from gcc offsetof:
   - offset 0: type (sysz_op_type, 4 bytes)
   - offset 4: padding (4 bytes)
   - offset 8: union (reg/imm/mem - 24 bytes)
   Total size: 32 bytes
*)
type cs_sysz_op
let cs_sysz_op : cs_sysz_op structure typ = structure "cs_sysz_op"
let sysz_op_type = field cs_sysz_op "type" uint32_t      (* sysz_op_type *)
let _sysz_op_pad = field cs_sysz_op "_pad" uint32_t      (* padding *)
(* Union at offset 8 - reserve 24 bytes (3 x int64_t) *)
let sysz_op_union = field cs_sysz_op "union" (array 3 int64_t)  (* 24 bytes *)
let () = seal cs_sysz_op

(* Accessor functions for union members *)
let get_sysz_op_reg op =
  let union_arr = getf op sysz_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_sysz_op_imm op =
  let union_arr = getf op sysz_op_union in
  CArray.get union_arr 0

let get_sysz_op_mem op =
  let union_arr = getf op sysz_op_union in
  let w0 = CArray.get union_arr 0 in
  let w1 = CArray.get union_arr 1 in
  let w2 = CArray.get union_arr 2 in
  (* mem struct: base(1), index(1), pad(6), length(8), disp(8) = 24 bytes *)
  let base = Int64.to_int (Int64.logand w0 0xFFL) in
  let index = Int64.to_int (Int64.logand (Int64.shift_right_logical w0 8) 0xFFL) in
  let length = Unsigned.UInt64.of_int64 w1 in
  let disp = w2 in
  (base, index, length, disp)

(* cs_sysz - SystemZ instruction detail
   Layout from gcc offsetof:
   - offset 0: cc (sysz_cc, 4 bytes)
   - offset 4: op_count (uint8_t)
   - offset 5-7: padding (3 bytes)
   - offset 8: operands[6] (6 * 32 = 192 bytes)
   Total size: 200 bytes
*)
type cs_sysz
let cs_sysz : cs_sysz structure typ = structure "cs_sysz"
let sysz_cc = field cs_sysz "cc" uint32_t        (* sysz_cc *)
let sysz_op_count = field cs_sysz "op_count" uint8_t
let _sysz_pad = field cs_sysz "_pad" (array 3 uint8_t)   (* padding to offset 8 *)
let sysz_operands = field cs_sysz "operands" (array 6 cs_sysz_op)
let () = seal cs_sysz

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
  let acreg = 64  (* access register *)
end
