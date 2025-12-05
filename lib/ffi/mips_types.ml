(* Capstone FFI - MIPS architecture-specific types *)

open Ctypes

(* mips_op_mem - Memory operand
   Layout from mips.h:
   - offset 0: base (mips_reg, 4 bytes)
   - offset 4: padding (4 bytes for alignment)
   - offset 8: disp (int64_t)
   Total size: 16 bytes
*)
type mips_op_mem
let mips_op_mem : mips_op_mem structure typ = structure "mips_op_mem"
let mips_mem_base = field mips_op_mem "base" uint32_t   (* mips_reg *)
let _mips_mem_pad = field mips_op_mem "_pad" uint32_t   (* padding *)
let mips_mem_disp = field mips_op_mem "disp" int64_t
let () = seal mips_op_mem

(* cs_mips_op - Single operand
   Layout:
   - offset 0: type (mips_op_type, 4 bytes)
   - offset 4: padding (4 bytes for alignment)
   - offset 8: union (reg/imm/mem - 16 bytes for largest member)
   Total size: 24 bytes

   Note: The union contains:
   - reg: mips_reg (4 bytes)
   - imm: int64_t (8 bytes)
   - mem: mips_op_mem (16 bytes)
*)
type cs_mips_op
let cs_mips_op : cs_mips_op structure typ = structure "cs_mips_op"
let mips_op_type = field cs_mips_op "type" uint32_t      (* mips_op_type *)
let _mips_op_pad = field cs_mips_op "_pad" uint32_t      (* padding *)
(* Union at offset 8 - reserve 16 bytes *)
let mips_op_union = field cs_mips_op "union" (array 2 int64_t)  (* 16 bytes *)
let () = seal cs_mips_op

(* Accessor functions for union members *)
let get_mips_op_reg op =
  let union_arr = getf op mips_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_mips_op_imm op =
  let union_arr = getf op mips_op_union in
  CArray.get union_arr 0

let get_mips_op_mem op =
  let union_arr = getf op mips_op_union in
  let w0 = CArray.get union_arr 0 in
  let w1 = CArray.get union_arr 1 in
  (* mem struct: base(4), pad(4), disp(8) = 16 bytes *)
  let base = Int64.to_int (Int64.logand w0 0xFFFFFFFFL) in
  let disp = w1 in
  (base, disp)

(* cs_mips - MIPS instruction detail
   Layout from mips.h:
   - offset 0: op_count (uint8_t)
   - offset 1-7: padding (7 bytes to align operands)
   - offset 8: operands[10] (10 * 24 = 240 bytes)
   Total size: 248 bytes
*)
type cs_mips
let cs_mips : cs_mips structure typ = structure "cs_mips"
let mips_op_count = field cs_mips "op_count" uint8_t
let _mips_pad = field cs_mips "_pad" (array 7 uint8_t)  (* padding to align operands *)
let mips_operands = field cs_mips "operands" (array 10 cs_mips_op)
let () = seal cs_mips

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
end
