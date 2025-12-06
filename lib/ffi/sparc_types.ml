(* Capstone FFI - SPARC architecture-specific types *)

open Ctypes

(* sparc_op_mem - Memory operand
   Layout from sparc.h:
   - offset 0: base (uint8_t, sparc_reg)
   - offset 1: index (uint8_t, sparc_reg)
   - offset 2-3: padding (2 bytes for alignment)
   - offset 4: disp (int32_t)
   Total size: 8 bytes
*)
type sparc_op_mem
let sparc_op_mem : sparc_op_mem structure typ = structure "sparc_op_mem"
let sparc_mem_base = field sparc_op_mem "base" uint8_t   (* sparc_reg *)
let sparc_mem_index = field sparc_op_mem "index" uint8_t (* sparc_reg *)
let _sparc_mem_pad = field sparc_op_mem "_pad" (array 2 uint8_t)  (* padding *)
let sparc_mem_disp = field sparc_op_mem "disp" int32_t
let () = seal sparc_op_mem

(* cs_sparc_op - Single operand
   Layout:
   - offset 0: type (sparc_op_type, 4 bytes)
   - offset 4: union (reg/imm/mem - 8 bytes for largest member imm which is int64_t)
   Total size: 16 bytes (with padding)

   Note: The union contains:
   - reg: sparc_reg (4 bytes, but we use 8 for alignment)
   - imm: int64_t (8 bytes)
   - mem: sparc_op_mem (8 bytes)
*)
type cs_sparc_op
let cs_sparc_op : cs_sparc_op structure typ = structure "cs_sparc_op"
let sparc_op_type = field cs_sparc_op "type" uint32_t      (* sparc_op_type *)
let _sparc_op_pad = field cs_sparc_op "_pad" uint32_t      (* padding *)
(* Union at offset 8 - reserve 8 bytes (size of int64_t) *)
let sparc_op_union = field cs_sparc_op "union" int64_t     (* 8 bytes for imm, covers all union members *)
let () = seal cs_sparc_op

(* Accessor functions for union members *)
let get_sparc_op_reg op =
  let union_val = getf op sparc_op_union in
  Int64.to_int (Int64.logand union_val 0xFFFFFFFFL)

let get_sparc_op_imm op =
  getf op sparc_op_union

let get_sparc_op_mem op =
  let union_val = getf op sparc_op_union in
  (* mem struct: base(1), index(1), pad(2), disp(4) = 8 bytes total *)
  let base = Int64.to_int (Int64.logand union_val 0xFFL) in
  let index = Int64.to_int (Int64.logand (Int64.shift_right_logical union_val 8) 0xFFL) in
  let disp = Int64.to_int32 (Int64.shift_right_logical union_val 32) in
  (base, index, disp)

(* cs_sparc - SPARC instruction detail
   Layout from sparc.h:
   - offset 0: cc (sparc_cc, 4 bytes)
   - offset 4: hint (sparc_hint, 4 bytes)
   - offset 8: op_count (uint8_t)
   - offset 9-15: padding (7 bytes to align operands)
   - offset 16: operands[4] (4 * 16 = 64 bytes)
   Total size: 80 bytes
*)
type cs_sparc
let cs_sparc : cs_sparc structure typ = structure "cs_sparc"
let sparc_cc = field cs_sparc "cc" uint32_t           (* sparc_cc *)
let sparc_hint = field cs_sparc "hint" uint32_t       (* sparc_hint *)
let sparc_op_count = field cs_sparc "op_count" uint8_t
let _sparc_pad = field cs_sparc "_pad" (array 7 uint8_t)  (* padding to align operands *)
let sparc_operands = field cs_sparc "operands" (array 4 cs_sparc_op)
let () = seal cs_sparc

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
end
