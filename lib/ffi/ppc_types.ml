(* Capstone FFI - Power architecture-specific types *)

open Ctypes

(* ppc_op_mem - Memory operand
   Layout from gcc offsetof:
   - offset 0: base (uint32_t, ppc_reg)
   - offset 4: disp (int32_t)
   Total size: 8 bytes
*)
type ppc_op_mem
let ppc_op_mem : ppc_op_mem structure typ = structure "ppc_op_mem"
let ppc_mem_base = field ppc_op_mem "base" uint32_t  (* ppc_reg *)
let ppc_mem_disp = field ppc_op_mem "disp" int32_t
let () = seal ppc_op_mem

(* ppc_op_crx - Condition register operand
   Layout from gcc offsetof:
   - offset 0: scale (uint32_t)
   - offset 4: reg (uint32_t, ppc_reg)
   - offset 8: cond (uint32_t, ppc_bc)
   Total size: 12 bytes
*)
type ppc_op_crx
let ppc_op_crx : ppc_op_crx structure typ = structure "ppc_op_crx"
let ppc_crx_scale = field ppc_op_crx "scale" uint32_t
let ppc_crx_reg = field ppc_op_crx "reg" uint32_t    (* ppc_reg *)
let ppc_crx_cond = field ppc_op_crx "cond" uint32_t  (* ppc_bc *)
let () = seal ppc_op_crx

(* cs_ppc_op - Single operand
   Layout from gcc offsetof:
   - offset 0: type (ppc_op_type, 4 bytes)
   - offset 4: padding (4 bytes)
   - offset 8: union (reg/imm/mem/crx - 16 bytes max for alignment)
   Total size: 24 bytes
*)
type cs_ppc_op
let cs_ppc_op : cs_ppc_op structure typ = structure "cs_ppc_op"
let ppc_op_type = field cs_ppc_op "type" uint32_t      (* ppc_op_type *)
let _ppc_op_pad = field cs_ppc_op "_pad" uint32_t      (* padding *)
(* Union at offset 8 - reserve 16 bytes *)
let ppc_op_union = field cs_ppc_op "union" (array 2 int64_t)  (* 16 bytes *)
let () = seal cs_ppc_op

(* Accessor functions for union members *)
let get_ppc_op_reg op =
  let union_arr = getf op ppc_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_ppc_op_imm op =
  let union_arr = getf op ppc_op_union in
  CArray.get union_arr 0

let get_ppc_op_mem op =
  let union_arr = getf op ppc_op_union in
  let w0 = CArray.get union_arr 0 in
  (* mem struct: base(4), disp(4) = 8 bytes in first word *)
  let base = Int64.to_int (Int64.logand w0 0xFFFFFFFFL) in
  let disp = Int64.to_int32 (Int64.shift_right w0 32) in
  (base, disp)

let get_ppc_op_crx op =
  let union_arr = getf op ppc_op_union in
  let w0 = CArray.get union_arr 0 in
  let w1 = CArray.get union_arr 1 in
  (* crx struct: scale(4), reg(4), cond(4) = 12 bytes *)
  let scale = Int64.to_int (Int64.logand w0 0xFFFFFFFFL) in
  let reg = Int64.to_int (Int64.shift_right_logical w0 32 |> Int64.logand 0xFFFFFFFFL) in
  let cond = Int64.to_int (Int64.logand w1 0xFFFFFFFFL) in
  (scale, reg, cond)

(* cs_ppc - Power instruction detail
   Layout from gcc offsetof:
   - offset 0: bc (ppc_bc, 4 bytes)
   - offset 4: bh (ppc_bh, 4 bytes)
   - offset 8: update_cr0 (bool, 1 byte)
   - offset 9: op_count (uint8_t)
   - offset 10-15: padding (6 bytes)
   - offset 16: operands[8] (8 * 24 = 192 bytes)
   Total size: 208 bytes
*)
type cs_ppc
let cs_ppc : cs_ppc structure typ = structure "cs_ppc"
let ppc_bc = field cs_ppc "bc" uint32_t        (* ppc_bc *)
let ppc_bh = field cs_ppc "bh" uint32_t        (* ppc_bh *)
let ppc_update_cr0 = field cs_ppc "update_cr0" bool
let ppc_op_count = field cs_ppc "op_count" uint8_t
let _ppc_pad = field cs_ppc "_pad" (array 6 uint8_t)   (* padding to offset 16 *)
let ppc_operands = field cs_ppc "operands" (array 8 cs_ppc_op)
let () = seal cs_ppc

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
  let crx = 64
end
