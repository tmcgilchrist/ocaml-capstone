(* Capstone FFI - RISC-V architecture-specific types *)

open Ctypes

(* riscv_op_mem - Memory operand
   Layout from gcc offsetof:
   - offset 0: base (uint32_t, riscv_reg)
   - offset 4: padding (4 bytes)
   - offset 8: disp (int64_t)
   Total size: 16 bytes
*)
type riscv_op_mem
let riscv_op_mem : riscv_op_mem structure typ = structure "riscv_op_mem"
let riscv_mem_base = field riscv_op_mem "base" uint32_t  (* riscv_reg *)
let _riscv_mem_pad = field riscv_op_mem "_pad" uint32_t  (* padding *)
let riscv_mem_disp = field riscv_op_mem "disp" int64_t
let () = seal riscv_op_mem

(* cs_riscv_op - Single operand
   Layout from gcc offsetof:
   - offset 0: type (riscv_op_type, 4 bytes)
   - offset 4: padding (4 bytes)
   - offset 8: union (reg/imm/mem - 16 bytes)
   Total size: 24 bytes
*)
type cs_riscv_op
let cs_riscv_op : cs_riscv_op structure typ = structure "cs_riscv_op"
let riscv_op_type = field cs_riscv_op "type" uint32_t      (* riscv_op_type *)
let _riscv_op_pad = field cs_riscv_op "_pad" uint32_t      (* padding *)
(* Union at offset 8 - reserve 16 bytes *)
let riscv_op_union = field cs_riscv_op "union" (array 2 int64_t)  (* 16 bytes *)
let () = seal cs_riscv_op

(* Accessor functions for union members *)
let get_riscv_op_reg op =
  let union_arr = getf op riscv_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_riscv_op_imm op =
  let union_arr = getf op riscv_op_union in
  CArray.get union_arr 0

let get_riscv_op_mem op =
  let union_arr = getf op riscv_op_union in
  let w0 = CArray.get union_arr 0 in
  let w1 = CArray.get union_arr 1 in
  (* mem struct: base(4), pad(4), disp(8) = 16 bytes *)
  let base = Int64.to_int (Int64.logand w0 0xFFFFFFFFL) in
  let disp = w1 in
  (base, disp)

(* cs_riscv - RISC-V instruction detail
   Layout from gcc offsetof:
   - offset 0: need_effective_addr (bool, 1 byte)
   - offset 1: op_count (uint8_t)
   - offset 2-7: padding (6 bytes)
   - offset 8: operands[8] (8 * 24 = 192 bytes)
   Total size: 200 bytes
*)
type cs_riscv
let cs_riscv : cs_riscv structure typ = structure "cs_riscv"
let riscv_need_effective_addr = field cs_riscv "need_effective_addr" bool
let riscv_op_count = field cs_riscv "op_count" uint8_t
let _riscv_pad = field cs_riscv "_pad" (array 6 uint8_t)   (* padding to offset 8 *)
let riscv_operands = field cs_riscv "operands" (array 8 cs_riscv_op)
let () = seal cs_riscv

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
end
