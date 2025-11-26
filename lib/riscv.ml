(* Capstone OCaml Bindings - RISC-V architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.Riscv_types

(* Memory operand *)
type mem = {
  base : int;      (* riscv_reg *)
  disp : int64;
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int     (* riscv_reg *)
  | Imm of int64
  | Mem of mem

(* Single operand *)
type operand = {
  value : op_value;
}

(* Instruction detail *)
type detail = {
  need_effective_addr : bool;
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_riscv_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.riscv_op_type) in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_riscv_op_reg op)
    | 2 -> Imm (Types.get_riscv_op_imm op)
    | 3 ->
      let (base, disp) = Types.get_riscv_op_mem op in
      Mem { base; disp }
    | _ -> Invalid
  in

  { value }

(* Convert cs_riscv to OCaml detail *)
let detail_of_cs_riscv riscv =
  let op_count = Unsigned.UInt8.to_int (getf riscv Types.riscv_op_count) in
  let ops_array = getf riscv Types.riscv_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_riscv_op (CArray.get ops_array i)
  ) in

  {
    need_effective_addr = getf riscv Types.riscv_need_effective_addr;
    operands;
  }

(* Extract common detail fields from cs_detail *)
let common_detail_of_cs_detail detail_ptr =
  let detail = !@ detail_ptr in
  let module AarchTypes = Ffi.Aarch64_types in
  let regs_read_count = Unsigned.UInt8.to_int (getf detail AarchTypes.detail_regs_read_count) in
  let regs_write_count = Unsigned.UInt8.to_int (getf detail AarchTypes.detail_regs_write_count) in
  let groups_count = Unsigned.UInt8.to_int (getf detail AarchTypes.detail_groups_count) in

  let regs_read_arr = getf detail AarchTypes.detail_regs_read in
  let regs_write_arr = getf detail AarchTypes.detail_regs_write in
  let groups_arr = getf detail AarchTypes.detail_groups in

  {
    regs_read = Array.init regs_read_count (fun i ->
      Unsigned.UInt16.to_int (CArray.get regs_read_arr i));
    regs_write = Array.init regs_write_count (fun i ->
      Unsigned.UInt16.to_int (CArray.get regs_write_arr i));
    groups = Array.init groups_count (fun i ->
      Unsigned.UInt8.to_int (CArray.get groups_arr i));
  }

(* Extract RISC-V specific detail from cs_detail
   The riscv union is at offset 96 *)
let detail_of_cs_detail detail_ptr =
  let detail_base = to_voidp detail_ptr in
  let byte_ptr = from_voidp uint8_t detail_base in
  let riscv_ptr = from_voidp Types.cs_riscv (to_voidp (byte_ptr +@ 96)) in
  let riscv = !@ riscv_ptr in
  detail_of_cs_riscv riscv
