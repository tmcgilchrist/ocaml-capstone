(* Capstone OCaml Bindings - SystemZ (s390x) architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.Sysz_types

(* Memory operand *)
type mem = {
  base : int;       (* sysz_reg *)
  index : int;      (* sysz_reg *)
  length : int64;   (* BDLAddr operand *)
  disp : int64;
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int      (* sysz_reg *)
  | Imm of int64
  | Mem of mem
  | Acreg of int    (* access register *)

(* Single operand *)
type operand = {
  value : op_value;
}

(* Instruction detail *)
type detail = {
  cc : int;              (* sysz_cc - condition code *)
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_sysz_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.sysz_op_type) in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_sysz_op_reg op)
    | 2 -> Imm (Types.get_sysz_op_imm op)
    | 3 ->
      let (base, index, length, disp) = Types.get_sysz_op_mem op in
      Mem { base; index; length = Unsigned.UInt64.to_int64 length; disp }
    | 64 -> Acreg (Types.get_sysz_op_reg op)
    | _ -> Invalid
  in

  { value }

(* Convert cs_sysz to OCaml detail *)
let detail_of_cs_sysz sysz =
  let op_count = Unsigned.UInt8.to_int (getf sysz Types.sysz_op_count) in
  let ops_array = getf sysz Types.sysz_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_sysz_op (CArray.get ops_array i)
  ) in

  {
    cc = Unsigned.UInt32.to_int (getf sysz Types.sysz_cc);
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

(* Extract SystemZ specific detail from cs_detail
   The sysz union is at offset 96 *)
let detail_of_cs_detail detail_ptr =
  let detail_base = to_voidp detail_ptr in
  let byte_ptr = from_voidp uint8_t detail_base in
  let sysz_ptr = from_voidp Types.cs_sysz (to_voidp (byte_ptr +@ 96)) in
  let sysz = !@ sysz_ptr in
  detail_of_cs_sysz sysz
