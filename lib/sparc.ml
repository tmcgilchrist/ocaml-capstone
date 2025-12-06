(* Capstone OCaml Bindings - SPARC architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.Sparc_types

(* Memory operand *)
type mem = {
  base : int;      (* sparc_reg *)
  index : int;     (* sparc_reg *)
  disp : int32;
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int     (* sparc_reg *)
  | Imm of int64
  | Mem of mem

(* Single operand *)
type operand = {
  value : op_value;
}

(* Instruction detail *)
type detail = {
  cc : int;        (* sparc_cc - condition code *)
  hint : int;      (* sparc_hint - branch hint *)
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_sparc_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.sparc_op_type) in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_sparc_op_reg op)
    | 2 -> Imm (Types.get_sparc_op_imm op)
    | 3 ->
      let (base, index, disp) = Types.get_sparc_op_mem op in
      Mem { base; index; disp }
    | _ -> Invalid
  in

  { value }

(* Convert cs_sparc to OCaml detail *)
let detail_of_cs_sparc sparc =
  let op_count = Unsigned.UInt8.to_int (getf sparc Types.sparc_op_count) in
  let ops_array = getf sparc Types.sparc_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_sparc_op (CArray.get ops_array i)
  ) in

  {
    cc = Unsigned.UInt32.to_int (getf sparc Types.sparc_cc);
    hint = Unsigned.UInt32.to_int (getf sparc Types.sparc_hint);
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

(* Extract SPARC specific detail from cs_detail
   The sparc union is at offset 96 *)
let detail_of_cs_detail detail_ptr =
  let detail_base = to_voidp detail_ptr in
  let byte_ptr = from_voidp uint8_t detail_base in
  let sparc_ptr = from_voidp Types.cs_sparc (to_voidp (byte_ptr +@ 96)) in
  let sparc = !@ sparc_ptr in
  detail_of_cs_sparc sparc

(* Empty detail for when no detail is available *)
let empty_detail = {
  cc = 0;
  hint = 0;
  operands = [||];
}
