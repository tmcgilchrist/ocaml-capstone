(* Capstone OCaml Bindings - M680X architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.M680x_types

(* Indexed addressing operand *)
type idx = {
  base_reg : int;       (* m680x_reg *)
  offset_reg : int;     (* m680x_reg *)
  offset : int;         (* 5-/8-/16-bit offset *)
  offset_addr : int;    (* offset addr for PC-relative *)
  offset_bits : int;    (* offset width in bits *)
  inc_dec : int;        (* inc/dec value: -8..8 *)
  flags : int;          (* 8-bit flags *)
}

(* Relative addressing operand *)
type rel = {
  address : int;        (* absolute address *)
  offset : int;         (* displacement *)
}

(* Extended addressing operand *)
type ext = {
  address : int;        (* absolute address *)
  indirect : bool;      (* true if extended indirect *)
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int          (* m680x_reg *)
  | Imm of int32
  | Idx of idx
  | Ext of ext
  | Direct of int       (* direct_addr, lower 8-bit *)
  | Rel of rel
  | Const of int        (* constant value *)

(* Single operand *)
type operand = {
  value : op_value;
  size : int;           (* operand size in bytes *)
  access : int;         (* access flags: read/write *)
}

(* Instruction detail *)
type detail = {
  flags : int;          (* instruction flags *)
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_m680x_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.m680x_op_type) in
  let size = Unsigned.UInt8.to_int (getf op Types.m680x_op_size) in
  let access = Unsigned.UInt8.to_int (getf op Types.m680x_op_access) in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_m680x_op_reg op)
    | 2 -> Imm (Types.get_m680x_op_imm op)
    | 3 ->
      let (base_reg, offset_reg, offset, offset_addr, offset_bits, inc_dec, flags) =
        Types.get_m680x_op_idx op in
      Idx { base_reg; offset_reg; offset; offset_addr; offset_bits; inc_dec; flags }
    | 4 ->
      let (address, indirect) = Types.get_m680x_op_ext op in
      Ext { address; indirect }
    | 5 -> Direct (Types.get_m680x_op_direct_addr op)
    | 6 ->
      let (address, offset) = Types.get_m680x_op_rel op in
      Rel { address; offset }
    | 7 -> Const (Types.get_m680x_op_const_val op)
    | _ -> Invalid
  in

  { value; size; access }

(* Convert cs_m680x to OCaml detail *)
let detail_of_cs_m680x m680x =
  let flags = Unsigned.UInt8.to_int (getf m680x Types.m680x_flags) in
  let op_count = Unsigned.UInt8.to_int (getf m680x Types.m680x_op_count) in
  let ops_array = getf m680x Types.m680x_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_m680x_op (CArray.get ops_array i)
  ) in

  { flags; operands }

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

(* Extract M680X specific detail from cs_detail
   The m680x union is at offset 96 *)
let detail_of_cs_detail detail_ptr =
  let detail_base = to_voidp detail_ptr in
  let byte_ptr = from_voidp uint8_t detail_base in
  let m680x_ptr = from_voidp Types.cs_m680x (to_voidp (byte_ptr +@ 96)) in
  let m680x = !@ m680x_ptr in
  detail_of_cs_m680x m680x

(* Empty detail for when no detail is available *)
let empty_detail = {
  flags = 0;
  operands = [||];
}
