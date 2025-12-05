(* Capstone OCaml Bindings - AArch64 architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.Aarch64_types
module Const = Aarch64_const

(* Operand shift *)
type shift = {
  shift_type : int;   (* arm64_shifter *)
  shift_value : int;
}

(* Memory operand *)
type mem = {
  base : int;    (* arm64_reg *)
  index : int;   (* arm64_reg *)
  disp : int32;
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int          (* arm64_reg *)
  | Imm of int64
  | Mem of mem
  | Fp of float
  | CImm of int64
  | Reg_mrs of int
  | Reg_msr of int
  | Pstate of int
  | Sys of int
  | Prefetch of int
  | Barrier of int
  | Sme_index of int * int * int32  (* reg, base, disp *)

(* Access type *)
type access = Read | Write | ReadWrite

let access_of_int = function
  | 1 -> Read
  | 2 -> Write
  | 3 -> ReadWrite
  | _ -> Read  (* default *)

(* Single operand *)
type operand = {
  vector_index : int option;
  vas : int;             (* arm64_vas *)
  shift : shift option;
  ext : int;             (* arm64_extender *)
  value : op_value;
  access : access;
}

(* Instruction detail *)
type detail = {
  cc : int;              (* arm64_cc *)
  update_flags : bool;
  writeback : bool;
  post_index : bool;
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_arm64_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.op_type) in
  let vector_idx = getf op Types.op_vector_index in
  let vector_index = if vector_idx < 0 then None else Some vector_idx in

  let shift_struct = getf op Types.op_shift in
  let shift_type_val = Unsigned.UInt32.to_int (getf shift_struct Types.shift_type) in
  let shift_value_val = Unsigned.UInt32.to_int (getf shift_struct Types.shift_value) in
  let shift =
    if shift_type_val = 0 && shift_value_val = 0 then None
    else Some { shift_type = shift_type_val; shift_value = shift_value_val }
  in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_op_reg op)
    | 2 -> Imm (Types.get_op_imm op)
    | 3 ->
      let (base, index, disp) = Types.get_op_mem op in
      Mem { base; index; disp }
    | 4 -> Fp (Types.get_op_fp op)
    | 64 -> CImm (Types.get_op_imm op)
    | 65 -> Reg_mrs (Types.get_op_reg op)
    | 66 -> Reg_msr (Types.get_op_reg op)
    | 67 -> Pstate (Types.get_op_reg op)
    | 68 -> Sys (Types.get_op_reg op)
    | 69 -> Prefetch (Types.get_op_reg op)
    | 70 -> Barrier (Types.get_op_reg op)
    | _ -> Invalid
  in

  {
    vector_index;
    vas = Unsigned.UInt32.to_int (getf op Types.op_vas);
    shift;
    ext = Unsigned.UInt32.to_int (getf op Types.op_ext);
    value;
    access = access_of_int (Unsigned.UInt8.to_int (getf op Types.op_access));
  }

(* Convert cs_arm64 to OCaml detail *)
let detail_of_cs_arm64 arm64 =
  let op_count = Unsigned.UInt8.to_int (getf arm64 Types.arm64_op_count) in
  let ops_array = getf arm64 Types.arm64_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_arm64_op (CArray.get ops_array i)
  ) in
  {
    cc = Unsigned.UInt32.to_int (getf arm64 Types.arm64_cc);
    update_flags = getf arm64 Types.arm64_update_flags;
    writeback = getf arm64 Types.arm64_writeback;
    post_index = getf arm64 Types.arm64_post_index;
    operands;
  }

(* Extract common detail fields *)
let common_detail_of_cs_detail detail_ptr =
  let detail = !@ detail_ptr in
  let regs_read_count = Unsigned.UInt8.to_int (getf detail Types.detail_regs_read_count) in
  let regs_write_count = Unsigned.UInt8.to_int (getf detail Types.detail_regs_write_count) in
  let groups_count = Unsigned.UInt8.to_int (getf detail Types.detail_groups_count) in

  let regs_read_arr = getf detail Types.detail_regs_read in
  let regs_write_arr = getf detail Types.detail_regs_write in
  let groups_arr = getf detail Types.detail_groups in

  {
    regs_read = Array.init regs_read_count (fun i ->
      Unsigned.UInt16.to_int (CArray.get regs_read_arr i));
    regs_write = Array.init regs_write_count (fun i ->
      Unsigned.UInt16.to_int (CArray.get regs_write_arr i));
    groups = Array.init groups_count (fun i ->
      Unsigned.UInt8.to_int (CArray.get groups_arr i));
  }

(* Extract ARM64-specific detail from cs_detail *)
let detail_of_cs_detail detail_ptr =
  let detail = !@ detail_ptr in
  let arm64 = getf detail Types.detail_arm64 in
  detail_of_cs_arm64 arm64

(* Empty detail for when no detail is available *)
let empty_detail = {
  cc = 0;
  update_flags = false;
  writeback = false;
  post_index = false;
  operands = [||];
}
