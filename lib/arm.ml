(* Capstone OCaml Bindings - ARM 32-bit architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.Arm_types

(* Memory operand *)
type mem = {
  base : int;      (* arm_reg *)
  index : int;     (* arm_reg *)
  scale : int32;
  disp : int32;
  lshift : int32;
}

(* Shift info *)
type shift = {
  shift_type : int;   (* arm_shifter *)
  shift_value : int;
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int     (* arm_reg *)
  | Imm of int32
  | Mem of mem
  | Fp of float
  | Cimm of int32  (* C-Immediate for coprocessor *)
  | Pimm of int32  (* P-Immediate for coprocessor *)
  | Setend of int  (* arm_setend_type *)
  | Sysreg of int  (* arm_reg *)

(* Single operand *)
type operand = {
  vector_index : int;
  shift : shift;
  value : op_value;
  subtracted : bool;
  access : int;
  neon_lane : int;
}

(* Instruction detail *)
type detail = {
  usermode : bool;
  vector_size : int;
  vector_data : int;   (* arm_vectordata_type *)
  cps_mode : int;      (* arm_cpsmode_type *)
  cps_flag : int;      (* arm_cpsflag_type *)
  cc : int;            (* arm_cc *)
  update_flags : bool;
  writeback : bool;
  post_index : bool;
  mem_barrier : int;   (* arm_mem_barrier *)
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_arm_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.op_type) in
  let shift_s = getf op Types.op_shift in

  let shift = {
    shift_type = Unsigned.UInt32.to_int (getf shift_s Types.shift_type);
    shift_value = Unsigned.UInt32.to_int (getf shift_s Types.shift_value);
  } in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_op_reg op)
    | 2 -> Imm (Types.get_op_imm op)
    | 3 ->
      let (base, index, scale, disp, lshift) = Types.get_op_mem op in
      Mem { base; index; scale; disp; lshift }
    | 4 -> Fp (Types.get_op_fp op)
    | 64 -> Cimm (Types.get_op_imm op)  (* C-Immediate *)
    | 65 -> Pimm (Types.get_op_imm op)  (* P-Immediate *)
    | 66 -> Setend (Types.get_op_setend op)
    | 67 -> Sysreg (Types.get_op_reg op)
    | _ -> Invalid
  in

  {
    vector_index = Int32.to_int (getf op Types.op_vector_index);
    shift;
    value;
    subtracted = getf op Types.op_subtracted;
    access = Unsigned.UInt8.to_int (getf op Types.op_access);
    neon_lane = getf op Types.op_neon_lane;
  }

(* Convert cs_arm to OCaml detail *)
let detail_of_cs_arm arm =
  let op_count = Unsigned.UInt8.to_int (getf arm Types.arm_op_count) in
  let ops_array = getf arm Types.arm_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_arm_op (CArray.get ops_array i)
  ) in

  {
    usermode = getf arm Types.arm_usermode;
    vector_size = Int32.to_int (getf arm Types.arm_vector_size);
    vector_data = Unsigned.UInt32.to_int (getf arm Types.arm_vector_data);
    cps_mode = Unsigned.UInt32.to_int (getf arm Types.arm_cps_mode);
    cps_flag = Unsigned.UInt32.to_int (getf arm Types.arm_cps_flag);
    cc = Unsigned.UInt32.to_int (getf arm Types.arm_cc);
    update_flags = getf arm Types.arm_update_flags;
    writeback = getf arm Types.arm_writeback;
    post_index = getf arm Types.arm_post_index;
    mem_barrier = Unsigned.UInt32.to_int (getf arm Types.arm_mem_barrier);
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

(* Extract ARM specific detail from cs_detail
   The arm union is at offset 96 *)
let detail_of_cs_detail detail_ptr =
  let detail_base = to_voidp detail_ptr in
  let byte_ptr = from_voidp uint8_t detail_base in
  let arm_ptr = from_voidp Types.cs_arm (to_voidp (byte_ptr +@ 96)) in
  let arm = !@ arm_ptr in
  detail_of_cs_arm arm
