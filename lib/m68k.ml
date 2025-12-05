(* Capstone OCaml Bindings - M68K architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.M68k_types

(* Memory operand for M68K
   Represents the complex M68K addressing modes including:
   - Base register
   - Index register with scale
   - Inner indirect base register
   - Inner/outer displacements
   - Bit field parameters (width, offset)
*)
type mem = {
  base_reg : int;       (* m68k_reg - base register (or 0 if irrelevant) *)
  index_reg : int;      (* m68k_reg - index register (or 0 if irrelevant) *)
  in_base_reg : int;    (* m68k_reg - indirect base register (or 0 if irrelevant) *)
  in_disp : int32;      (* indirect displacement *)
  out_disp : int32;     (* other displacement *)
  disp : int;           (* displacement value (int16_t in C) *)
  scale : int;          (* scale for index register (1, 2, 4, 8) *)
  bitfield : bool;      (* true if bitfield parameters are used *)
  width : int;          (* used for bf* instructions *)
  offset : int;         (* used for bf* instructions *)
  index_size : int;     (* 0 = word, 1 = long *)
}

(* Branch displacement operand *)
type br_disp = {
  disp : int32;        (* displacement value *)
  disp_size : int;     (* size: 1=byte, 2=word, 4=long *)
}

(* Register pair (used for some instructions like DIV/MUL) *)
type reg_pair = {
  reg_0 : int;         (* first register *)
  reg_1 : int;         (* second register *)
}

(* Operation size information *)
type op_size =
  | Size_invalid
  | Cpu_size of int    (* byte=1, word=2, long=4 *)
  | Fpu_size of int    (* single=4, double=8, extended=12 *)

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid                (* M68K_OP_INVALID *)
  | Reg of int             (* M68K_OP_REG - register number (m68k_reg) *)
  | Imm of int64           (* M68K_OP_IMM - immediate value *)
  | Mem of mem             (* M68K_OP_MEM - memory operand *)
  | Fp_single of float     (* M68K_OP_FP_SINGLE - single precision float *)
  | Fp_double of float     (* M68K_OP_FP_DOUBLE - double precision float *)
  | Reg_bits of int        (* M68K_OP_REG_BITS - register bits for movem *)
  | Reg_pair of reg_pair   (* M68K_OP_REG_PAIR - register pair *)
  | Br_disp of br_disp     (* M68K_OP_BR_DISP - branch displacement *)

(* Addressing mode enumeration *)
type address_mode =
  | AM_none                    (* No address mode *)
  | AM_reg_direct_data         (* Register Direct - Data *)
  | AM_reg_direct_addr         (* Register Direct - Address *)
  | AM_regi_addr               (* Register Indirect - Address *)
  | AM_regi_addr_post_inc      (* Register Indirect - Address with Postincrement *)
  | AM_regi_addr_pre_dec       (* Register Indirect - Address with Predecrement *)
  | AM_regi_addr_disp          (* Register Indirect - Address with Displacement *)
  | AM_aregi_index_8_bit_disp  (* Address Register Indirect With Index - 8-bit displacement *)
  | AM_aregi_index_base_disp   (* Address Register Indirect With Index - Base displacement *)
  | AM_memi_post_index         (* Memory indirect - Postindex *)
  | AM_memi_pre_index          (* Memory indirect - Preindex *)
  | AM_pci_disp                (* Program Counter Indirect - with Displacement *)
  | AM_pci_index_8_bit_disp    (* PC Indirect with Index - 8-Bit Displacement *)
  | AM_pci_index_base_disp     (* PC Indirect with Index - Base Displacement *)
  | AM_pc_memi_post_index      (* PC Memory Indirect - Postindexed *)
  | AM_pc_memi_pre_index       (* PC Memory Indirect - Preindexed *)
  | AM_absolute_data_short     (* Absolute Data Addressing - Short *)
  | AM_absolute_data_long      (* Absolute Data Addressing - Long *)
  | AM_immediate               (* Immediate value *)
  | AM_branch_displacement     (* Address as displacement from (PC+2) used by branches *)

(* Single operand *)
type operand = {
  value : op_value;
  address_mode : address_mode;
}

(* Instruction detail *)
type detail = {
  operands : operand array;
  op_size : op_size;
}

(* Common detail fields (shared with other architectures) *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert integer address mode to variant *)
let address_mode_of_int = function
  | 0 -> AM_none
  | 1 -> AM_reg_direct_data
  | 2 -> AM_reg_direct_addr
  | 3 -> AM_regi_addr
  | 4 -> AM_regi_addr_post_inc
  | 5 -> AM_regi_addr_pre_dec
  | 6 -> AM_regi_addr_disp
  | 7 -> AM_aregi_index_8_bit_disp
  | 8 -> AM_aregi_index_base_disp
  | 9 -> AM_memi_post_index
  | 10 -> AM_memi_pre_index
  | 11 -> AM_pci_disp
  | 12 -> AM_pci_index_8_bit_disp
  | 13 -> AM_pci_index_base_disp
  | 14 -> AM_pc_memi_post_index
  | 15 -> AM_pc_memi_pre_index
  | 16 -> AM_absolute_data_short
  | 17 -> AM_absolute_data_long
  | 18 -> AM_immediate
  | 19 -> AM_branch_displacement
  | _ -> AM_none

(* Convert ctypes operand to OCaml *)
let operand_of_cs_m68k_op op =
  let op_type = Types.get_m68k_op_type op in
  let addr_mode = address_mode_of_int (Types.get_m68k_op_address_mode op) in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_m68k_op_reg op)
    | 2 -> Imm (Types.get_m68k_op_imm op)
    | 3 ->
      let (base_reg, index_reg, in_base_reg, in_disp, out_disp, disp_raw,
           scale, bitfield_raw, width, offset, index_size) =
        Types.get_m68k_op_mem op in
      Mem {
        base_reg;
        index_reg;
        in_base_reg;
        in_disp;
        out_disp;
        disp = disp_raw;  (* int16_t comes through as int *)
        scale;
        bitfield = bitfield_raw <> 0;
        width;
        offset;
        index_size;
      }
    | 4 -> Fp_single (Types.get_m68k_op_simm op)
    | 5 -> Fp_double (Types.get_m68k_op_dimm op)
    | 6 -> Reg_bits (Types.get_m68k_op_register_bits op)
    | 7 ->
      let (reg_0, reg_1) = Types.get_m68k_op_reg_pair op in
      Reg_pair { reg_0; reg_1 }
    | 8 ->
      let (disp, disp_size) = Types.get_m68k_op_br_disp op in
      Br_disp { disp; disp_size }
    | _ -> Invalid
  in

  { value; address_mode = addr_mode }

(* Convert operation size *)
let op_size_of_cs_m68k m68k =
  let (size_type, size_value) = Types.get_m68k_op_size m68k in
  match size_type with
  | 0 -> Size_invalid
  | 1 -> Cpu_size size_value
  | 2 -> Fpu_size size_value
  | _ -> Size_invalid

(* Convert cs_m68k to OCaml detail *)
let detail_of_cs_m68k m68k =
  let op_count = Types.get_m68k_op_count m68k in
  let ops_array = getf m68k Types.m68k_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_m68k_op (CArray.get ops_array i)
  ) in
  let op_size = op_size_of_cs_m68k m68k in

  { operands; op_size }

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

(* Extract M68K specific detail from cs_detail
   The m68k union is at offset 96 in cs_detail *)
let detail_of_cs_detail detail_ptr =
  let detail_base = to_voidp detail_ptr in
  let byte_ptr = from_voidp uint8_t detail_base in
  let m68k_ptr = from_voidp Types.cs_m68k (to_voidp (byte_ptr +@ 96)) in
  let m68k = !@ m68k_ptr in
  detail_of_cs_m68k m68k

(* Empty detail for when no detail is available *)
let empty_detail = {
  operands = [||];
  op_size = Size_invalid;
}
