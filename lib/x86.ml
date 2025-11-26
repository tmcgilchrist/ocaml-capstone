(* Capstone OCaml Bindings - x86 architecture-specific types *)

open Ctypes
module Ffi = Capstone_ffi
module Types = Ffi.X86_types
module Const = X86_const

(* Memory operand *)
type mem = {
  segment : int;   (* x86_reg *)
  base : int;      (* x86_reg *)
  index : int;     (* x86_reg *)
  scale : int;
  disp : int64;
}

(* Operand value - variant based on op_type *)
type op_value =
  | Invalid
  | Reg of int     (* x86_reg *)
  | Imm of int64
  | Mem of mem

(* Access type *)
type access = Read | Write | ReadWrite

let access_of_int = function
  | 1 -> Read
  | 2 -> Write
  | 3 -> ReadWrite
  | _ -> Read  (* default *)

(* Single operand *)
type operand = {
  value : op_value;
  size : int;          (* operand size in bytes *)
  access : access;
  avx_bcast : int;     (* x86_avx_bcast *)
  avx_zero_opmask : bool;
}

(* Instruction detail *)
type detail = {
  prefix : int array;     (* up to 4 prefixes *)
  opcode : int array;     (* up to 4 opcode bytes *)
  rex : int;              (* REX prefix for x86-64 *)
  addr_size : int;        (* address size *)
  modrm : int;            (* ModR/M byte *)
  sib : int;              (* SIB byte *)
  disp : int64;           (* displacement *)
  sib_index : int;        (* SIB index register *)
  sib_scale : int;        (* SIB scale *)
  sib_base : int;         (* SIB base register *)
  xop_cc : int;           (* XOP condition code *)
  sse_cc : int;           (* SSE condition code *)
  avx_cc : int;           (* AVX condition code *)
  avx_sae : bool;         (* AVX suppress-all-exceptions *)
  avx_rm : int;           (* AVX rounding mode *)
  eflags : int64;         (* EFLAGS/FPU flags *)
  operands : operand array;
}

(* Common detail fields *)
type common_detail = {
  regs_read : int array;
  regs_write : int array;
  groups : int array;
}

(* Convert ctypes operand to OCaml *)
let operand_of_cs_x86_op op =
  let op_type = Unsigned.UInt32.to_int (getf op Types.x86_op_type) in

  let value = match op_type with
    | 0 -> Invalid
    | 1 -> Reg (Types.get_x86_op_reg op)
    | 2 -> Imm (Types.get_x86_op_imm op)
    | 3 ->
      let (segment, base, index, scale, disp) = Types.get_x86_op_mem op in
      Mem { segment; base; index; scale; disp }
    | _ -> Invalid
  in

  {
    value;
    size = Unsigned.UInt8.to_int (getf op Types.x86_op_size);
    access = access_of_int (Unsigned.UInt8.to_int (getf op Types.x86_op_access));
    avx_bcast = Unsigned.UInt32.to_int (getf op Types.x86_op_avx_bcast);
    avx_zero_opmask = getf op Types.x86_op_avx_zero_opmask;
  }

(* Convert cs_x86 to OCaml detail *)
let detail_of_cs_x86 x86 =
  let op_count = Unsigned.UInt8.to_int (getf x86 Types.x86_op_count) in
  let ops_array = getf x86 Types.x86_operands in
  let operands = Array.init op_count (fun i ->
    operand_of_cs_x86_op (CArray.get ops_array i)
  ) in

  let prefix_arr = getf x86 Types.x86_prefix in
  let opcode_arr = getf x86 Types.x86_opcode in

  {
    prefix = Array.init 4 (fun i -> Unsigned.UInt8.to_int (CArray.get prefix_arr i));
    opcode = Array.init 4 (fun i -> Unsigned.UInt8.to_int (CArray.get opcode_arr i));
    rex = Unsigned.UInt8.to_int (getf x86 Types.x86_rex);
    addr_size = Unsigned.UInt8.to_int (getf x86 Types.x86_addr_size);
    modrm = Unsigned.UInt8.to_int (getf x86 Types.x86_modrm);
    sib = Unsigned.UInt8.to_int (getf x86 Types.x86_sib);
    disp = getf x86 Types.x86_disp;
    sib_index = Unsigned.UInt32.to_int (getf x86 Types.x86_sib_index);
    sib_scale = getf x86 Types.x86_sib_scale;
    sib_base = Unsigned.UInt32.to_int (getf x86 Types.x86_sib_base);
    xop_cc = Unsigned.UInt32.to_int (getf x86 Types.x86_xop_cc);
    sse_cc = Unsigned.UInt32.to_int (getf x86 Types.x86_sse_cc);
    avx_cc = Unsigned.UInt32.to_int (getf x86 Types.x86_avx_cc);
    avx_sae = getf x86 Types.x86_avx_sae;
    avx_rm = Unsigned.UInt32.to_int (getf x86 Types.x86_avx_rm);
    eflags = Unsigned.UInt64.to_int64 (getf x86 Types.x86_eflags);
    operands;
  }

(* Extract common detail fields from cs_detail for x86 *)
let common_detail_of_cs_detail detail_ptr =
  (* We reuse the aarch64_types cs_detail structure since the common
     fields are at the same offsets *)
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

(* Extract x86-specific detail from cs_detail
   The x86 union is at the same offset (96) as arm64 *)
let detail_of_cs_detail detail_ptr =
  (* Access x86 at the same offset as arm64 (offset 96) *)
  let detail_base = to_voidp detail_ptr in
  (* Cast to uint8_t pointer for byte arithmetic, then offset by 96 *)
  let byte_ptr = from_voidp uint8_t detail_base in
  let x86_ptr = from_voidp Types.cs_x86 (to_voidp (byte_ptr +@ 96)) in
  let x86 = !@ x86_ptr in
  detail_of_cs_x86 x86
