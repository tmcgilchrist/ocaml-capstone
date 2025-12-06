(* Capstone FFI - M68K architecture-specific types *)

open Ctypes

(* M68K operand count *)
let m68k_operand_count = 4

(* m68k_op_mem - Memory operand (28 bytes)
   Layout from m68k.h:
   - offset 0: base_reg (m68k_reg, 4 bytes)
   - offset 4: index_reg (m68k_reg, 4 bytes)
   - offset 8: in_base_reg (m68k_reg, 4 bytes)
   - offset 12: in_disp (uint32_t, 4 bytes)
   - offset 16: out_disp (uint32_t, 4 bytes)
   - offset 20: disp (int16_t, 2 bytes)
   - offset 22: scale (uint8_t, 1 byte)
   - offset 23: bitfield (uint8_t, 1 byte)
   - offset 24: width (uint8_t, 1 byte)
   - offset 25: offset (uint8_t, 1 byte)
   - offset 26: index_size (uint8_t, 1 byte)
   - offset 27: padding (1 byte)
   Total: 28 bytes
*)
type m68k_op_mem
let m68k_op_mem : m68k_op_mem structure typ = structure "m68k_op_mem"
let mem_base_reg = field m68k_op_mem "base_reg" uint32_t
let mem_index_reg = field m68k_op_mem "index_reg" uint32_t
let mem_in_base_reg = field m68k_op_mem "in_base_reg" uint32_t
let mem_in_disp = field m68k_op_mem "in_disp" uint32_t
let mem_out_disp = field m68k_op_mem "out_disp" uint32_t
let mem_disp = field m68k_op_mem "disp" int16_t
let mem_scale = field m68k_op_mem "scale" uint8_t
let mem_bitfield = field m68k_op_mem "bitfield" uint8_t
let mem_width = field m68k_op_mem "width" uint8_t
let mem_offset = field m68k_op_mem "offset" uint8_t
let mem_index_size = field m68k_op_mem "index_size" uint8_t
let _mem_pad = field m68k_op_mem "_pad" uint8_t
let () = seal m68k_op_mem

(* m68k_op_br_disp - Branch displacement (8 bytes)
   Layout:
   - offset 0: disp (int32_t, 4 bytes)
   - offset 4: disp_size (uint8_t, 1 byte)
   - offset 5-7: padding (3 bytes)
*)
type m68k_op_br_disp
let m68k_op_br_disp : m68k_op_br_disp structure typ = structure "m68k_op_br_disp"
let br_disp_disp = field m68k_op_br_disp "disp" int32_t
let br_disp_size = field m68k_op_br_disp "disp_size" uint8_t
let _br_disp_pad = field m68k_op_br_disp "_pad" (array 3 uint8_t)
let () = seal m68k_op_br_disp

(* cs_m68k_op_reg_pair - Register pair for dual-register operands (8 bytes)
   Layout:
   - offset 0: reg_0 (m68k_reg, 4 bytes)
   - offset 4: reg_1 (m68k_reg, 4 bytes)
*)
type cs_m68k_op_reg_pair
let cs_m68k_op_reg_pair : cs_m68k_op_reg_pair structure typ = structure "cs_m68k_op_reg_pair"
let reg_pair_reg_0 = field cs_m68k_op_reg_pair "reg_0" uint32_t
let reg_pair_reg_1 = field cs_m68k_op_reg_pair "reg_1" uint32_t
let () = seal cs_m68k_op_reg_pair

(* cs_m68k_op - Single operand
   This is a complex structure with a union.

   Layout from m68k.h:
   - offset 0: union (8 bytes for largest member: uint64_t imm or double dimm)
     - imm (uint64_t, 8 bytes) - immediate value
     - dimm (double, 8 bytes) - double float immediate
     - simm (float, 4 bytes) - single float immediate
     - reg (m68k_reg, 4 bytes) - register
     - reg_pair (cs_m68k_op_reg_pair, 8 bytes) - register pair
   - offset 8: mem (m68k_op_mem, 28 bytes)
   - offset 36: br_disp (m68k_op_br_disp, 8 bytes)
   - offset 44: register_bits (uint32_t, 4 bytes)
   - offset 48: type (m68k_op_type, 4 bytes)
   - offset 52: address_mode (m68k_address_mode, 4 bytes)
   Total: 56 bytes
*)
type cs_m68k_op
let cs_m68k_op : cs_m68k_op structure typ = structure "cs_m68k_op"
(* Union at offset 0 - use 8 bytes for imm/dimm as largest member *)
let m68k_op_imm = field cs_m68k_op "imm" uint64_t
(* mem struct follows at offset 8 *)
let m68k_op_mem_field = field cs_m68k_op "mem" m68k_op_mem
(* br_disp struct at offset 36 *)
let m68k_op_br_disp_field = field cs_m68k_op "br_disp" m68k_op_br_disp
(* register_bits at offset 44 *)
let m68k_op_register_bits = field cs_m68k_op "register_bits" uint32_t
(* type at offset 48 *)
let m68k_op_type = field cs_m68k_op "type" uint32_t
(* address_mode at offset 52 *)
let m68k_op_address_mode = field cs_m68k_op "address_mode" uint32_t
let () = seal cs_m68k_op

(* m68k_op_size - Operation size (8 bytes)
   Layout:
   - offset 0: type (m68k_size_type, 4 bytes)
   - offset 4: union (cpu_size or fpu_size, 4 bytes)
*)
type m68k_op_size
let m68k_op_size : m68k_op_size structure typ = structure "m68k_op_size"
let op_size_type = field m68k_op_size "type" uint32_t
let op_size_value = field m68k_op_size "value" uint32_t
let () = seal m68k_op_size

(* cs_m68k - M68K instruction detail
   Layout:
   - offset 0: operands[4] (4 * sizeof(cs_m68k_op) = 4 * 56 = 224 bytes)
   - offset 224: op_size (8 bytes)
   - offset 232: op_count (1 byte)
   - padding to alignment
*)
type cs_m68k
let cs_m68k : cs_m68k structure typ = structure "cs_m68k"
let m68k_operands = field cs_m68k "operands" (array 4 cs_m68k_op)
let m68k_op_size_field = field cs_m68k "op_size" m68k_op_size
let m68k_op_count = field cs_m68k "op_count" uint8_t
let () = seal cs_m68k

(* Operand type constants from m68k.h *)
module OpType = struct
  let invalid = 0    (* M68K_OP_INVALID *)
  let reg = 1        (* M68K_OP_REG *)
  let imm = 2        (* M68K_OP_IMM *)
  let mem = 3        (* M68K_OP_MEM *)
  let fp_single = 4  (* M68K_OP_FP_SINGLE *)
  let fp_double = 5  (* M68K_OP_FP_DOUBLE *)
  let reg_bits = 6   (* M68K_OP_REG_BITS *)
  let reg_pair = 7   (* M68K_OP_REG_PAIR *)
  let br_disp = 8    (* M68K_OP_BR_DISP *)
end

(* Addressing mode constants from m68k.h *)
module AddressMode = struct
  let none = 0                     (* M68K_AM_NONE *)
  let reg_direct_data = 1          (* M68K_AM_REG_DIRECT_DATA *)
  let reg_direct_addr = 2          (* M68K_AM_REG_DIRECT_ADDR *)
  let regi_addr = 3                (* M68K_AM_REGI_ADDR *)
  let regi_addr_post_inc = 4       (* M68K_AM_REGI_ADDR_POST_INC *)
  let regi_addr_pre_dec = 5        (* M68K_AM_REGI_ADDR_PRE_DEC *)
  let regi_addr_disp = 6           (* M68K_AM_REGI_ADDR_DISP *)
  let aregi_index_8_bit_disp = 7   (* M68K_AM_AREGI_INDEX_8_BIT_DISP *)
  let aregi_index_base_disp = 8    (* M68K_AM_AREGI_INDEX_BASE_DISP *)
  let memi_post_index = 9          (* M68K_AM_MEMI_POST_INDEX *)
  let memi_pre_index = 10          (* M68K_AM_MEMI_PRE_INDEX *)
  let pci_disp = 11                (* M68K_AM_PCI_DISP *)
  let pci_index_8_bit_disp = 12    (* M68K_AM_PCI_INDEX_8_BIT_DISP *)
  let pci_index_base_disp = 13     (* M68K_AM_PCI_INDEX_BASE_DISP *)
  let pc_memi_post_index = 14      (* M68K_AM_PC_MEMI_POST_INDEX *)
  let pc_memi_pre_index = 15       (* M68K_AM_PC_MEMI_PRE_INDEX *)
  let absolute_data_short = 16     (* M68K_AM_ABSOLUTE_DATA_SHORT *)
  let absolute_data_long = 17      (* M68K_AM_ABSOLUTE_DATA_LONG *)
  let immediate = 18               (* M68K_AM_IMMEDIATE *)
  let branch_displacement = 19     (* M68K_AM_BRANCH_DISPLACEMENT *)
end

(* Size type constants from m68k.h *)
module SizeType = struct
  let invalid = 0  (* M68K_SIZE_TYPE_INVALID *)
  let cpu = 1      (* M68K_SIZE_TYPE_CPU *)
  let fpu = 2      (* M68K_SIZE_TYPE_FPU *)
end

(* CPU size constants from m68k.h *)
module CpuSize = struct
  let none = 0  (* M68K_CPU_SIZE_NONE *)
  let byte = 1  (* M68K_CPU_SIZE_BYTE *)
  let word = 2  (* M68K_CPU_SIZE_WORD *)
  let long = 4  (* M68K_CPU_SIZE_LONG *)
end

(* FPU size constants from m68k.h *)
module FpuSize = struct
  let none = 0      (* M68K_FPU_SIZE_NONE *)
  let single = 4    (* M68K_FPU_SIZE_SINGLE *)
  let double = 8    (* M68K_FPU_SIZE_DOUBLE *)
  let extended = 12 (* M68K_FPU_SIZE_EXTENDED *)
end

(* Branch displacement size constants from m68k.h *)
module BrDispSize = struct
  let invalid = 0  (* M68K_OP_BR_DISP_SIZE_INVALID *)
  let byte = 1     (* M68K_OP_BR_DISP_SIZE_BYTE *)
  let word = 2     (* M68K_OP_BR_DISP_SIZE_WORD *)
  let long = 4     (* M68K_OP_BR_DISP_SIZE_LONG *)
end

(* Accessor functions for operand data *)

(* Get immediate value (64-bit) *)
let get_m68k_op_imm op =
  Unsigned.UInt64.to_int64 (getf op m68k_op_imm)

(* Get register value *)
let get_m68k_op_reg op =
  (* Register is stored in the union at offset 0, lower 32 bits *)
  let imm = getf op m68k_op_imm in
  Unsigned.UInt64.to_int (Unsigned.UInt64.logand imm (Unsigned.UInt64.of_int 0xFFFFFFFF))

(* Get single-precision float immediate *)
let get_m68k_op_simm op =
  let imm = getf op m68k_op_imm in
  let bits = Unsigned.UInt64.to_int64 imm in
  Int32.float_of_bits (Int64.to_int32 bits)

(* Get double-precision float immediate *)
let get_m68k_op_dimm op =
  let imm = getf op m68k_op_imm in
  Int64.float_of_bits (Unsigned.UInt64.to_int64 imm)

(* Get register pair *)
let get_m68k_op_reg_pair op =
  let imm = getf op m68k_op_imm in
  let bits = Unsigned.UInt64.to_int64 imm in
  let reg_0 = Int64.to_int (Int64.logand bits 0xFFFFFFFFL) in
  let reg_1 = Int64.to_int (Int64.shift_right_logical bits 32) in
  (reg_0, reg_1)

(* Get memory operand fields *)
let get_m68k_op_mem op =
  let mem = getf op m68k_op_mem_field in
  let base_reg = Unsigned.UInt32.to_int (getf mem mem_base_reg) in
  let index_reg = Unsigned.UInt32.to_int (getf mem mem_index_reg) in
  let in_base_reg = Unsigned.UInt32.to_int (getf mem mem_in_base_reg) in
  let in_disp = Unsigned.UInt32.to_int32 (getf mem mem_in_disp) in
  let out_disp = Unsigned.UInt32.to_int32 (getf mem mem_out_disp) in
  let disp = getf mem mem_disp in
  let scale = Unsigned.UInt8.to_int (getf mem mem_scale) in
  let bitfield = Unsigned.UInt8.to_int (getf mem mem_bitfield) in
  let width = Unsigned.UInt8.to_int (getf mem mem_width) in
  let offset = Unsigned.UInt8.to_int (getf mem mem_offset) in
  let index_size = Unsigned.UInt8.to_int (getf mem mem_index_size) in
  (base_reg, index_reg, in_base_reg, in_disp, out_disp, disp, scale, bitfield, width, offset, index_size)

(* Get branch displacement operand fields *)
let get_m68k_op_br_disp op =
  let br = getf op m68k_op_br_disp_field in
  let disp = getf br br_disp_disp in
  let disp_size = Unsigned.UInt8.to_int (getf br br_disp_size) in
  (disp, disp_size)

(* Get register bits (for movem etc.) *)
let get_m68k_op_register_bits op =
  Unsigned.UInt32.to_int (getf op m68k_op_register_bits)

(* Get operand type *)
let get_m68k_op_type op =
  Unsigned.UInt32.to_int (getf op m68k_op_type)

(* Get addressing mode *)
let get_m68k_op_address_mode op =
  Unsigned.UInt32.to_int (getf op m68k_op_address_mode)

(* Get operation size info *)
let get_m68k_op_size detail =
  let op_size = getf detail m68k_op_size_field in
  let size_type = Unsigned.UInt32.to_int (getf op_size op_size_type) in
  let size_value = Unsigned.UInt32.to_int (getf op_size op_size_value) in
  (size_type, size_value)

(* Get operand count *)
let get_m68k_op_count detail =
  Unsigned.UInt8.to_int (getf detail m68k_op_count)
