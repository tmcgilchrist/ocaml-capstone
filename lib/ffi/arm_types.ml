(* Capstone FFI - ARM 32-bit architecture-specific types *)

open Ctypes

(* arm_op_mem - Memory operand
   Layout from arm.h:
   - base: arm_reg (uint32_t)
   - index: arm_reg (uint32_t)
   - scale: int (4 bytes)
   - disp: int (4 bytes)
   - lshift: int (4 bytes)
   Total size: 20 bytes
*)
type arm_op_mem
let arm_op_mem : arm_op_mem structure typ = structure "arm_op_mem"
let mem_base = field arm_op_mem "base" uint32_t   (* arm_reg *)
let mem_index = field arm_op_mem "index" uint32_t (* arm_reg *)
let mem_scale = field arm_op_mem "scale" int32_t
let mem_disp = field arm_op_mem "disp" int32_t
let mem_lshift = field arm_op_mem "lshift" int32_t
let () = seal arm_op_mem

(* Shift info within operand *)
type arm_op_shift
let arm_op_shift : arm_op_shift structure typ = structure "arm_op_shift"
let shift_type = field arm_op_shift "type" uint32_t  (* arm_shifter *)
let shift_value = field arm_op_shift "value" uint32_t
let () = seal arm_op_shift

(* cs_arm_op - Single operand
   Layout from gcc offsetof:
   - offset 0: vector_index (int, 4 bytes)
   - offset 4: shift.type (uint32_t, 4 bytes)
   - offset 8: shift.value (uint32_t, 4 bytes)
   - offset 12: type (arm_op_type, 4 bytes)
   - offset 16: union (reg/imm/fp/mem/setend - 24 bytes)
   - offset 40: subtracted (bool, 1 byte)
   - offset 41: access (uint8_t)
   - offset 42: neon_lane (int8_t)
   - offset 43-47: padding (5 bytes)
   Total size: 48 bytes
*)
type cs_arm_op
let cs_arm_op : cs_arm_op structure typ = structure "cs_arm_op"
let op_vector_index = field cs_arm_op "vector_index" int32_t
let op_shift = field cs_arm_op "shift" arm_op_shift
let op_type = field cs_arm_op "type" uint32_t         (* arm_op_type *)
(* Union at offset 16 - reserve 24 bytes (arm_op_mem is 20 bytes but union aligned to 24) *)
let op_union = field cs_arm_op "union" (array 6 int32_t)  (* 24 bytes for union *)
let op_subtracted = field cs_arm_op "subtracted" bool
let op_access = field cs_arm_op "access" uint8_t
let op_neon_lane = field cs_arm_op "neon_lane" int8_t
let _op_pad = field cs_arm_op "_pad" (array 5 uint8_t)  (* padding to 48 bytes *)
let () = seal cs_arm_op

(* Accessor functions for union members *)
let get_op_reg op =
  let union_arr = getf op op_union in
  Int32.to_int (CArray.get union_arr 0)

let get_op_imm op =
  let union_arr = getf op op_union in
  CArray.get union_arr 0

let get_op_fp op =
  let union_arr = getf op op_union in
  (* double is 8 bytes, stored in first two int32s *)
  let low = Int32.to_int (CArray.get union_arr 0) in
  let high = Int32.to_int (CArray.get union_arr 1) in
  let bits = Int64.logor
    (Int64.of_int (low land 0xFFFFFFFF))
    (Int64.shift_left (Int64.of_int (high land 0xFFFFFFFF)) 32) in
  Int64.float_of_bits bits

let get_op_mem op =
  let union_arr = getf op op_union in
  (* mem struct: base(4), index(4), scale(4), disp(4), lshift(4) = 20 bytes *)
  let base = Int32.to_int (CArray.get union_arr 0) in
  let index = Int32.to_int (CArray.get union_arr 1) in
  let scale = CArray.get union_arr 2 in
  let disp = CArray.get union_arr 3 in
  let lshift = CArray.get union_arr 4 in
  (base, index, scale, disp, lshift)

let get_op_setend op =
  let union_arr = getf op op_union in
  Int32.to_int (CArray.get union_arr 0)

(* cs_arm - ARM instruction detail
   Layout from gcc offsetof:
   - offset 0: usermode (bool, 1 byte)
   - offset 4: vector_size (int, 4 bytes)
   - offset 8: vector_data (arm_vectordata_type, 4 bytes)
   - offset 12: cps_mode (arm_cpsmode_type, 4 bytes)
   - offset 16: cps_flag (arm_cpsflag_type, 4 bytes)
   - offset 20: cc (arm_cc, 4 bytes)
   - offset 24: update_flags (bool)
   - offset 25: writeback (bool)
   - offset 26: post_index (bool)
   - offset 28: mem_barrier (arm_mem_barrier, 4 bytes)
   - offset 32: op_count (uint8_t)
   - offset 40: operands[36] (36 * 48 = 1728 bytes)
   Total size: 1768 bytes
*)
type cs_arm
let cs_arm : cs_arm structure typ = structure "cs_arm"
let arm_usermode = field cs_arm "usermode" bool
let _arm_pad1 = field cs_arm "_pad1" (array 3 uint8_t)    (* padding to offset 4 *)
let arm_vector_size = field cs_arm "vector_size" int32_t
let arm_vector_data = field cs_arm "vector_data" uint32_t (* arm_vectordata_type *)
let arm_cps_mode = field cs_arm "cps_mode" uint32_t       (* arm_cpsmode_type *)
let arm_cps_flag = field cs_arm "cps_flag" uint32_t       (* arm_cpsflag_type *)
let arm_cc = field cs_arm "cc" uint32_t                   (* arm_cc *)
let arm_update_flags = field cs_arm "update_flags" bool
let arm_writeback = field cs_arm "writeback" bool
let arm_post_index = field cs_arm "post_index" bool
let _arm_pad2 = field cs_arm "_pad2" uint8_t              (* padding to offset 28 *)
let arm_mem_barrier = field cs_arm "mem_barrier" uint32_t (* arm_mem_barrier *)
let arm_op_count = field cs_arm "op_count" uint8_t
let _arm_pad3 = field cs_arm "_pad3" (array 7 uint8_t)    (* padding to offset 40 *)
let arm_operands = field cs_arm "operands" (array 36 cs_arm_op)
let () = seal cs_arm

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
  let fp = 4
  let cimm = 64     (* C-Immediate (coprocessor registers) *)
  let pimm = 65     (* P-Immediate (coprocessor registers) *)
  let setend = 66   (* SETEND instruction operand *)
  let sysreg = 67   (* MSR/MRS special register *)
end

(* Access type constants *)
module Access = struct
  let invalid = 0
  let read = 1
  let write = 2
  let read_write = 3
end
