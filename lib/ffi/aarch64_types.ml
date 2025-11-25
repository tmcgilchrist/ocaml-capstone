(* Capstone FFI - AArch64 architecture-specific types *)

open Ctypes

(* arm64_op_mem - Memory operand *)
type arm64_op_mem
let arm64_op_mem : arm64_op_mem structure typ = structure "arm64_op_mem"
let mem_base = field arm64_op_mem "base" uint32_t   (* arm64_reg *)
let mem_index = field arm64_op_mem "index" uint32_t (* arm64_reg *)
let mem_disp = field arm64_op_mem "disp" int32_t
let () = seal arm64_op_mem

(* arm64_op_sme_index - SME index operand *)
type arm64_op_sme_index
let arm64_op_sme_index : arm64_op_sme_index structure typ = structure "arm64_op_sme_index"
let sme_reg = field arm64_op_sme_index "reg" uint32_t
let sme_base = field arm64_op_sme_index "base" uint32_t
let sme_disp = field arm64_op_sme_index "disp" int32_t
let () = seal arm64_op_sme_index

(* Shift info within operand *)
type arm64_op_shift
let arm64_op_shift : arm64_op_shift structure typ = structure "arm64_op_shift"
let shift_type = field arm64_op_shift "type" uint32_t  (* arm64_shifter *)
let shift_value = field arm64_op_shift "value" uint32_t
let () = seal arm64_op_shift

(* cs_arm64_op - Single operand
   Layout from gcc offsetof:
   - offset 0: vector_index (int, 4 bytes)
   - offset 4: vas (uint32_t, 4 bytes)
   - offset 8: shift (8 bytes - type + value)
   - offset 16: ext (uint32_t, 4 bytes)
   - offset 20: type (uint32_t, 4 bytes)
   - offset 24: svcr (uint32_t, 4 bytes) - BEFORE the union!
   - offset 28: padding (4 bytes for alignment)
   - offset 32: union (reg/imm/fp/mem/sme_index - 16 bytes)
   - offset 48: access (uint8_t)
   - offset 49-55: padding (7 bytes to reach 56)
   Total size: 56 bytes

   Note: Ctypes doesn't support unions directly, so we define the full
   structure and access union members via address arithmetic *)
type cs_arm64_op
let cs_arm64_op : cs_arm64_op structure typ = structure "cs_arm64_op"
let op_vector_index = field cs_arm64_op "vector_index" int
let op_vas = field cs_arm64_op "vas" uint32_t           (* arm64_vas *)
let op_shift = field cs_arm64_op "shift" arm64_op_shift
let op_ext = field cs_arm64_op "ext" uint32_t           (* arm64_extender *)
let op_type = field cs_arm64_op "type" uint32_t         (* arm64_op_type *)
let op_svcr = field cs_arm64_op "svcr" uint32_t         (* arm64_svcr_op - at offset 24 *)
let _op_pad1 = field cs_arm64_op "_pad1" uint32_t       (* padding to offset 32 *)
(* Union at offset 32 - we reserve 16 bytes for it using an array *)
let op_union = field cs_arm64_op "union" (array 2 int64_t)  (* 16 bytes for union *)
let op_access = field cs_arm64_op "access" uint8_t
let _op_pad2 = field cs_arm64_op "_pad2" (array 7 uint8_t)  (* padding to 56 bytes *)
let () = seal cs_arm64_op

(* Accessor functions for union members - these read from op_union at offset 32 *)
let get_op_reg op =
  let union_arr = getf op op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_op_imm op =
  let union_arr = getf op op_union in
  CArray.get union_arr 0

let get_op_fp op =
  let union_arr = getf op op_union in
  Int64.float_of_bits (CArray.get union_arr 0)

let get_op_mem op =
  let union_arr = getf op op_union in
  let data = CArray.get union_arr 0 in
  let data2 = CArray.get union_arr 1 in
  (* mem struct: base (uint32), index (uint32), disp (int32) = 12 bytes *)
  let base = Int64.to_int (Int64.logand data 0xFFFFFFFFL) in
  let index = Int64.to_int (Int64.logand (Int64.shift_right_logical data 32) 0xFFFFFFFFL) in
  let disp = Int32.of_int (Int64.to_int (Int64.logand data2 0xFFFFFFFFL)) in
  (base, index, disp)

(* cs_arm64 - ARM64 instruction detail *)
type cs_arm64
let cs_arm64 : cs_arm64 structure typ = structure "cs_arm64"
let arm64_cc = field cs_arm64 "cc" uint32_t             (* arm64_cc *)
let arm64_update_flags = field cs_arm64 "update_flags" bool
let arm64_writeback = field cs_arm64 "writeback" bool
let arm64_post_index = field cs_arm64 "post_index" bool
let arm64_op_count = field cs_arm64 "op_count" uint8_t
let arm64_operands = field cs_arm64 "operands" (array 8 cs_arm64_op)
let () = seal cs_arm64

(* cs_detail - Full instruction detail with architecture union
   From gcc output with Capstone 5.0.x (Homebrew):
   - MAX_IMPL_R_REGS = 20, MAX_IMPL_W_REGS = 20
   - regs_read: offset 0 (20 * uint16_t = 40 bytes)
   - regs_read_count: offset 40 (uint8_t)
   - padding: offset 41 (1 byte for alignment)
   - regs_write: offset 42 (20 * uint16_t = 40 bytes)
   - regs_write_count: offset 82 (uint8_t)
   - groups: offset 83 (8 * uint8_t = 8 bytes)
   - groups_count: offset 91 (uint8_t)
   - writeback: offset 92 (bool)
   - padding to offset 96
   - arm64 union: offset 96
*)
type cs_detail
let cs_detail : cs_detail structure typ = structure "cs_detail"
let detail_regs_read = field cs_detail "regs_read" (array 20 uint16_t)
let detail_regs_read_count = field cs_detail "regs_read_count" uint8_t
let _detail_pad1 = field cs_detail "_pad1" uint8_t
let detail_regs_write = field cs_detail "regs_write" (array 20 uint16_t)
let detail_regs_write_count = field cs_detail "regs_write_count" uint8_t
let detail_groups = field cs_detail "groups" (array 8 uint8_t)
let detail_groups_count = field cs_detail "groups_count" uint8_t
let detail_writeback = field cs_detail "writeback" bool
(* Padding to align arm64 at offset 96 (current offset is 93, need 3 bytes) *)
let _detail_pad2 = field cs_detail "_pad2" (array 3 uint8_t)
(* Architecture-specific union - access based on handle's architecture *)
let detail_arm64 = field cs_detail "arm64" cs_arm64
let () = seal cs_detail

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let reg = 1
  let imm = 2
  let mem = 3
  let fp = 4
  let cimm = 64
  let reg_mrs = 65
  let reg_msr = 66
  let pstate = 67
  let sys = 68
  let prefetch = 69
  let barrier = 70
  let sme_index = 71
end

(* Access type constants *)
module Access = struct
  let invalid = 0
  let read = 1
  let write = 2
  let read_write = 3
end
