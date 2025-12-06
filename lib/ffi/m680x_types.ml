(* Capstone FFI - M680X architecture-specific types *)

open Ctypes

(* m680x_op_idx - Indexed addressing operand
   Layout from m680x.h:
   - offset 0: base_reg (m680x_reg, 4 bytes)
   - offset 4: offset_reg (m680x_reg, 4 bytes)
   - offset 8: offset (int16_t)
   - offset 10: offset_addr (uint16_t)
   - offset 12: offset_bits (uint8_t)
   - offset 13: inc_dec (int8_t)
   - offset 14: flags (uint8_t)
   - offset 15: padding (1 byte)
   Total size: 16 bytes
*)
type m680x_op_idx
let m680x_op_idx : m680x_op_idx structure typ = structure "m680x_op_idx"
let idx_base_reg = field m680x_op_idx "base_reg" uint32_t
let idx_offset_reg = field m680x_op_idx "offset_reg" uint32_t
let idx_offset = field m680x_op_idx "offset" int16_t
let idx_offset_addr = field m680x_op_idx "offset_addr" uint16_t
let idx_offset_bits = field m680x_op_idx "offset_bits" uint8_t
let idx_inc_dec = field m680x_op_idx "inc_dec" int8_t
let idx_flags = field m680x_op_idx "flags" uint8_t
let _idx_pad = field m680x_op_idx "_pad" uint8_t
let () = seal m680x_op_idx

(* m680x_op_rel - Relative addressing operand
   Layout:
   - offset 0: address (uint16_t)
   - offset 2: offset (int16_t)
   Total size: 4 bytes
*)
type m680x_op_rel
let m680x_op_rel : m680x_op_rel structure typ = structure "m680x_op_rel"
let rel_address = field m680x_op_rel "address" uint16_t
let rel_offset = field m680x_op_rel "offset" int16_t
let () = seal m680x_op_rel

(* m680x_op_ext - Extended addressing operand
   Layout:
   - offset 0: address (uint16_t)
   - offset 2: indirect (bool, 1 byte + padding)
   Total size: 4 bytes (with padding)
*)
type m680x_op_ext
let m680x_op_ext : m680x_op_ext structure typ = structure "m680x_op_ext"
let ext_address = field m680x_op_ext "address" uint16_t
let ext_indirect = field m680x_op_ext "indirect" bool
let () = seal m680x_op_ext

(* cs_m680x_op - Single operand
   Layout:
   - offset 0: type (m680x_op_type, 4 bytes)
   - offset 4: union (16 bytes - largest is idx)
     - imm: int32_t (4 bytes)
     - reg: m680x_reg (4 bytes)
     - idx: m680x_op_idx (16 bytes)
     - rel: m680x_op_rel (4 bytes)
     - ext: m680x_op_ext (4 bytes)
     - direct_addr: uint8_t (1 byte)
     - const_val: uint8_t (1 byte)
   - offset 20: size (uint8_t)
   - offset 21: access (uint8_t)
   - offset 22: padding (2 bytes)
   Total size: 24 bytes
*)
type cs_m680x_op
let cs_m680x_op : cs_m680x_op structure typ = structure "cs_m680x_op"
let m680x_op_type = field cs_m680x_op "type" uint32_t
(* Union at offset 4 - reserve 16 bytes *)
let m680x_op_union = field cs_m680x_op "union" (array 2 int64_t)  (* 16 bytes *)
let m680x_op_size = field cs_m680x_op "size" uint8_t
let m680x_op_access = field cs_m680x_op "access" uint8_t
let _m680x_op_pad = field cs_m680x_op "_pad" (array 2 uint8_t)
let () = seal cs_m680x_op

(* Accessor functions for union members *)
let get_m680x_op_imm op =
  let union_arr = getf op m680x_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int32 (Int64.logand first_word 0xFFFFFFFFL)

let get_m680x_op_reg op =
  let union_arr = getf op m680x_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFFFFFFFL)

let get_m680x_op_idx op =
  let union_arr = getf op m680x_op_union in
  let w0 = CArray.get union_arr 0 in
  let w1 = CArray.get union_arr 1 in
  (* idx struct: base_reg(4), offset_reg(4), offset(2), offset_addr(2), offset_bits(1), inc_dec(1), flags(1), pad(1) *)
  let base_reg = Int64.to_int (Int64.logand w0 0xFFFFFFFFL) in
  let offset_reg = Int64.to_int (Int64.shift_right_logical w0 32) in
  let offset = Int64.to_int (Int64.logand w1 0xFFFFL) in
  let offset_addr = Int64.to_int (Int64.logand (Int64.shift_right_logical w1 16) 0xFFFFL) in
  let offset_bits = Int64.to_int (Int64.logand (Int64.shift_right_logical w1 32) 0xFFL) in
  let inc_dec = Int64.to_int (Int64.logand (Int64.shift_right_logical w1 40) 0xFFL) in
  let inc_dec = if inc_dec > 127 then inc_dec - 256 else inc_dec in  (* Convert to signed *)
  let flags = Int64.to_int (Int64.logand (Int64.shift_right_logical w1 48) 0xFFL) in
  (base_reg, offset_reg, offset, offset_addr, offset_bits, inc_dec, flags)

let get_m680x_op_rel op =
  let union_arr = getf op m680x_op_union in
  let first_word = CArray.get union_arr 0 in
  let address = Int64.to_int (Int64.logand first_word 0xFFFFL) in
  let offset = Int64.to_int (Int64.logand (Int64.shift_right_logical first_word 16) 0xFFFFL) in
  let offset = if offset > 32767 then offset - 65536 else offset in  (* Convert to signed *)
  (address, offset)

let get_m680x_op_ext op =
  let union_arr = getf op m680x_op_union in
  let first_word = CArray.get union_arr 0 in
  let address = Int64.to_int (Int64.logand first_word 0xFFFFL) in
  let indirect = Int64.to_int (Int64.logand (Int64.shift_right_logical first_word 16) 0xFFL) <> 0 in
  (address, indirect)

let get_m680x_op_direct_addr op =
  let union_arr = getf op m680x_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFL)

let get_m680x_op_const_val op =
  let union_arr = getf op m680x_op_union in
  let first_word = CArray.get union_arr 0 in
  Int64.to_int (Int64.logand first_word 0xFFL)

(* cs_m680x - M680X instruction detail
   Layout from m680x.h:
   - offset 0: flags (uint8_t)
   - offset 1: op_count (uint8_t)
   - offset 2: padding (2 bytes to align operands)
   - offset 4: padding (4 more bytes to align to 8)
   - offset 8: operands[9] (9 * 24 = 216 bytes)
   Total size: 224 bytes
*)
type cs_m680x
let cs_m680x : cs_m680x structure typ = structure "cs_m680x"
let m680x_flags = field cs_m680x "flags" uint8_t
let m680x_op_count = field cs_m680x "op_count" uint8_t
let _m680x_pad = field cs_m680x "_pad" (array 6 uint8_t)  (* padding to align operands *)
let m680x_operands = field cs_m680x "operands" (array 9 cs_m680x_op)
let () = seal cs_m680x

(* Operand type constants *)
module OpType = struct
  let invalid = 0
  let register = 1
  let immediate = 2
  let indexed = 3
  let extended = 4
  let direct = 5
  let relative = 6
  let constant = 7
end
