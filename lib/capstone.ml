(* Capstone OCaml Bindings - Modern ctypes-based implementation *)

open Ctypes

module Ffi = Capstone_ffi
module Types = Ffi.Types
module Bindings = Ffi.Bindings

(* Re-export constants and architecture modules *)
module Cs_const = Cs_const
module Aarch64_const = Aarch64_const
module X86_const = X86_const
module Aarch64 = Aarch64
module X86 = X86

(* Error type *)
type error =
  | Ok
  | Mem
  | Arch
  | Handle
  | Csh
  | Mode
  | Option
  | Detail
  | Memsetup
  | Version
  | Diet
  | Skipdata
  | X86_att
  | X86_intel
  | X86_masm

let error_of_int = function
  | 0 -> Ok
  | 1 -> Mem
  | 2 -> Arch
  | 3 -> Handle
  | 4 -> Csh
  | 5 -> Mode
  | 6 -> Option
  | 7 -> Detail
  | 8 -> Memsetup
  | 9 -> Version
  | 10 -> Diet
  | 11 -> Skipdata
  | 12 -> X86_att
  | 13 -> X86_intel
  | 14 -> X86_masm
  | _ -> failwith "Unknown error code"

exception Capstone_error of error

let () = Callback.register_exception "capstone_error" (Capstone_error Ok)

(* Basic instruction record - architecture independent *)
type insn = {
  id : int;
  address : int64;
  size : int;
  bytes : bytes;
  mnemonic : string;
  op_str : string;
}

(* Detailed instruction with architecture-specific info *)
type 'a detailed_insn = {
  insn : insn;
  regs_read : int array;
  regs_write : int array;
  groups : int array;
  arch_detail : 'a;
}

(* Internal handle representation *)
type handle = {
  h : Unsigned.size_t;
  arch : int;
}

(* Architecture GADT for type safety *)
module Arch = struct
  type 'a t =
    | AARCH64 : [> `AARCH64 ] t
    | X86_16 : [> `X86_16 ] t
    | X86_32 : [> `X86_32 ] t
    | X86_64 : [> `X86_64 ] t

  let to_arch_mode : type a. a t -> int * int = function
    | AARCH64 -> (Types.Arch.aarch64, Types.Mode.little_endian)
    | X86_16 -> (Types.Arch.x86, Types.Mode.mode_16)
    | X86_32 -> (Types.Arch.x86, Types.Mode.mode_32)
    | X86_64 -> (Types.Arch.x86, Types.Mode.mode_64)
end

(* Disassembler type with phantom type for architecture *)
type 'a t = handle

(* Get Capstone version *)
let version () =
  let major = allocate int 0 in
  let minor = allocate int 0 in
  let _ = Bindings.cs_version (Some major) (Some minor) in
  (!@ major, !@ minor)

(* Check if architecture is supported *)
let supports arch =
  Bindings.cs_support arch

(* Create a disassembler handle *)
let create : type a. a Arch.t -> (a t, error) result = fun arch ->
  let (arch_id, mode) = Arch.to_arch_mode arch in
  let handle_ptr = allocate size_t Unsigned.Size_t.zero in
  let err = Bindings.cs_open arch_id mode handle_ptr in
  if err = Types.Err.ok then
    Result.Ok { h = !@ handle_ptr; arch = arch_id }
  else
    Result.Error (error_of_int err)

(* Create, raising on error *)
let create_exn arch =
  match create arch with
  | Result.Ok h -> h
  | Result.Error e -> raise (Capstone_error e)

(* Close a handle *)
let close (handle : _ t) =
  let handle_ptr = allocate size_t handle.h in
  let err = Bindings.cs_close handle_ptr in
  if err <> Types.Err.ok then
    raise (Capstone_error (error_of_int err))

(* Set an option *)
let set_option (handle : _ t) opt_type value =
  let err = Bindings.cs_option handle.h opt_type (Unsigned.Size_t.of_int value) in
  if err <> Types.Err.ok then
    raise (Capstone_error (error_of_int err))

(* Enable detailed instruction information *)
let set_detail (handle : _ t) enabled =
  set_option handle Types.OptType.detail
    (if enabled then Types.OptValue.on else Types.OptValue.off)

(* Set syntax (for x86) *)
let set_syntax_intel (handle : _ t) =
  set_option handle Types.OptType.syntax Types.OptValue.syntax_intel

let set_syntax_att (handle : _ t) =
  set_option handle Types.OptType.syntax Types.OptValue.syntax_att

(* Convert cs_insn structure to OCaml record *)
let insn_of_cs_insn ptr =
  let mnemonic_arr = getf (!@ ptr) Types.insn_mnemonic in
  let op_str_arr = getf (!@ ptr) Types.insn_op_str in
  let bytes_arr = getf (!@ ptr) Types.insn_bytes in
  let size = Unsigned.UInt16.to_int (getf (!@ ptr) Types.insn_size) in
  {
    id = Unsigned.UInt32.to_int (getf (!@ ptr) Types.insn_id);
    address = Unsigned.UInt64.to_int64 (getf (!@ ptr) Types.insn_address);
    size;
    bytes = Types.uint8_array_to_bytes bytes_arr size;
    mnemonic = Types.char_array_to_string mnemonic_arr;
    op_str = Types.char_array_to_string op_str_arr;
  }

(* Disassemble binary code *)
let disasm ?(count=0) ~addr (handle : _ t) (code : bytes) : insn list =
  let code_len = Bytes.length code in
  let code_ptr = allocate_n uint8_t ~count:code_len in
  for i = 0 to code_len - 1 do
    (code_ptr +@ i) <-@ Unsigned.UInt8.of_int (Char.code (Bytes.get code i))
  done;

  let insn_ptr = allocate (ptr Types.cs_insn) (from_voidp Types.cs_insn null) in
  let num_insns = Bindings.cs_disasm
    handle.h
    code_ptr
    (Unsigned.Size_t.of_int code_len)
    (Unsigned.UInt64.of_int64 addr)
    (Unsigned.Size_t.of_int count)
    insn_ptr
  in

  let num = Unsigned.Size_t.to_int num_insns in
  if num = 0 then
    []
  else begin
    let insns_array = !@ insn_ptr in
    let result = List.init num (fun i ->
      insn_of_cs_insn (insns_array +@ i)
    ) in
    Bindings.cs_free insns_array num_insns;
    result
  end

(* Get register name *)
let reg_name (handle : _ t) reg_id =
  Bindings.cs_reg_name handle.h (Unsigned.UInt.of_int reg_id)

(* Get instruction name *)
let insn_name (handle : _ t) insn_id =
  Bindings.cs_insn_name handle.h (Unsigned.UInt.of_int insn_id)

(* Get group name *)
let group_name (handle : _ t) group_id =
  Bindings.cs_group_name handle.h (Unsigned.UInt.of_int group_id)

(* Get error string *)
let strerror err =
  let code = match err with
    | Ok -> 0 | Mem -> 1 | Arch -> 2 | Handle -> 3 | Csh -> 4
    | Mode -> 5 | Option -> 6 | Detail -> 7 | Memsetup -> 8
    | Version -> 9 | Diet -> 10 | Skipdata -> 11
    | X86_att -> 12 | X86_intel -> 13 | X86_masm -> 14
  in
  Bindings.cs_strerror code

(* Convenience function: disassemble with automatic handle management *)
let with_handle : type a. a Arch.t -> (a t -> 'b) -> ('b, error) result =
  fun arch f ->
    match create arch with
    | Result.Error e -> Result.Error e
    | Result.Ok handle ->
      let result = f handle in
      close handle;
      Result.Ok result

(* Disassemble a single block of code *)
let disassemble_block : type a. a Arch.t -> bytes -> addr:int64 -> (insn list, error) result =
  fun arch code ~addr ->
    with_handle arch (fun h -> disasm ~addr h code)

(* Convert cs_insn to detailed instruction for AArch64 *)
let detailed_insn_of_cs_insn_aarch64 ptr =
  let basic = insn_of_cs_insn ptr in
  let detail_opt = getf (!@ ptr) Types.insn_detail in
  match detail_opt with
  | None ->
    (* No detail available - return empty arrays *)
    {
      insn = basic;
      regs_read = [||];
      regs_write = [||];
      groups = [||];
      arch_detail = {
        Aarch64.cc = 0;
        update_flags = false;
        writeback = false;
        post_index = false;
        operands = [||];
      };
    }
  | Some detail_ptr ->
    let common = Aarch64.common_detail_of_cs_detail detail_ptr in
    let arch_detail = Aarch64.detail_of_cs_detail detail_ptr in
    {
      insn = basic;
      regs_read = common.regs_read;
      regs_write = common.regs_write;
      groups = common.groups;
      arch_detail;
    }

(* Disassemble with detailed information (AArch64) *)
let disasm_aarch64_detail ?(count=0) ~addr (handle : [> `AARCH64] t) (code : bytes)
    : Aarch64.detail detailed_insn list =
  let code_len = Bytes.length code in
  let code_ptr = allocate_n uint8_t ~count:code_len in
  for i = 0 to code_len - 1 do
    (code_ptr +@ i) <-@ Unsigned.UInt8.of_int (Char.code (Bytes.get code i))
  done;

  let insn_ptr = allocate (ptr Types.cs_insn) (from_voidp Types.cs_insn null) in
  let num_insns = Bindings.cs_disasm
    handle.h
    code_ptr
    (Unsigned.Size_t.of_int code_len)
    (Unsigned.UInt64.of_int64 addr)
    (Unsigned.Size_t.of_int count)
    insn_ptr
  in

  let num = Unsigned.Size_t.to_int num_insns in
  if num = 0 then
    []
  else begin
    let insns_array = !@ insn_ptr in
    let result = List.init num (fun i ->
      detailed_insn_of_cs_insn_aarch64 (insns_array +@ i)
    ) in
    Bindings.cs_free insns_array num_insns;
    result
  end

(* Convert cs_insn to detailed instruction for x86 *)
let detailed_insn_of_cs_insn_x86 ptr =
  let basic = insn_of_cs_insn ptr in
  let detail_opt = getf (!@ ptr) Types.insn_detail in
  match detail_opt with
  | None ->
    (* No detail available - return empty arrays *)
    {
      insn = basic;
      regs_read = [||];
      regs_write = [||];
      groups = [||];
      arch_detail = {
        X86.prefix = [|0;0;0;0|];
        opcode = [|0;0;0;0|];
        rex = 0;
        addr_size = 0;
        modrm = 0;
        sib = 0;
        disp = 0L;
        sib_index = 0;
        sib_scale = 0;
        sib_base = 0;
        xop_cc = 0;
        sse_cc = 0;
        avx_cc = 0;
        avx_sae = false;
        avx_rm = 0;
        eflags = 0L;
        operands = [||];
      };
    }
  | Some detail_ptr ->
    let common = X86.common_detail_of_cs_detail detail_ptr in
    let arch_detail = X86.detail_of_cs_detail detail_ptr in
    {
      insn = basic;
      regs_read = common.regs_read;
      regs_write = common.regs_write;
      groups = common.groups;
      arch_detail;
    }

(* Disassemble with detailed information (x86) *)
let disasm_x86_detail ?(count=0) ~addr (handle : [> `X86_16 | `X86_32 | `X86_64] t) (code : bytes)
    : X86.detail detailed_insn list =
  let code_len = Bytes.length code in
  let code_ptr = allocate_n uint8_t ~count:code_len in
  for i = 0 to code_len - 1 do
    (code_ptr +@ i) <-@ Unsigned.UInt8.of_int (Char.code (Bytes.get code i))
  done;

  let insn_ptr = allocate (ptr Types.cs_insn) (from_voidp Types.cs_insn null) in
  let num_insns = Bindings.cs_disasm
    handle.h
    code_ptr
    (Unsigned.Size_t.of_int code_len)
    (Unsigned.UInt64.of_int64 addr)
    (Unsigned.Size_t.of_int count)
    insn_ptr
  in

  let num = Unsigned.Size_t.to_int num_insns in
  if num = 0 then
    []
  else begin
    let insns_array = !@ insn_ptr in
    let result = List.init num (fun i ->
      detailed_insn_of_cs_insn_x86 (insns_array +@ i)
    ) in
    Bindings.cs_free insns_array num_insns;
    result
  end
