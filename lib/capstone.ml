open Ctypes

module Ffi = Capstone_ffi
module Types = Ffi.Types
module Bindings = Ffi.Bindings

(* Re-export constants and architecture modules *)
module Cs_const = Cs_const
module Aarch64_const = Aarch64_const
module Arm_const = Arm_const
module X86_const = X86_const
module Riscv_const = Riscv_const
module Ppc_const = Ppc_const
module Sysz_const = Sysz_const
module Aarch64 = Aarch64
module Arm = Arm
module X86 = X86
module Riscv = Riscv
module Ppc = Ppc
module Sysz = Sysz

type error =
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
  | n -> failwith (Printf.sprintf "Unknown error code: %d" n)

exception Capstone_error of error

let () = Callback.register_exception "capstone_error" (Capstone_error Mem)

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
    | ARM : [> `ARM ] t
    | ARM_BE : [> `ARM_BE ] t
    | THUMB : [> `THUMB ] t
    | THUMB_BE : [> `THUMB_BE ] t
    | THUMB_MCLASS : [> `THUMB_MCLASS ] t
    | ARMV8 : [> `ARMV8 ] t
    | X86_16 : [> `X86_16 ] t
    | X86_32 : [> `X86_32 ] t
    | X86_64 : [> `X86_64 ] t
    | RISCV32 : [> `RISCV32 ] t
    | RISCV64 : [> `RISCV64 ] t
    | PPC32 : [> `PPC32 ] t
    | PPC64 : [> `PPC64 ] t
    | PPC64LE : [> `PPC64LE ] t
    | SYSZ : [> `SYSZ ] t

  let to_arch_mode : type a. a t -> int * int = function
    | AARCH64 -> (Types.Arch.aarch64, Types.Mode.little_endian)
    | ARM -> (Types.Arch.arm, Types.Mode.arm)
    | ARM_BE -> (Types.Arch.arm, Types.Mode.arm lor Types.Mode.big_endian)
    | THUMB -> (Types.Arch.arm, Types.Mode.thumb)
    | THUMB_BE -> (Types.Arch.arm, Types.Mode.thumb lor Types.Mode.big_endian)
    | THUMB_MCLASS -> (Types.Arch.arm, Types.Mode.thumb lor Types.Mode.mclass)
    | ARMV8 -> (Types.Arch.arm, Types.Mode.arm lor Types.Mode.v8)
    | X86_16 -> (Types.Arch.x86, Types.Mode.mode_16)
    | X86_32 -> (Types.Arch.x86, Types.Mode.mode_32)
    | X86_64 -> (Types.Arch.x86, Types.Mode.mode_64)
    | RISCV32 -> (Types.Arch.riscv, Types.Mode.riscv32)
    | RISCV64 -> (Types.Arch.riscv, Types.Mode.riscv64)
    | PPC32 -> (Types.Arch.ppc, Types.Mode.ppc32 lor Types.Mode.big_endian)
    | PPC64 -> (Types.Arch.ppc, Types.Mode.ppc64 lor Types.Mode.big_endian)
    | PPC64LE -> (Types.Arch.ppc, Types.Mode.ppc64)
    | SYSZ -> (Types.Arch.sysz, Types.Mode.big_endian)
end

(* Disassembler type with phantom type for architecture *)
type 'a t = handle

(* Get Capstone version *)
let version () =
  let major = allocate int 0 in
  let minor = allocate int 0 in
  let _ = Bindings.cs_version (Some major) (Some minor) in (* TODO Why is this here? *)
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

let set_syntax_intel (handle : _ t) =
  set_option handle Types.OptType.syntax Types.OptValue.syntax_intel

let set_syntax_att (handle : _ t) =
  set_option handle Types.OptType.syntax Types.OptValue.syntax_att

(* Runtime mode switching *)
module Mode = struct
  (* ARM modes *)
  type arm =
    | ARM           (* 32-bit ARM *)
    | Thumb         (* Thumb mode *)
    | Thumb_MClass  (* Thumb + Cortex-M *)
    | ARMv8         (* ARMv8 A32 *)

  let arm_to_int = function
    | ARM -> Types.Mode.arm
    | Thumb -> Types.Mode.thumb
    | Thumb_MClass -> Types.Mode.thumb lor Types.Mode.mclass
    | ARMv8 -> Types.Mode.arm lor Types.Mode.v8

  (* x86 modes *)
  type x86 =
    | Mode_16  (* 16-bit real mode *)
    | Mode_32  (* 32-bit protected mode *)
    | Mode_64  (* 64-bit long mode *)

  let x86_to_int = function
    | Mode_16 -> Types.Mode.mode_16
    | Mode_32 -> Types.Mode.mode_32
    | Mode_64 -> Types.Mode.mode_64

end

(* Set ARM mode at runtime *)
let set_mode_arm (handle : [> `ARM | `ARM_BE | `THUMB | `THUMB_BE | `THUMB_MCLASS | `ARMV8] t) mode =
  set_option handle Types.OptType.mode (Mode.arm_to_int mode)

(* Set x86 mode at runtime *)
let set_mode_x86 (handle : [> `X86_16 | `X86_32 | `X86_64] t) mode =
  set_option handle Types.OptType.mode (Mode.x86_to_int mode)

(* Enable or disable SKIPDATA mode *)
let set_skipdata (handle : _ t) enabled =
  set_option handle Types.OptType.skipdata
    (if enabled then Types.OptValue.on else Types.OptValue.off)

(* Configure SKIPDATA with custom mnemonic.
   This enables SKIPDATA mode and sets the mnemonic for skipped bytes.
   The mnemonic string must remain valid for the lifetime of the handle.
   Pass None to use the default ".byte" mnemonic. *)
let set_skipdata_mnemonic (handle : _ t) mnemonic =
  set_skipdata handle true;
  match mnemonic with
  | None -> ()
  | Some mnem ->
    let skipdata_setup = make Types.cs_opt_skipdata in

    let mnem_cstr = CArray.of_string mnem in
    setf skipdata_setup Types.skipdata_mnemonic (CArray.start mnem_cstr);
    setf skipdata_setup Types.skipdata_callback (Ctypes.null);
    setf skipdata_setup Types.skipdata_user_data (Ctypes.null);
    let ptr_val = Ctypes.raw_address_of_ptr (Ctypes.to_voidp (addr skipdata_setup)) in
    let err = Bindings.cs_option handle.h Types.OptType.skipdata_setup
      (Unsigned.Size_t.of_int64 (Int64.of_nativeint ptr_val)) in
    if err <> Types.Err.ok then
      raise (Capstone_error (error_of_int err))

(* Set custom mnemonic for a specific instruction *)
let set_mnemonic (handle : _ t) ~insn_id mnemonic =
  let opt_mnem = make Types.cs_opt_mnem in
  setf opt_mnem Types.mnem_id (Unsigned.UInt32.of_int insn_id);
  (match mnemonic with
   | None ->
     setf opt_mnem Types.mnem_mnemonic (Ctypes.from_voidp Ctypes.char Ctypes.null)
   | Some mnem ->
     let mnem_cstr = CArray.of_string mnem in
     setf opt_mnem Types.mnem_mnemonic (CArray.start mnem_cstr));
  let ptr_val = Ctypes.raw_address_of_ptr (Ctypes.to_voidp (addr opt_mnem)) in
  let err = Bindings.cs_option handle.h Types.OptType.mnemonic
    (Unsigned.Size_t.of_int64 (Int64.of_nativeint ptr_val)) in
  if err <> Types.Err.ok then
    raise (Capstone_error (error_of_int err))

(* Reset a custom mnemonic back to default *)
let reset_mnemonic (handle : _ t) ~insn_id =
  set_mnemonic handle ~insn_id None

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
let disasm ?(count=0) ~addr (handle : _ t) code =
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
    | Mem -> 1 | Arch -> 2 | Handle -> 3 | Csh -> 4
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

(* Sum type for architecture-specific details *)
type arch_detail =
  | Aarch64_detail of Aarch64.detail
  | Arm_detail of Arm.detail
  | X86_detail of X86.detail
  | Riscv_detail of Riscv.detail
  | Ppc_detail of Ppc.detail
  | Sysz_detail of Sysz.detail

(* Detailed instruction with architecture-agnostic detail *)
type any_detailed_insn = {
  insn : insn;
  regs_read : int array;
  regs_write : int array;
  groups : int array;
  detail : arch_detail;
}

(* Internal: convert cs_insn to any_detailed_insn based on architecture *)
let any_detailed_insn_of_cs_insn ~arch ptr =
  let basic = insn_of_cs_insn ptr in
  let detail_opt = getf (!@ ptr) Types.insn_detail in
  match detail_opt with
  | None ->
    (* No detail available - return empty detail based on arch *)
    let detail = match arch with
      | a when a = Types.Arch.aarch64 -> Aarch64_detail Aarch64.empty_detail
      | a when a = Types.Arch.arm -> Arm_detail Arm.empty_detail
      | a when a = Types.Arch.x86 -> X86_detail X86.empty_detail
      | a when a = Types.Arch.riscv -> Riscv_detail Riscv.empty_detail
      | a when a = Types.Arch.ppc -> Ppc_detail Ppc.empty_detail
      | a when a = Types.Arch.sysz -> Sysz_detail Sysz.empty_detail
      | _ -> failwith "Unsupported architecture"
    in
    {
      insn = basic;
      regs_read = [||];
      regs_write = [||];
      groups = [||];
      detail;
    }
  | Some detail_ptr ->
    (* Use aarch64's common_detail since the layout is shared *)
    let common = Aarch64.common_detail_of_cs_detail detail_ptr in
    let detail = match arch with
      | a when a = Types.Arch.aarch64 ->
        Aarch64_detail (Aarch64.detail_of_cs_detail detail_ptr)
      | a when a = Types.Arch.arm ->
        Arm_detail (Arm.detail_of_cs_detail detail_ptr)
      | a when a = Types.Arch.x86 ->
        X86_detail (X86.detail_of_cs_detail detail_ptr)
      | a when a = Types.Arch.riscv ->
        Riscv_detail (Riscv.detail_of_cs_detail detail_ptr)
      | a when a = Types.Arch.ppc ->
        Ppc_detail (Ppc.detail_of_cs_detail detail_ptr)
      | a when a = Types.Arch.sysz ->
        Sysz_detail (Sysz.detail_of_cs_detail detail_ptr)
      | _ -> failwith "Unsupported architecture"
    in
    {
      insn = basic;
      regs_read = common.regs_read;
      regs_write = common.regs_write;
      groups = common.groups;
      detail;
    }

(* Internal: shared disassembly implementation for detailed instructions *)
let disasm_detail_internal ?(count=0) ~addr handle code =
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
      any_detailed_insn_of_cs_insn ~arch:handle.arch (insns_array +@ i)
    ) in
    Bindings.cs_free insns_array num_insns;
    result
  end

(* Unified disassembly with architecture-agnostic detailed information *)
let disasm_detail ?(count=0) ~addr handle code =
  disasm_detail_internal ~count ~addr handle code

(* Helper to convert any_detailed_insn to typed detailed_insn *)
let to_aarch64_detail any =
  match any.detail with
  | Aarch64_detail d ->
    { insn = any.insn; regs_read = any.regs_read;
      regs_write = any.regs_write; groups = any.groups; arch_detail = d }
  | _ -> failwith "Expected AArch64 detail"

let to_arm_detail any =
  match any.detail with
  | Arm_detail d ->
    { insn = any.insn; regs_read = any.regs_read;
      regs_write = any.regs_write; groups = any.groups; arch_detail = d }
  | _ -> failwith "Expected ARM detail"

let to_x86_detail any =
  match any.detail with
  | X86_detail d ->
    { insn = any.insn; regs_read = any.regs_read;
      regs_write = any.regs_write; groups = any.groups; arch_detail = d }
  | _ -> failwith "Expected x86 detail"

let to_riscv_detail any =
  match any.detail with
  | Riscv_detail d ->
    { insn = any.insn; regs_read = any.regs_read;
      regs_write = any.regs_write; groups = any.groups; arch_detail = d }
  | _ -> failwith "Expected RISC-V detail"

let to_ppc_detail any =
  match any.detail with
  | Ppc_detail d ->
    { insn = any.insn; regs_read = any.regs_read;
      regs_write = any.regs_write; groups = any.groups; arch_detail = d }
  | _ -> failwith "Expected PowerPC detail"

let to_sysz_detail any =
  match any.detail with
  | Sysz_detail d ->
    { insn = any.insn; regs_read = any.regs_read;
      regs_write = any.regs_write; groups = any.groups; arch_detail = d }
  | _ -> failwith "Expected SystemZ detail"

(* Disassemble with detailed information (AArch64) *)
let disasm_aarch64_detail ?(count=0) ~addr (handle : [> `AARCH64] t) code =
  disasm_detail_internal ~count ~addr handle code
  |> List.map to_aarch64_detail

(* Disassemble with detailed information (x86) *)
let disasm_x86_detail ?(count=0) ~addr (handle : [> `X86_16 | `X86_32 | `X86_64] t) code =
  disasm_detail_internal ~count ~addr handle code
  |> List.map to_x86_detail

(* Disassemble with detailed information (RISC-V) *)
let disasm_riscv_detail ?(count=0) ~addr (handle : [> `RISCV32 | `RISCV64] t) code =
  disasm_detail_internal ~count ~addr handle code
  |> List.map to_riscv_detail

(* Disassemble with detailed information (Power) *)
let disasm_ppc_detail ?(count=0) ~addr (handle : [> `PPC32 | `PPC64 | `PPC64LE] t) code =
  disasm_detail_internal ~count ~addr handle code
  |> List.map to_ppc_detail

(* Disassemble with detailed information (SystemZ) *)
let disasm_sysz_detail ?(count=0) ~addr (handle : [> `SYSZ] t) code =
  disasm_detail_internal ~count ~addr handle code
  |> List.map to_sysz_detail

(* Disassemble with detailed information (ARM 32-bit) *)
let disasm_arm_detail ?(count=0) ~addr (handle : [> `ARM | `ARM_BE | `THUMB | `THUMB_BE | `THUMB_MCLASS | `ARMV8] t) code =
  disasm_detail_internal ~count ~addr handle code
  |> List.map to_arm_detail

(* Get all registers accessed by an instruction (both explicit and implicit) *)
type regs_access = {
  regs_read : int array;
  regs_write : int array;
}

(* Low-level function that takes a raw cs_insn pointer *)
let regs_access_raw (handle : _ t) insn_ptr =
  let regs_read = CArray.make Ctypes.uint16_t 64 in
  let regs_write = CArray.make Ctypes.uint16_t 64 in
  let read_count = allocate uint8_t (Unsigned.UInt8.of_int 0) in
  let write_count = allocate uint8_t (Unsigned.UInt8.of_int 0) in
  let err = Bindings.cs_regs_access
    handle.h
    insn_ptr
    (CArray.start regs_read)
    read_count
    (CArray.start regs_write)
    write_count
  in
  if err = Types.Err.ok then begin
    let read_n = Unsigned.UInt8.to_int (!@ read_count) in
    let write_n = Unsigned.UInt8.to_int (!@ write_count) in
    let regs_read_arr = Array.init read_n (fun i ->
      Unsigned.UInt16.to_int (CArray.get regs_read i)
    ) in
    let regs_write_arr = Array.init write_n (fun i ->
      Unsigned.UInt16.to_int (CArray.get regs_write i)
    ) in
    Result.Ok { regs_read = regs_read_arr; regs_write = regs_write_arr }
  end else
    Result.Error (error_of_int err)

(* Disassemble and get register access for each instruction *)
let disasm_with_regs_access ?(count=0) ~addr (handle : _ t) code =
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
      let ptr = insns_array +@ i in
      let basic = insn_of_cs_insn ptr in
      let regs = match regs_access_raw handle ptr with
        | Result.Ok r -> r
        | Result.Error _ -> { regs_read = [||]; regs_write = [||] }
      in
      (basic, regs)
    ) in
    Bindings.cs_free insns_array num_insns;
    result
  end
