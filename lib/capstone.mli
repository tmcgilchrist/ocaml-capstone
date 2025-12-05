(** Capstone Disassembly Framework for OCaml

    Capstone is a lightweight multi-platform, multi-architecture disassembly
    framework. This module provides OCaml bindings with a type-safe API.

    {2 Quick Start}

    {[
      (* Disassemble some x86-64 code *)
      let code = Bytes.of_string "\x55\x48\x89\xe5" in
      match Capstone.create Capstone.Arch.X86_64 with
      | Ok handle ->
        let insns = Capstone.disasm ~addr:0x1000L handle code in
        List.iter (fun i ->
          Printf.printf "%Lx: %s %s\n" i.address i.mnemonic i.op_str
        ) insns;
        Capstone.close handle
      | Error e ->
        Printf.eprintf "Error: %s\n" (Capstone.strerror e)
    ]}

    {2 Supported Architectures}

    - AArch64 (ARM 64-bit)
    - ARM (32-bit, including Thumb modes)
    - x86 (16/32/64-bit)
    - RISC-V (32/64-bit)
    - PowerPC (32/64-bit, big/little endian)
    - SystemZ (s390x)
    - SPARC (32/64-bit)

    @see <https://www.capstone-engine.org/> Capstone Engine website
*)

(** {1 Re-exported Modules}

    Architecture-specific constants and detail types are available through
    these submodules.
*)

module Cs_const = Cs_const
(** Core Capstone constants (error codes, architectures, modes) *)

module Aarch64_const = Aarch64_const
(** AArch64 architecture constants (registers, instructions, groups) *)

module Arm_const = Arm_const
(** ARM 32-bit architecture constants *)

module X86_const = X86_const
(** x86 architecture constants *)

module Riscv_const = Riscv_const
(** RISC-V architecture constants *)

module Ppc_const = Ppc_const
(** PowerPC architecture constants *)

module Sysz_const = Sysz_const
(** SystemZ architecture constants *)

module Sparc_const = Sparc_const
(** SPARC architecture constants *)

module Aarch64 = Aarch64
(** AArch64 instruction detail types *)

module Arm = Arm
(** ARM 32-bit instruction detail types *)

module X86 = X86
(** x86 instruction detail types *)

module Riscv = Riscv
(** RISC-V instruction detail types *)

module Ppc = Ppc
(** PowerPC instruction detail types *)

module Sysz = Sysz
(** SystemZ instruction detail types *)

module Sparc = Sparc
(** SPARC instruction detail types *)

(** {1 Error Handling} *)

(** Error codes returned by Capstone operations.

    These correspond to Capstone's [cs_err] values (excluding [CS_ERR_OK],
    which is represented by [Result.Ok] instead). *)
type error =
  | Mem         (** Out of memory *)
  | Arch        (** Unsupported architecture *)
  | Handle      (** Invalid handle *)
  | Csh         (** Invalid csh argument *)
  | Mode        (** Invalid/unsupported mode *)
  | Option      (** Invalid/unsupported option *)
  | Detail      (** Information unavailable in diet engine *)
  | Memsetup    (** Dynamic memory management uninitialized *)
  | Version     (** Unsupported version (bindings) *)
  | Diet        (** Information unavailable in diet engine *)
  | Skipdata    (** Access irrelevant data in skipdata mode *)
  | X86_att     (** X86 AT&T syntax unsupported *)
  | X86_intel   (** X86 Intel syntax unsupported *)
  | X86_masm    (** X86 MASM syntax unsupported *)

(** Exception raised by functions that don't return [Result.t] *)
exception Capstone_error of error

(** Convert error to human-readable string *)
val strerror : error -> string

(** {1 Types} *)

(** Basic disassembled instruction.

    Contains the essential information about a single instruction without
    architecture-specific details. *)
type insn = {
  id : int;           (** Instruction ID (architecture-specific) *)
  address : int64;    (** Address of this instruction *)
  size : int;         (** Size of this instruction in bytes *)
  bytes : bytes;      (** Raw bytes of this instruction *)
  mnemonic : string;  (** Instruction mnemonic (e.g., "mov", "add") *)
  op_str : string;    (** Operand string (e.g., "eax, ebx") *)
}

(** Detailed instruction with architecture-specific information.

    The ['a] type parameter represents the architecture-specific detail type
    (e.g., {!Aarch64.detail}, {!X86.detail}). *)
type 'a detailed_insn = {
  insn : insn;              (** Basic instruction info *)
  regs_read : int array;    (** Implicit registers read *)
  regs_write : int array;   (** Implicit registers written *)
  groups : int array;       (** Instruction groups this belongs to *)
  arch_detail : 'a;         (** Architecture-specific details *)
}

(** Register access information for an instruction *)
type regs_access = {
  regs_read : int array;    (** All registers read (implicit + explicit) *)
  regs_write : int array;   (** All registers written (implicit + explicit) *)
}

(** {2 Architecture-Agnostic Details}

    These types allow working with detailed instructions without knowing
    the specific architecture at compile time. Useful for tools that process
    multiple architectures dynamically. *)

(** Sum type containing architecture-specific instruction details.

    Use pattern matching to extract the appropriate detail type:
    {[
      match insn.detail with
      | Aarch64_detail d -> (* access d.operands, d.cc, etc. *)
      | X86_detail d -> (* access d.rex, d.prefix, etc. *)
      | _ -> ()
    ]} *)
type arch_detail =
  | Aarch64_detail of Aarch64.detail
  | Arm_detail of Arm.detail
  | X86_detail of X86.detail
  | Riscv_detail of Riscv.detail
  | Ppc_detail of Ppc.detail
  | Sysz_detail of Sysz.detail
  | Sparc_detail of Sparc.detail

(** Detailed instruction with architecture-agnostic detail type.

    Unlike {!detailed_insn}, this type doesn't require knowing the
    architecture at compile time. The architecture is determined at
    runtime based on the handle used for disassembly. *)
type any_detailed_insn = {
  insn : insn;              (** Basic instruction info *)
  regs_read : int array;    (** Implicit registers read *)
  regs_write : int array;   (** Implicit registers written *)
  groups : int array;       (** Instruction groups this belongs to *)
  detail : arch_detail;     (** Architecture-specific details (sum type) *)
}

(** {1 Architecture Selection}

    Use the {!module-Arch} module to select the target architecture when creating
    a disassembler handle. The type system ensures you can only use
    architecture-appropriate functions. *)

module Arch : sig
  (** Architecture selector with phantom type for type safety.

      The phantom type parameter ensures that architecture-specific functions
      can only be called with compatible handles. *)
  type 'a t =
    | AARCH64 : [> `AARCH64 ] t
        (** ARM 64-bit (little endian) *)
    | ARM : [> `ARM ] t
        (** ARM 32-bit (little endian) *)
    | ARM_BE : [> `ARM_BE ] t
        (** ARM 32-bit (big endian) *)
    | THUMB : [> `THUMB ] t
        (** ARM Thumb mode (little endian) *)
    | THUMB_BE : [> `THUMB_BE ] t
        (** ARM Thumb mode (big endian) *)
    | THUMB_MCLASS : [> `THUMB_MCLASS ] t
        (** ARM Thumb Cortex-M series *)
    | ARMV8 : [> `ARMV8 ] t
        (** ARMv8 A32 encoding *)
    | X86_16 : [> `X86_16 ] t
        (** x86 16-bit real mode *)
    | X86_32 : [> `X86_32 ] t
        (** x86 32-bit protected mode *)
    | X86_64 : [> `X86_64 ] t
        (** x86 64-bit long mode *)
    | RISCV32 : [> `RISCV32 ] t
        (** RISC-V 32-bit *)
    | RISCV64 : [> `RISCV64 ] t
        (** RISC-V 64-bit *)
    | PPC32 : [> `PPC32 ] t
        (** PowerPC 32-bit (big endian) *)
    | PPC64 : [> `PPC64 ] t
        (** PowerPC 64-bit (big endian) *)
    | PPC64LE : [> `PPC64LE ] t
        (** PowerPC 64-bit (little endian) *)
    | SYSZ : [> `SYSZ ] t
        (** SystemZ (s390x) *)
    | SPARC : [> `SPARC ] t
        (** SPARC 32-bit (big endian) *)
    | SPARC64 : [> `SPARC64 ] t
        (** SPARC 64-bit / V9 (big endian) *)
end

(** {1 Runtime Mode Switching}

    Use the {!module-Mode} module types with {!set_mode_arm} or {!set_mode_x86} to
    switch disassembly modes at runtime without creating a new handle. *)
module Mode : sig
  (** ARM 32-bit execution modes *)
  type arm =
    | ARM          (** 32-bit ARM mode *)
    | Thumb        (** Thumb mode (16/32-bit) *)
    | Thumb_MClass (** Thumb mode for Cortex-M *)
    | ARMv8        (** ARMv8 A32 encoding *)

  (** x86 execution modes *)
  type x86 =
    | Mode_16  (** 16-bit real mode *)
    | Mode_32  (** 32-bit protected mode *)
    | Mode_64  (** 64-bit long mode *)
end

(** {1 Disassembler Handle} *)

(** Disassembler handle. *)
type 'a t

(** {1 Core Functions} *)

(** Get the Capstone library version.

    @return [(major, minor)] version tuple *)
val version : unit -> int * int

(** Check if an architecture is supported.

    @param arch Architecture ID from {!Cs_const}
    @return [true] if the architecture is compiled into Capstone *)
val supports : int -> bool

(** Create a new disassembler handle.

    {[
      match Capstone.create Capstone.Arch.X86_64 with
      | Ok handle -> (* use handle *)
      | Error e -> (* handle error *)
    ]}

    @param arch Architecture selector from {!module-Arch}
    @return [Ok handle] on success, [Error e] on failure *)
val create : 'a Arch.t -> ('a t, error) result

(** Create a new disassembler handle, raising on error.

    @param arch Architecture selector
    @return Disassembler handle
    @raise Capstone_error on failure *)
val create_exn : 'a Arch.t -> 'a t

(** Close a disassembler handle and free resources.

    @param handle Handle to close
    @raise Capstone_error on failure *)
val close : 'a t -> unit

(** {1 Disassembly Functions} *)

(** Disassemble binary code into instructions.

    {[
      let insns = Capstone.disasm ~addr:0x1000L handle code in
      List.iter (fun i -> Printf.printf "%s %s\n" i.mnemonic i.op_str) insns
    ]}

    @param count Maximum number of instructions to disassemble (0 = all)
    @param addr Starting address for the first instruction
    @param handle Disassembler handle
    @param code Binary code to disassemble
    @return List of disassembled instructions *)
val disasm : ?count:int -> addr:int64 -> 'a t -> bytes -> insn list

(** Disassemble with AArch64 architecture-specific details.

    Requires {!set_detail} to be enabled on the handle.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle AArch64-compatible handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_aarch64_detail :
  ?count:int -> addr:int64 -> [> `AARCH64 ] t -> bytes ->
  Aarch64.detail detailed_insn list

(** Disassemble with ARM 32-bit architecture-specific details.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle ARM-compatible handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_arm_detail :
  ?count:int -> addr:int64 ->
  [> `ARM | `ARM_BE | `THUMB | `THUMB_BE | `THUMB_MCLASS | `ARMV8 ] t -> bytes ->
  Arm.detail detailed_insn list

(** Disassemble with x86 architecture-specific details.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle x86-compatible handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_x86_detail :
  ?count:int -> addr:int64 -> [> `X86_16 | `X86_32 | `X86_64 ] t -> bytes ->
  X86.detail detailed_insn list

(** Disassemble with RISC-V architecture-specific details.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle RISC-V compatible handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_riscv_detail :
  ?count:int -> addr:int64 -> [> `RISCV32 | `RISCV64 ] t -> bytes ->
  Riscv.detail detailed_insn list

(** Disassemble with PowerPC architecture-specific details.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle PowerPC-compatible handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_ppc_detail :
  ?count:int -> addr:int64 -> [> `PPC32 | `PPC64 | `PPC64LE ] t -> bytes ->
  Ppc.detail detailed_insn list

(** Disassemble with SystemZ architecture-specific details.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle SystemZ handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_sysz_detail :
  ?count:int -> addr:int64 -> [> `SYSZ ] t -> bytes ->
  Sysz.detail detailed_insn list

(** Disassemble with SPARC architecture-specific details.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle SPARC-compatible handle
    @param code Binary code
    @return List of detailed instructions *)
val disasm_sparc_detail :
  ?count:int -> addr:int64 -> [> `SPARC | `SPARC64 ] t -> bytes ->
  Sparc.detail detailed_insn list

(** {2 Architecture-Agnostic Detailed Disassembly} *)

(** Disassemble with architecture-agnostic detailed information.

    This function works with any architecture and returns details wrapped
    in the {!arch_detail} sum type. Useful for tools that need to process
    multiple architectures without knowing them at compile time.

    {[
      let insns = Capstone.disasm_detail ~addr:0x1000L handle code in
      List.iter (fun i ->
        Printf.printf "%s %s\n" i.insn.mnemonic i.insn.op_str;
        match i.detail with
        | X86_detail d -> Printf.printf "  rex: 0x%x\n" d.rex
        | Aarch64_detail d -> Printf.printf "  cc: %d\n" d.cc
        | _ -> ()
      ) insns
    ]}

    Requires {!set_detail} to be enabled on the handle.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle Disassembler handle (any architecture)
    @param code Binary code
    @return List of detailed instructions with sum-typed details *)
val disasm_detail :
  ?count:int -> addr:int64 -> 'a t -> bytes -> any_detailed_insn list

(** {2 Detail Conversion Helpers}

    These functions convert {!any_detailed_insn} to typed {!detailed_insn}.
    They raise [Failure] if the architecture doesn't match. *)

(** Convert to AArch64-typed detail. Raises if not AArch64. *)
val to_aarch64_detail : any_detailed_insn -> Aarch64.detail detailed_insn

(** Convert to ARM-typed detail. Raises if not ARM. *)
val to_arm_detail : any_detailed_insn -> Arm.detail detailed_insn

(** Convert to x86-typed detail. Raises if not x86. *)
val to_x86_detail : any_detailed_insn -> X86.detail detailed_insn

(** Convert to RISC-V-typed detail. Raises if not RISC-V. *)
val to_riscv_detail : any_detailed_insn -> Riscv.detail detailed_insn

(** Convert to PowerPC-typed detail. Raises if not PowerPC. *)
val to_ppc_detail : any_detailed_insn -> Ppc.detail detailed_insn

(** Convert to SystemZ-typed detail. Raises if not SystemZ. *)
val to_sysz_detail : any_detailed_insn -> Sysz.detail detailed_insn

(** Convert to SPARC-typed detail. Raises if not SPARC. *)
val to_sparc_detail : any_detailed_insn -> Sparc.detail detailed_insn

(** Disassemble and get all registers accessed by each instruction.

    This uses [cs_regs_access] to get both implicit and explicit register
    accesses. Requires {!set_detail} to be enabled.

    @param count Maximum instructions (0 = all)
    @param addr Starting address
    @param handle Disassembler handle
    @param code Binary code
    @return List of (instruction, register access) pairs *)
val disasm_with_regs_access :
  ?count:int -> addr:int64 -> 'a t -> bytes -> (insn * regs_access) list

(** {1 Configuration} *)

(** Enable or disable detailed instruction information.

    When enabled, disassembly functions will populate register, group,
    and architecture-specific detail fields. This has a performance cost.

    @param handle Disassembler handle
    @param enabled [true] to enable, [false] to disable *)
val set_detail : 'a t -> bool -> unit

(** Set x86 syntax to Intel format (default).

    Example: [mov eax, [ebx + 4]]

    @param handle x86-compatible handle *)
val set_syntax_intel : 'a t -> unit

(** Set x86 syntax to AT&T format.

    Example: [movl 4(%ebx), %eax]

    @param handle x86-compatible handle *)
val set_syntax_att : 'a t -> unit

(** {2 SKIPDATA Mode}

    SKIPDATA mode allows disassembly to continue past invalid byte sequences
    by emitting pseudo-instructions for unrecognized data. *)

(** Enable or disable SKIPDATA mode.

    When enabled, invalid bytes produce [.byte] pseudo-instructions instead
    of stopping disassembly.

    @param handle Disassembler handle
    @param enabled [true] to enable, [false] to disable *)
val set_skipdata : 'a t -> bool -> unit

(** Enable SKIPDATA mode with optional custom mnemonic.

    @param handle Disassembler handle
    @param mnemonic [Some "db"] for custom mnemonic, [None] for default [.byte] *)
val set_skipdata_mnemonic : 'a t -> string option -> unit

(** {2 Runtime Mode Switching}

    Switch between execution modes at runtime without creating a new handle.
    Essential for analyzing code with mode transitions. *)

(** Switch ARM mode at runtime.

    {[
      (* Switch from ARM to Thumb when encountering BX instruction *)
      Capstone.set_mode_arm handle Capstone.Mode.Thumb
    ]}

    @param handle ARM-compatible handle
    @param mode New ARM execution mode *)
val set_mode_arm :
  [> `ARM | `ARM_BE | `THUMB | `THUMB_BE | `THUMB_MCLASS | `ARMV8 ] t ->
  Mode.arm -> unit

(** Switch x86 mode at runtime.

    {[
      (* Switch from real mode to protected mode *)
      Capstone.set_mode_x86 handle Capstone.Mode.Mode_32
    ]}

    @param handle x86-compatible handle
    @param mode New x86 execution mode *)
val set_mode_x86 : [> `X86_16 | `X86_32 | `X86_64 ] t -> Mode.x86 -> unit

(** {2 Custom Mnemonics}

    Override default instruction mnemonics for specific instruction IDs. *)

(** Set a custom mnemonic for an instruction.

    {[
      (* Change x86 NOP (ID 510) to "nothing" *)
      Capstone.set_mnemonic handle ~insn_id:510 (Some "nothing")
    ]}

    @param handle Disassembler handle
    @param insn_id Instruction ID from architecture constants
    @param mnemonic [Some str] for custom, [None] to reset to default *)
val set_mnemonic : 'a t -> insn_id:int -> string option -> unit

(** Reset an instruction's mnemonic to default.

    Equivalent to [set_mnemonic handle ~insn_id None].

    @param handle Disassembler handle
    @param insn_id Instruction ID to reset *)
val reset_mnemonic : 'a t -> insn_id:int -> unit

(** {1 Name Lookup} *)

(** Get the name of a register by ID.

    @param handle Disassembler handle
    @param reg_id Register ID
    @return Register name (e.g., "eax", "x0") or [None] if invalid *)
val reg_name : 'a t -> int -> string option

(** Get the name of an instruction by ID.

    @param handle Disassembler handle
    @param insn_id Instruction ID
    @return Instruction name (e.g., "mov", "add") or [None] if invalid *)
val insn_name : 'a t -> int -> string option

(** Get the name of an instruction group by ID.

    @param handle Disassembler handle
    @param group_id Group ID
    @return Group name (e.g., "jump", "call") or [None] if invalid *)
val group_name : 'a t -> int -> string option

(** {1 Convenience Functions} *)

(** Execute a function with automatic handle management.

    The handle is automatically closed when the function returns or raises.

    {[
      Capstone.with_handle Arch.X86_64 (fun h ->
        Capstone.disasm ~addr:0L h code
      )
    ]}

    @param arch Architecture selector
    @param f Function to execute with the handle
    @return [Ok result] on success, [Error e] if handle creation failed *)
val with_handle : 'a Arch.t -> ('a t -> 'b) -> ('b, error) result

(** Disassemble a block of code with automatic handle management.

    Convenience function that creates a handle, disassembles, and closes.

    @param arch Architecture selector
    @param code Binary code to disassemble
    @param addr Starting address
    @return [Ok insns] on success, [Error e] on failure *)
val disassemble_block : 'a Arch.t -> bytes -> addr:int64 -> (insn list, error) result
