(* Capstone OCaml Bindings - Tests *)

open Alcotest

let test_version () =
  let (major, minor) = Capstone.version () in
  check bool "major >= 5" true (major >= 5);
  check bool "minor >= 0" true (minor >= 0)

let test_aarch64_basic () =
  (* NOP instruction: 0x1f, 0x20, 0x03, 0xd5 *)
  let code = Bytes.of_string "\x1f\x20\x03\xd5" in
  match Capstone.create Capstone.Arch.AARCH64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "nop" insn.mnemonic;
    check int "size" 4 insn.size

let test_aarch64_multiple () =
  (* Two instructions:
     0x1f, 0x20, 0x03, 0xd5  - nop
     0xc0, 0x03, 0x5f, 0xd6  - ret
  *)
  let code = Bytes.of_string "\x1f\x20\x03\xd5\xc0\x03\x5f\xd6" in
  match Capstone.create Capstone.Arch.AARCH64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 2 (List.length insns);
    let insn1 = List.nth insns 0 in
    let insn2 = List.nth insns 1 in
    check string "first mnemonic" "nop" insn1.mnemonic;
    check string "second mnemonic" "ret" insn2.mnemonic;
    check int64 "first address" 0x1000L insn1.address;
    check int64 "second address" 0x1004L insn2.address

let test_x86_64_basic () =
  (* NOP: 0x90, INT3: 0xcc *)
  let code = Bytes.of_string "\x90\xcc" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 2 (List.length insns);
    let insn1 = List.nth insns 0 in
    let insn2 = List.nth insns 1 in
    check string "first mnemonic" "nop" insn1.mnemonic;
    check string "second mnemonic" "int3" insn2.mnemonic

let test_x86_64_mov () =
  (* mov rax, rbx: 48 89 d8 *)
  let code = Bytes.of_string "\x48\x89\xd8" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "mov" insn.mnemonic;
    check bool "has operands" true (String.length insn.op_str > 0)

let test_with_handle () =
  let code = Bytes.of_string "\x90" in
  match Capstone.with_handle Capstone.Arch.X86_64 (fun h ->
    Capstone.disasm ~addr:0L h code
  ) with
  | Error e ->
    fail (Printf.sprintf "with_handle failed: %s" (Capstone.strerror e))
  | Ok insns ->
    check int "instruction count" 1 (List.length insns)

let test_disassemble_block () =
  let code = Bytes.of_string "\x1f\x20\x03\xd5" in
  match Capstone.disassemble_block Capstone.Arch.AARCH64 code ~addr:0x1000L with
  | Error e ->
    fail (Printf.sprintf "disassemble_block failed: %s" (Capstone.strerror e))
  | Ok insns ->
    check int "instruction count" 1 (List.length insns);
    check string "mnemonic" "nop" (List.hd insns).mnemonic

let test_reg_name () =
  match Capstone.create Capstone.Arch.X86_64 with
  | Error _ -> fail "Failed to create handle"
  | Ok h ->
    (* RAX is register 35 in x86 *)
    let name = Capstone.reg_name h 35 in
    Capstone.close h;
    check (option string) "RAX name" (Some "rax") name

let test_aarch64_detail () =
  (* add x0, x1, x2 : 0x20, 0x00, 0x02, 0x8b *)
  let code = Bytes.of_string "\x20\x00\x02\x8b" in
  match Capstone.create Capstone.Arch.AARCH64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_aarch64_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "add" insn.insn.mnemonic;
    (* Check we have operands *)
    check bool "has operands" true (Array.length insn.arch_detail.operands > 0);
    (* ADD x0, x1, x2 should have 3 register operands *)
    check int "operand count" 3 (Array.length insn.arch_detail.operands);
    (* First operand should be a register *)
    (match insn.arch_detail.operands.(0).value with
     | Capstone.Aarch64.Reg _ -> ()
     | _ -> fail "Expected register operand")

let test_aarch64_detail_mem () =
  (* ldr x0, [x1, #8] : 0x20, 0x04, 0x40, 0xf9 *)
  let code = Bytes.of_string "\x20\x04\x40\xf9" in
  match Capstone.create Capstone.Arch.AARCH64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_aarch64_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "ldr" insn.insn.mnemonic;
    (* LDR x0, [x1, #8] should have 2 operands: reg and mem *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Second operand should be memory *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Aarch64.Mem m ->
       check bool "has base register" true (m.base <> 0)
     | _ -> fail "Expected memory operand")

let test_x86_64_detail () =
  (* mov rax, rbx: 48 89 d8 *)
  let code = Bytes.of_string "\x48\x89\xd8" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_x86_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "mov" insn.insn.mnemonic;
    (* mov rax, rbx should have 2 register operands *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Check REX prefix is present (0x48) *)
    check int "rex prefix" 0x48 insn.arch_detail.rex;
    (* First operand should be a register *)
    (match insn.arch_detail.operands.(0).value with
     | Capstone.X86.Reg r ->
       check bool "dest is rax" true (r = 35)  (* RAX = 35 *)
     | _ -> fail "Expected register operand")

let test_x86_64_detail_mem () =
  (* mov rax, [rbx+rcx*4+0x10]: 48 8b 44 8b 10 *)
  let code = Bytes.of_string "\x48\x8b\x44\x8b\x10" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_x86_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "mov" insn.insn.mnemonic;
    (* mov rax, [rbx+rcx*4+0x10] should have 2 operands: reg and mem *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Second operand should be memory *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.X86.Mem m ->
       check bool "has base register" true (m.base <> 0);
       check bool "has index register" true (m.index <> 0);
       check int "scale" 4 m.scale;
       check int64 "displacement" 0x10L m.disp
     | _ -> fail "Expected memory operand")

let test_riscv64_basic () =
  (* addi x1, x2, 5 (RV64I): 0x00510093
     In little endian bytes: 93 00 51 00 *)
  let code = Bytes.of_string "\x93\x00\x51\x00" in
  match Capstone.create Capstone.Arch.RISCV64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "addi" insn.mnemonic;
    check int "size" 4 insn.size

let test_riscv64_detail () =
  (* addi x1, x2, 5 (RV64I): 0x00510093
     In little endian bytes: 93 00 51 00 *)
  let code = Bytes.of_string "\x93\x00\x51\x00" in
  match Capstone.create Capstone.Arch.RISCV64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_riscv_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "addi" insn.insn.mnemonic;
    (* addi x1, x2, 5 should have 3 operands: 2 regs and 1 imm *)
    check int "operand count" 3 (Array.length insn.arch_detail.operands);
    (* First operand should be a register *)
    (match insn.arch_detail.operands.(0).value with
     | Capstone.Riscv.Reg _ -> ()
     | _ -> fail "Expected register operand");
    (* Third operand should be immediate *)
    (match insn.arch_detail.operands.(2).value with
     | Capstone.Riscv.Imm imm ->
       check int64 "immediate value" 5L imm
     | _ -> fail "Expected immediate operand")

let test_riscv64_detail_mem () =
  (* ld x3, 8(x4) : 0x00843183
     In little endian bytes: 83 31 84 00 *)
  let code = Bytes.of_string "\x83\x31\x84\x00" in
  match Capstone.create Capstone.Arch.RISCV64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_riscv_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "ld" insn.insn.mnemonic;
    (* ld x3, 8(x4) should have 2 operands: reg and mem *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Second operand should be memory *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Riscv.Mem m ->
       check bool "has base register" true (m.base <> 0);
       check int64 "displacement" 8L m.disp
     | _ -> fail "Expected memory operand")

let test_ppc64_basic () =
  (* li r3, 5 (addi r3, 0, 5) - Big endian: 0x38600005 *)
  let code = Bytes.of_string "\x38\x60\x00\x05" in
  match Capstone.create Capstone.Arch.PPC64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "li" insn.mnemonic;
    check int "size" 4 insn.size

let test_ppc64_detail () =
  (* li r3, 5 (addi r3, 0, 5) - Big endian: 0x38600005 *)
  let code = Bytes.of_string "\x38\x60\x00\x05" in
  match Capstone.create Capstone.Arch.PPC64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_ppc_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "li" insn.insn.mnemonic;
    (* li r3, 5 should have 2 operands: reg and imm *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* First operand should be a register *)
    (match insn.arch_detail.operands.(0).value with
     | Capstone.Ppc.Reg _ -> ()
     | _ -> fail "Expected register operand");
    (* Second operand should be immediate *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Ppc.Imm imm ->
       check int64 "immediate value" 5L imm
     | _ -> fail "Expected immediate operand")

let test_ppc64_detail_mem () =
  (* lwz r3, 8(r4) - Big endian: 0x80640008 *)
  let code = Bytes.of_string "\x80\x64\x00\x08" in
  match Capstone.create Capstone.Arch.PPC64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_ppc_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "lwz" insn.insn.mnemonic;
    (* lwz r3, 8(r4) should have 2 operands: reg and mem *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Second operand should be memory *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Ppc.Mem m ->
       check bool "has base register" true (m.base <> 0);
       check int32 "displacement" 8l m.disp
     | _ -> fail "Expected memory operand")

let test_sysz_basic () =
  (* lgr %r1, %r2 (load 64-bit register) - Big endian: 0xb9040012 *)
  let code = Bytes.of_string "\xb9\x04\x00\x12" in
  match Capstone.create Capstone.Arch.SYSZ with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "lgr" insn.mnemonic;
    check int "size" 4 insn.size

let test_sysz_detail () =
  (* lgr %r1, %r2 (load 64-bit register) - Big endian: 0xb9040012 *)
  let code = Bytes.of_string "\xb9\x04\x00\x12" in
  match Capstone.create Capstone.Arch.SYSZ with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_sysz_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "lgr" insn.insn.mnemonic;
    (* lgr %r1, %r2 should have 2 register operands *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Both operands should be registers *)
    (match insn.arch_detail.operands.(0).value with
     | Capstone.Sysz.Reg _ -> ()
     | _ -> fail "Expected register operand");
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Sysz.Reg _ -> ()
     | _ -> fail "Expected register operand")

let test_sysz_detail_mem () =
  (* lg %r1, 8(%r2) (load 64-bit from memory) - Big endian: 0xe31020080004 *)
  let code = Bytes.of_string "\xe3\x10\x20\x08\x00\x04" in
  match Capstone.create Capstone.Arch.SYSZ with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_sysz_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "lg" insn.insn.mnemonic;
    (* lg %r1, 8(%r2) should have 2 operands: reg and mem *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Second operand should be memory *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Sysz.Mem m ->
       check bool "has base register" true (m.base <> 0);
       check int64 "displacement" 8L m.disp
     | _ -> fail "Expected memory operand")

let test_regs_access () =
  (* mov rax, rbx: 48 89 d8 - reads rbx, writes rax *)
  let code = Bytes.of_string "\x48\x89\xd8" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let results = Capstone.disasm_with_regs_access ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length results);
    let (insn, regs) = List.hd results in
    check string "mnemonic" "mov" insn.mnemonic;
    (* mov rax, rbx should read rbx and write rax *)
    check bool "has regs_read" true (Array.length regs.regs_read > 0);
    check bool "has regs_write" true (Array.length regs.regs_write > 0)

let test_regs_access_aarch64 () =
  (* add x0, x1, x2 : 0x20, 0x00, 0x02, 0x8b - reads x1, x2, writes x0 *)
  let code = Bytes.of_string "\x20\x00\x02\x8b" in
  match Capstone.create Capstone.Arch.AARCH64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let results = Capstone.disasm_with_regs_access ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length results);
    let (insn, regs) = List.hd results in
    check string "mnemonic" "add" insn.mnemonic;
    (* add x0, x1, x2 should read x1, x2 and write x0 *)
    check bool "has regs_read" true (Array.length regs.regs_read > 0);
    check bool "has regs_write" true (Array.length regs.regs_write > 0)

(* SKIPDATA tests *)
let test_skipdata_basic () =
  (* Mix valid x86 instruction with invalid bytes:
     nop (0x90), then 0xFF 0xFF (invalid), then nop (0x90) *)
  let code = Bytes.of_string "\x90\xff\xff\x90" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    (* Without SKIPDATA, disassembly stops at invalid bytes *)
    let insns_without = Capstone.disasm ~addr:0x1000L h code in
    (* With SKIPDATA, disassembly continues past invalid bytes *)
    Capstone.set_skipdata h true;
    let insns_with = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    (* Without skipdata, we only get the first nop *)
    check int "without skipdata: instruction count" 1 (List.length insns_without);
    check string "without skipdata: first mnemonic" "nop" (List.hd insns_without).mnemonic;
    (* With skipdata, we get: nop, .byte, .byte, nop (or nop, .byte 2x, nop depending on grouping) *)
    check bool "with skipdata: more instructions" true (List.length insns_with > 1);
    (* First instruction should still be nop *)
    check string "with skipdata: first mnemonic" "nop" (List.hd insns_with).mnemonic;
    (* There should be at least one .byte pseudo-instruction *)
    let has_skipdata = List.exists (fun i -> i.Capstone.mnemonic = ".byte") insns_with in
    check bool "with skipdata: has .byte" true has_skipdata

let test_skipdata_custom_mnemonic () =
  (* Test custom mnemonic for skipped data *)
  let code = Bytes.of_string "\x90\xff\xff\x90" in
  match Capstone.create Capstone.Arch.X86_64 with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_skipdata_mnemonic h (Some "db");
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    (* There should be at least one "db" pseudo-instruction *)
    let has_db = List.exists (fun i -> i.Capstone.mnemonic = "db") insns in
    check bool "has custom mnemonic 'db'" true has_db

(* ARM 32-bit tests *)
let test_arm_basic () =
  (* nop (mov r0, r0) in ARM mode: 0x00, 0x00, 0xa0, 0xe1 (little endian) *)
  let code = Bytes.of_string "\x00\x00\xa0\xe1" in
  match Capstone.create Capstone.Arch.ARM with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "mov" insn.mnemonic;
    check int "size" 4 insn.size

let test_arm_detail () =
  (* add r0, r1, r2 in ARM mode: 0x02, 0x00, 0x81, 0xe0 (little endian) *)
  let code = Bytes.of_string "\x02\x00\x81\xe0" in
  match Capstone.create Capstone.Arch.ARM with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_arm_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "add" insn.insn.mnemonic;
    (* add r0, r1, r2 should have 3 operands *)
    check int "operand count" 3 (Array.length insn.arch_detail.operands);
    (* First operand should be a register *)
    (match insn.arch_detail.operands.(0).value with
     | Capstone.Arm.Reg _ -> ()
     | _ -> fail "Expected register operand")

let test_arm_detail_mem () =
  (* ldr r0, [r1, #4] in ARM mode: 0x04, 0x00, 0x91, 0xe5 (little endian) *)
  let code = Bytes.of_string "\x04\x00\x91\xe5" in
  match Capstone.create Capstone.Arch.ARM with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    Capstone.set_detail h true;
    let insns = Capstone.disasm_arm_detail ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "ldr" insn.insn.mnemonic;
    (* ldr r0, [r1, #4] should have 2 operands: reg and mem *)
    check int "operand count" 2 (Array.length insn.arch_detail.operands);
    (* Second operand should be memory *)
    (match insn.arch_detail.operands.(1).value with
     | Capstone.Arm.Mem m ->
       check bool "has base register" true (m.base <> 0);
       check int32 "displacement" 4l m.disp
     | _ -> fail "Expected memory operand")

let test_thumb_basic () =
  (* nop in Thumb mode: 0x00, 0xbf *)
  let code = Bytes.of_string "\x00\xbf" in
  match Capstone.create Capstone.Arch.THUMB with
  | Error e ->
    fail (Printf.sprintf "Failed to create handle: %s" (Capstone.strerror e))
  | Ok h ->
    let insns = Capstone.disasm ~addr:0x1000L h code in
    Capstone.close h;
    check int "instruction count" 1 (List.length insns);
    let insn = List.hd insns in
    check string "mnemonic" "nop" insn.mnemonic;
    check int "size" 2 insn.size

let () =
  run "Capstone" [
    "version", [
      test_case "version check" `Quick test_version;
    ];
    "aarch64", [
      test_case "basic disasm" `Quick test_aarch64_basic;
      test_case "multiple instructions" `Quick test_aarch64_multiple;
      test_case "detailed reg operands" `Quick test_aarch64_detail;
      test_case "detailed mem operands" `Quick test_aarch64_detail_mem;
    ];
    "arm", [
      test_case "basic disasm" `Quick test_arm_basic;
      test_case "detailed reg operands" `Quick test_arm_detail;
      test_case "detailed mem operands" `Quick test_arm_detail_mem;
      test_case "thumb basic disasm" `Quick test_thumb_basic;
    ];
    "x86_64", [
      test_case "basic disasm" `Quick test_x86_64_basic;
      test_case "mov instruction" `Quick test_x86_64_mov;
      test_case "detailed reg operands" `Quick test_x86_64_detail;
      test_case "detailed mem operands" `Quick test_x86_64_detail_mem;
    ];
    "riscv64", [
      test_case "basic disasm" `Quick test_riscv64_basic;
      test_case "detailed reg/imm operands" `Quick test_riscv64_detail;
      test_case "detailed mem operands" `Quick test_riscv64_detail_mem;
    ];
    "ppc64", [
      test_case "basic disasm" `Quick test_ppc64_basic;
      test_case "detailed reg/imm operands" `Quick test_ppc64_detail;
      test_case "detailed mem operands" `Quick test_ppc64_detail_mem;
    ];
    "sysz", [
      test_case "basic disasm" `Quick test_sysz_basic;
      test_case "detailed reg operands" `Quick test_sysz_detail;
      test_case "detailed mem operands" `Quick test_sysz_detail_mem;
    ];
    "convenience", [
      test_case "with_handle" `Quick test_with_handle;
      test_case "disassemble_block" `Quick test_disassemble_block;
      test_case "reg_name" `Quick test_reg_name;
      test_case "regs_access x86_64" `Quick test_regs_access;
      test_case "regs_access aarch64" `Quick test_regs_access_aarch64;
    ];
    "skipdata", [
      test_case "basic skipdata" `Quick test_skipdata_basic;
      test_case "custom mnemonic" `Quick test_skipdata_custom_mnemonic;
    ];
  ]
