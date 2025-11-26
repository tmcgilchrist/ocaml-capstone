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
    "x86_64", [
      test_case "basic disasm" `Quick test_x86_64_basic;
      test_case "mov instruction" `Quick test_x86_64_mov;
      test_case "detailed reg operands" `Quick test_x86_64_detail;
      test_case "detailed mem operands" `Quick test_x86_64_detail_mem;
    ];
    "convenience", [
      test_case "with_handle" `Quick test_with_handle;
      test_case "disassemble_block" `Quick test_disassemble_block;
      test_case "reg_name" `Quick test_reg_name;
    ];
  ]
