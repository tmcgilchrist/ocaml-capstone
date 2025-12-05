(* Capstone OCaml Bindings - Constant Generator

   This generator parses Capstone C headers and produces pure OCaml code
   for enum constants. The key innovation is handling duplicate enum values
   (like ARM64_SYSREG_TRCEXTINSELR and ARM64_SYSREG_TRCEXTINSELR0 both = 34884)
   by using pure OCaml pattern matching instead of C switch statements.

   In OCaml, multiple patterns can map to the same value in to_int,
   and we only emit canonical (first-seen) values in of_int.
*)

(* Configuration for each header file *)
type header_config = {
  header_name : string;      (* e.g., "aarch64.h" *)
  module_prefix : string;    (* e.g., "aarch64" - prefix to strip from enum names *)
  output_prefix : string;    (* e.g., "aarch64" - output file prefix *)
}

let headers = [
  { header_name = "capstone.h"; module_prefix = "cs"; output_prefix = "cs" };
  (* Capstone 5.x still uses arm64.h naming even though types are aarch64 *)
  { header_name = "arm64.h"; module_prefix = "arm64"; output_prefix = "aarch64" };
  { header_name = "arm.h"; module_prefix = "arm"; output_prefix = "arm" };
  { header_name = "x86.h"; module_prefix = "x86"; output_prefix = "x86" };
  { header_name = "riscv.h"; module_prefix = "riscv"; output_prefix = "riscv" };
  { header_name = "ppc.h"; module_prefix = "ppc"; output_prefix = "ppc" };
  { header_name = "systemz.h"; module_prefix = "sysz"; output_prefix = "sysz" };
  { header_name = "sparc.h"; module_prefix = "sparc"; output_prefix = "sparc" };
  { header_name = "mips.h"; module_prefix = "mips"; output_prefix = "mips" };
]

(* Parsed enum definition *)
type enum_def = {
  name : string;                         (* e.g., "aarch64_reg" *)
  variants : (string * int64) list;      (* (variant_name, value) in order *)
}

(* --- Utility functions --- *)

let is_digit = function '0'..'9' -> true | _ -> false

let trim s =
  let s = String.trim s in
  (* Remove trailing comments *)
  match String.index_opt s '/' with
  | Some i when i > 0 && s.[i-1] = ' ' -> String.trim (String.sub s 0 (i-1))
  | Some i -> String.trim (String.sub s 0 i)
  | None -> s

let starts_with prefix s =
  let plen = String.length prefix in
  String.length s >= plen && String.sub s 0 plen = prefix

let ends_with suffix s =
  let slen = String.length suffix in
  let len = String.length s in
  len >= slen && String.sub s (len - slen) slen = suffix

(* Split on commas, handling enum definitions *)
let split_on_comma s =
  String.split_on_char ',' s |> List.map String.trim |> List.filter ((<>) "")

(* Convert C enum name to OCaml variant name *)
let to_variant_name ~prefix name =
  (* Strip prefix (e.g., "AARCH64_REG_" -> "X0") *)
  let prefix_upper = String.uppercase_ascii prefix ^ "_" in
  let name_upper = String.uppercase_ascii name in
  if starts_with prefix_upper name_upper then
    let rest = String.sub name_upper (String.length prefix_upper)
                 (String.length name_upper - String.length prefix_upper) in
    (* Handle names starting with digits by prepending type name *)
    if String.length rest > 0 && is_digit rest.[0] then
      (* Find the type suffix, e.g., "REG" from "AARCH64_REG_X0" *)
      let parts = String.split_on_char '_' name_upper in
      if List.length parts >= 2 then
        List.nth parts 1 ^ "_" ^ rest
      else
        rest
    else
      rest
  else
    name_upper

(* OCaml reserved words that need escaping *)
let ocaml_keywords = [
  "and"; "as"; "asr"; "assert"; "begin"; "class"; "constraint"; "do"; "done";
  "downto"; "else"; "end"; "exception"; "external"; "false"; "for"; "fun";
  "function"; "functor"; "if"; "in"; "include"; "inherit"; "initializer";
  "land"; "lazy"; "let"; "lor"; "lsl"; "lsr"; "lxor"; "match"; "method";
  "mod"; "module"; "mutable"; "new"; "nonrec"; "object"; "of"; "open"; "or";
  "private"; "rec"; "sig"; "struct"; "then"; "to"; "true"; "try"; "type";
  "val"; "virtual"; "when"; "while"; "with"
]

let escape_keyword name =
  let lower = String.lowercase_ascii name in
  if List.mem lower ocaml_keywords then lower ^ "_" else lower

(* Should this enum variant be skipped? *)
let should_skip name =
  ends_with "_ENDING" name ||
  ends_with "_MAX" name ||
  ends_with "_INVALID" name

(* --- Parser --- *)

(* Parse a single enum value expression *)
let parse_value_expr expr current_value =
  let expr = trim expr in
  if expr = "" then
    current_value
  else
    (* Handle simple cases: decimal, hex, or reference to previous *)
    try
      if starts_with "0x" expr || starts_with "0X" expr then
        Int64.of_string expr
      else if is_digit expr.[0] || expr.[0] = '-' then
        Int64.of_string expr
      else
        (* Reference to another enum or expression - use current *)
        current_value
    with _ -> current_value

(* Parse enum definition from lines *)
let parse_enum lines ~prefix =
  let rec find_enum_start lines =
    match lines with
    | [] -> None
    | line :: rest ->
      let line = trim line in
      if starts_with "typedef enum" line || starts_with "enum " line then
        (* Extract enum name *)
        let parts = Str.split (Str.regexp "[ \t{]+") line in
        let name =
          if starts_with "typedef" line then
            if List.length parts >= 3 then List.nth parts 2 else ""
          else
            if List.length parts >= 2 then List.nth parts 1 else ""
        in
        Some (name, rest)
      else
        find_enum_start rest
  in

  let rec parse_variants lines variants current_value in_comment =
    match lines with
    | [] -> (List.rev variants, [])
    | line :: rest ->
      let raw_line = String.trim line in
      (* Handle multi-line comments - check raw line before trim removes /* *)
      let in_comment, skip_line =
        if in_comment then
          (* Look for end of comment *)
          let has_end =
            try
              let _ = Str.search_forward (Str.regexp_string "*/") raw_line 0 in
              true
            with Not_found -> false
          in
          if has_end then (false, true) else (true, true)
        else
          let has_start =
            try
              let _ = Str.search_forward (Str.regexp_string "/*") raw_line 0 in
              true
            with Not_found -> false
          in
          if has_start then
            (* Check if comment ends on same line *)
            let has_end =
              try
                let _ = Str.search_forward (Str.regexp_string "*/") raw_line 0 in
                true
              with Not_found -> false
            in
            if has_end then (false, true) else (true, true)
          else
            (false, false)
      in
      if skip_line then
        parse_variants rest variants current_value in_comment
      else begin
        let line = trim raw_line in
        if starts_with "}" line then
          (* End of enum - extract name if typedef *)
          (List.rev variants, rest)
        else if line = "" || starts_with "//" line then
          parse_variants rest variants current_value in_comment
        else begin
          (* Parse enum entries *)
          let entries = split_on_comma line in
          let (variants', value') = List.fold_left (fun (vars, val_) entry ->
            let entry = trim entry in
            if entry = "" || starts_with "//" entry then
              (vars, val_)
            else begin
              (* Parse "NAME = VALUE" or just "NAME" *)
              match String.index_opt entry '=' with
              | Some i ->
                let name = trim (String.sub entry 0 i) in
                let value_str = trim (String.sub entry (i+1) (String.length entry - i - 1)) in
                let value = parse_value_expr value_str val_ in
                if should_skip name then
                  (vars, Int64.succ value)
                else
                  let variant = to_variant_name ~prefix name in
                  ((variant, value) :: vars, Int64.succ value)
              | None ->
                let name = entry in
                if should_skip name then
                  (vars, Int64.succ val_)
                else
                  let variant = to_variant_name ~prefix name in
                  ((variant, val_) :: vars, Int64.succ val_)
            end
          ) (variants, current_value) entries in
          parse_variants rest variants' value' in_comment
        end
      end
  in

  match find_enum_start lines with
  | None -> None
  | Some (name, rest) ->
    let (variants, remaining) = parse_variants rest [] 0L false in
    Some ({ name; variants = List.rev variants }, remaining)

(* Parse all enums from a header file *)
let parse_header path ~prefix =
  let ic = open_in path in
  let rec read_lines acc =
    match input_line ic with
    | line -> read_lines (line :: acc)
    | exception End_of_file -> List.rev acc
  in
  let lines = read_lines [] in
  close_in ic;

  let rec parse_all lines enums =
    match parse_enum lines ~prefix with
    | None -> List.rev enums
    | Some (enum, rest) ->
      if List.length enum.variants > 0 then
        parse_all rest (enum :: enums)
      else
        parse_all rest enums
  in
  parse_all lines []

(* --- Code Emitter --- *)

let emit_enum oc enum =
  let module_name =
    String.split_on_char '_' enum.name
    |> List.map String.capitalize_ascii
    |> String.concat ""
  in

  (* Track seen values to identify canonical vs alias *)
  let seen_values = Hashtbl.create 100 in
  let canonical = ref [] in
  let all_variants = ref [] in

  List.iter (fun (name, value) ->
    all_variants := (name, value) :: !all_variants;
    if not (Hashtbl.mem seen_values value) then begin
      Hashtbl.add seen_values value name;
      canonical := (name, value) :: !canonical
    end
  ) enum.variants;

  let all_variants = List.rev !all_variants in
  let canonical = List.rev !canonical in

  if List.length all_variants = 0 then ()
  else begin
    Printf.fprintf oc "module %s = struct\n" module_name;

    (* Type definition *)
    Printf.fprintf oc "  type t = [\n";
    List.iter (fun (name, _) ->
      Printf.fprintf oc "    | `%s\n" name
    ) all_variants;
    Printf.fprintf oc "  ]\n\n";

    (* to_int: ALL variants map to their values (duplicates OK in OCaml) *)
    Printf.fprintf oc "  let to_int : t -> int = function\n";
    List.iter (fun (name, value) ->
      Printf.fprintf oc "    | `%s -> %Ld\n" name value
    ) all_variants;
    Printf.fprintf oc "\n";

    (* of_int: ONLY canonical variants (first occurrence) *)
    Printf.fprintf oc "  let of_int : int -> t option = function\n";
    List.iter (fun (name, value) ->
      Printf.fprintf oc "    | %Ld -> Some `%s\n" value name
    ) canonical;
    Printf.fprintf oc "    | _ -> None\n\n";

    (* of_int_exn for convenience *)
    Printf.fprintf oc "  let of_int_exn n =\n";
    Printf.fprintf oc "    match of_int n with\n";
    Printf.fprintf oc "    | Some v -> v\n";
    Printf.fprintf oc "    | None -> invalid_arg \"%s.of_int_exn\"\n\n" module_name;

    (* Named constants with lowercase names *)
    List.iter (fun (name, _) ->
      let lower = escape_keyword name in
      Printf.fprintf oc "  let %s : t = `%s\n" lower name
    ) all_variants;

    Printf.fprintf oc "end\n\n";
    Printf.fprintf oc "type %s = %s.t\n\n" (String.lowercase_ascii enum.name) module_name
  end

let emit_module oc enums =
  Printf.fprintf oc "(* Auto-generated by capstone-gen. Do not edit. *)\n\n";
  List.iter (emit_enum oc) enums

(* --- Main --- *)

let find_capstone_include () =
  (* Try common locations *)
  let candidates = [
    "/opt/homebrew/include/capstone";
    "/usr/local/include/capstone";
    "/usr/include/capstone";
  ] in
  match Sys.getenv_opt "CAPSTONE_INCLUDE" with
  | Some path -> path
  | None ->
    match List.find_opt Sys.file_exists candidates with
    | Some path -> path
    | None -> failwith "Cannot find Capstone headers. Set CAPSTONE_INCLUDE env var."

let () =
  let include_dir = find_capstone_include () in
  let output_dir =
    if Array.length Sys.argv > 1 then Sys.argv.(1)
    else "."
  in

  List.iter (fun config ->
    let header_path = Filename.concat include_dir config.header_name in
    if Sys.file_exists header_path then begin
      Printf.printf "Parsing %s...\n%!" header_path;
      let enums = parse_header header_path ~prefix:config.module_prefix in
      Printf.printf "  Found %d enums\n%!" (List.length enums);

      let output_path = Filename.concat output_dir (config.output_prefix ^ "_const.ml") in
      let oc = open_out output_path in
      emit_module oc enums;
      close_out oc;
      Printf.printf "  Generated %s\n%!" output_path
    end else
      Printf.printf "Skipping %s (not found)\n%!" header_path
  ) headers;

  Printf.printf "Done.\n%!"
