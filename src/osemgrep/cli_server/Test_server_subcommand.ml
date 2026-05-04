(* Tests for the server subcommand.
 *
 * Copyright (C) 2025 Opengrep contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation, with the
 * special exception on linking described in file LICENSE.
 *)
let t = Testo.create

(*****************************************************************************)
(* Prelude *)
(*****************************************************************************)
(*
 * Unit tests for the server subcommand.
 * These tests cover the ruleset cache and JSON helpers without requiring
 * a running HTTP server.
 *
 * Integration tests (start server → HTTP request → check response) should
 * be added as e2e pytest tests in cli/tests/ once this feature merges.
 *)

(*****************************************************************************)
(* Cache tests *)
(*****************************************************************************)

(* Access internal helpers via Server_subcommand — wrapped=false in dune *)

let make_dummy_entry id rules =
  Server_subcommand.
    { id;
      rules;
      rule_count = List.length rules;
      languages  = [ "python" ];
      source     = "test";
      loaded_at  = Unix.gettimeofday () }

let test_cache_add_find () =
  let cache = Server_subcommand.make_cache 16 in
  let entry = make_dummy_entry "rs_001" [] in
  Server_subcommand.cache_add cache entry;
  match Server_subcommand.cache_find cache "rs_001" with
  | None -> failwith "expected to find rs_001 after add"
  | Some e -> assert (e.Server_subcommand.id = "rs_001")

let test_cache_remove () =
  let cache = Server_subcommand.make_cache 16 in
  let entry = make_dummy_entry "rs_002" [] in
  Server_subcommand.cache_add cache entry;
  assert (Server_subcommand.cache_remove cache "rs_002");
  assert (Server_subcommand.cache_find cache "rs_002" = None);
  (* Removing again returns false *)
  assert (not (Server_subcommand.cache_remove cache "rs_002"))

let test_cache_eviction () =
  (* Cache of size 2 should evict the oldest entry when a third is added. *)
  let cache = Server_subcommand.make_cache 2 in
  let e1 = { (make_dummy_entry "rs_e1" []) with
              Server_subcommand.loaded_at = 1000.0 } in
  let e2 = { (make_dummy_entry "rs_e2" []) with
              Server_subcommand.loaded_at = 2000.0 } in
  let e3 = { (make_dummy_entry "rs_e3" []) with
              Server_subcommand.loaded_at = 3000.0 } in
  Server_subcommand.cache_add cache e1;
  Server_subcommand.cache_add cache e2;
  Server_subcommand.cache_add cache e3;
  (* e1 was oldest; it should have been evicted *)
  assert (Server_subcommand.cache_find cache "rs_e1" = None);
  assert (Server_subcommand.cache_find cache "rs_e2" <> None);
  assert (Server_subcommand.cache_find cache "rs_e3" <> None)

let test_next_id_format () =
  let cache = Server_subcommand.make_cache 16 in
  let id1 = Server_subcommand.next_id cache in
  let id2 = Server_subcommand.next_id cache in
  assert (id1 = "rs_0000000000000001");
  assert (id2 = "rs_0000000000000002")

(*****************************************************************************)
(* CLI parsing tests *)
(*****************************************************************************)

let test_parse_defaults () =
  let conf = Server_CLI.parse_argv [| "opengrep-server" |] in
  assert (conf.Server_CLI.host = "127.0.0.1");
  assert (conf.Server_CLI.port = 7777);
  assert (conf.Server_CLI.max_rulesets = 16);
  assert (conf.Server_CLI.preload = []);
  assert (conf.Server_CLI.idle_timeout = 0)

let test_parse_custom_port () =
  let conf =
    Server_CLI.parse_argv [| "opengrep-server"; "--port"; "8080" |]
  in
  assert (conf.Server_CLI.port = 8080)

let test_parse_preload () =
  let conf =
    Server_CLI.parse_argv
      [| "opengrep-server";
         "--preload"; "rules/python.yaml";
         "--preload"; "p/security-audit" |]
  in
  assert (List.length conf.Server_CLI.preload = 2);
  assert (List.mem "rules/python.yaml" conf.Server_CLI.preload);
  assert (List.mem "p/security-audit" conf.Server_CLI.preload)

(*****************************************************************************)
(* Test registry *)
(*****************************************************************************)

let tests =
  [
    t "server cache: add and find" test_cache_add_find;
    t "server cache: remove" test_cache_remove;
    t "server cache: evicts oldest when full" test_cache_eviction;
    t "server cache: next_id format" test_next_id_format;
    t "server CLI: default values" test_parse_defaults;
    t "server CLI: custom port" test_parse_custom_port;
    t "server CLI: multiple --preload" test_parse_preload;
  ]
