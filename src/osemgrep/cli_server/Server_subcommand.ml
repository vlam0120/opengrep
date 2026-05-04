(* Server subcommand: loads rules once, serves scan requests over HTTP.
 *
 * Copyright (C) 2025 Opengrep contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation, with the
 * special exception on linking described in file LICENSE.
 *
 * Implements the endpoints described in Server_CLI.ml:
 *
 *   POST   /rulesets        load rules from a file, dir, or registry ref
 *   GET    /rulesets        list cached rulesets
 *   DELETE /rulesets/:id    drop a cached ruleset
 *   POST   /scan            scan targets; NDJSON-streaming response
 *   GET    /health          server status
 *
 * Concurrency model
 * -----------------
 * The HTTP server runs entirely in Lwt. Scan execution is dispatched to a
 * system thread via Lwt_preemptive.detach so the Lwt scheduler stays
 * responsive during long scans. The file_match_hook (called from Core_scan's
 * internal threads) communicates back to Lwt via Lwt_preemptive.run_in_main,
 * which is the documented thread-safe path into the Lwt scheduler.
 *)
open Lwt.Syntax
open Lwt.Infix

module Log = (val Logs.src_log (Logs.Src.create "opengrep.server"))

(*****************************************************************************)
(* Capabilities *)
(*****************************************************************************)

type caps =
  < Cap.stdout
  ; Cap.network
  ; Cap.tmp
  ; Cap.fork
  ; Cap.time_limit
  ; Cap.memory_limit >

(*****************************************************************************)
(* Ruleset cache *)
(*****************************************************************************)

type ruleset_entry = {
  id         : string;
  rules      : Rule.t list;
  rule_count : int;
  languages  : string list;
  source     : string;
  loaded_at  : float;
}

type cache = {
  mu      : Mutex.t;
  tbl     : (string, ruleset_entry) Hashtbl.t;
  counter : int Atomic.t;
  cap     : int;
}

let make_cache cap = {
  mu      = Mutex.create ();
  tbl     = Hashtbl.create 16;
  counter = Atomic.make 0;
  cap;
}

let next_id cache =
  let n = Atomic.fetch_and_add cache.counter 1 + 1 in
  Printf.sprintf "rs_%016d" n

let cache_add cache entry =
  Mutex.lock cache.mu;
  (* Evict the oldest entry when at capacity. *)
  if Hashtbl.length cache.tbl >= cache.cap then begin
    let oldest =
      Hashtbl.fold
        (fun k v acc ->
          match acc with
          | None -> Some (k, v.loaded_at)
          | Some (_, t) -> if v.loaded_at < t then Some (k, v.loaded_at) else acc)
        cache.tbl None
    in
    Option.iter (fun (k, _) -> Hashtbl.remove cache.tbl k) oldest
  end;
  Hashtbl.replace cache.tbl entry.id entry;
  Mutex.unlock cache.mu

let cache_find cache id =
  Mutex.lock cache.mu;
  let v = Hashtbl.find_opt cache.tbl id in
  Mutex.unlock cache.mu;
  v

let cache_remove cache id =
  Mutex.lock cache.mu;
  let existed = Hashtbl.mem cache.tbl id in
  if existed then Hashtbl.remove cache.tbl id;
  Mutex.unlock cache.mu;
  existed

let cache_list cache =
  Mutex.lock cache.mu;
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) cache.tbl [] in
  Mutex.unlock cache.mu;
  List.sort (fun a b -> Float.compare a.loaded_at b.loaded_at) entries

(*****************************************************************************)
(* JSON helpers *)
(*****************************************************************************)

let jstr s   = `String s
let jint n   = `Int n
let jbool b  = `Bool b
let jfloat f = `Float f
let jlist l  = `List l
let jobj  a  = `Assoc a

let to_json v = Yojson.Safe.to_string v ^ "\n"

let error_json code msg =
  to_json (jobj [ "error", jstr code; "message", jstr msg ])

(*****************************************************************************)
(* Finding conversion *)
(*****************************************************************************)

let position_json (loc : Tok.location) =
  jobj [
    "line",   jint loc.Tok.pos.Pos.line;
    "col",    jint loc.Tok.pos.Pos.column;
    "offset", jint loc.Tok.pos.Pos.bytepos;
  ]

let match_to_json (m : Core_match.t) =
  let start_loc, end_loc = m.Core_match.range_loc in
  let path =
    Fpath.to_string m.Core_match.path.Target.internal_path_to_content in
  let rule_id =
    Rule_ID.to_string m.Core_match.rule_id.Core_match.id in
  let severity =
    match m.Core_match.severity_override with
    | Some s -> Rule.show_severity s
    | None   -> "INFO"
  in
  jobj [
    "check_id", jstr rule_id;
    "path",     jstr path;
    "start",    position_json start_loc;
    "end",      position_json end_loc;
    "severity", jstr severity;
    "message",  jstr m.Core_match.rule_id.Core_match.message;
  ]

(*****************************************************************************)
(* Target helpers *)
(*****************************************************************************)

let xlang_of_path fpath =
  match Lang.langs_of_filename fpath with
  | lang :: _ -> Xlang.L (lang, [])
  | []        -> Xlang.LSpacegrep

let expand_path p =
  if not (Sys.file_exists p) then []
  else if not (Sys.is_directory p) then [ p ]
  else
    let acc = ref [] in
    let rec walk dir =
      Array.iter
        (fun name ->
          let full = Filename.concat dir name in
          match Unix.stat full with
          | exception Unix.Unix_error _ -> ()
          | st -> (
              match st.Unix.st_kind with
              | Unix.S_REG -> acc := full :: !acc
              | Unix.S_DIR -> walk full
              | _ -> ()))
        (try Sys.readdir dir with Sys_error _ -> [||])
    in
    walk p;
    !acc

let make_targets paths =
  List.concat_map
    (fun p ->
      expand_path p
      |> List.filter_map (fun f ->
             try
               let fpath = Fpath.v f in
               Some (Target.mk_target (xlang_of_path fpath) fpath)
             with _ -> None))
    paths

(*****************************************************************************)
(* Rule loading *)
(*****************************************************************************)

let do_load_rules (caps : < Cap.network; Cap.tmp; .. >) source_str =
  let t0 = Unix.gettimeofday () in
  let rules_source = Rules_source.Configs [ source_str ] in
  let rules_and_origin, _errors =
    Rule_fetching.rules_from_rules_source ~rewrite_rule_ids:true ~strict:false
      (caps :> < Cap.network; Cap.tmp >)
      rules_source
  in
  let rules, _invalid =
    Rule_fetching.partition_rules_and_invalid rules_and_origin in
  let loaded_in_ms =
    int_of_float ((Unix.gettimeofday () -. t0) *. 1000.0) in
  let languages =
    List.filter_map
      (fun (r : Rule.t) ->
        match r.Rule.target_analyzer with
        | Xlang.L (lang, _) -> Some (Lang.to_string lang)
        | _ -> None)
      rules
    |> List.sort_uniq String.compare
  in
  (rules, languages, loaded_in_ms)

(*****************************************************************************)
(* HTTP utilities *)
(*****************************************************************************)

let respond_json ?(status = `OK) body =
  Cohttp_lwt_unix.Server.respond_string ~status
    ~headers:
      (Cohttp.Header.of_list [ ("Content-Type", "application/json") ])
    ~body ()

let respond_error status code msg = respond_json ~status (error_json code msg)

let strip_prefix prefix s =
  let n = String.length prefix in
  if String.length s > n && String.sub s 0 n = prefix then
    Some (String.sub s n (String.length s - n))
  else None

(*****************************************************************************)
(* Scan handler *)
(*****************************************************************************)

(* Run a scan in a background thread and stream NDJSON progress events.
 * The file_match_hook uses Lwt_preemptive.run_in_main — the documented
 * thread-safe way to push values into the Lwt scheduler from an OS thread.
 *)
let handle_scan (caps : < caps; .. >) entry targets timeout_sec num_jobs =
  let stream, push = Lwt_stream.create () in
  let t0             = Unix.gettimeofday () in
  let target_list    = make_targets targets in
  let findings_count = Atomic.make 0 in
  let skipped        = List.length targets - List.length target_list in

  let file_match_hook fpath (result : Core_result.matches_single_file) =
    let path = Fpath.to_string fpath in
    let findings =
      List.map match_to_json result.Core_result.matches in
    ignore (Atomic.fetch_and_add findings_count (List.length findings));
    let parse_errors =
      Core_error.ErrorSet.elements result.Core_result.errors
      |> List.map Core_error.string_of_error
    in
    let line =
      to_json
        (jobj
           [ "event",        jstr "progress";
             "file",         jstr path;
             "findings",     jlist findings;
             "parse_errors", jlist (List.map jstr parse_errors) ])
    in
    Lwt_preemptive.run_in_main (fun () ->
      push (Some line);
      Lwt.return_unit)
  in

  let config =
    { Core_scan_config.default with
      Core_scan_config.rule_source     = Core_scan_config.Rules entry.rules;
      Core_scan_config.target_source   =
        Core_scan_config.Targets target_list;
      Core_scan_config.output_format   = Core_scan_config.NoOutput;
      Core_scan_config.file_match_hook = Some file_match_hook;
      Core_scan_config.ncores          = num_jobs;
      Core_scan_config.timeout         = float_of_int timeout_sec }
  in

  (* Dispatch scan to a preemptive thread; the Lwt scheduler stays free. *)
  Lwt.async (fun () ->
    let* scan_result =
      Lwt_preemptive.detach
        (fun () -> Core_scan.scan (caps :> Core_scan.caps) config)
        ()
    in
    let duration_ms =
      int_of_float ((Unix.gettimeofday () -. t0) *. 1000.0) in
    let errors =
      match scan_result with
      | Ok _    -> []
      | Error e -> [ Exception.to_string e ]
    in
    let done_line =
      to_json
        (jobj
           [ "event",          jstr "done";
             "files_scanned",  jint (List.length target_list);
             "files_skipped",  jint skipped;
             "findings_total", jint (Atomic.get findings_count);
             "duration_ms",    jint duration_ms;
             "errors",         jlist (List.map jstr errors) ])
    in
    push (Some done_line);
    push None;
    Lwt.return_unit);

  let body = Cohttp_lwt.Body.of_stream stream in
  Cohttp_lwt_unix.Server.respond
    ~headers:
      (Cohttp.Header.of_list
         [ ("Content-Type", "application/x-ndjson");
           ("Transfer-Encoding", "chunked") ])
    ~status:`OK ~body ()

(*****************************************************************************)
(* HTTP callback *)
(*****************************************************************************)

let make_callback caps cache start_time _conn req body =
  let uri  = Cohttp.Request.uri req in
  let meth = Cohttp.Request.meth req in
  let path = Uri.path uri in

  Log.debug (fun f ->
      f "%s %s" (Cohttp.Code.string_of_method meth) path);

  match path, meth with
  (* ── health ──────────────────────────────────────────────────── *)
  | "/health", `GET ->
    let uptime        = int_of_float (Unix.gettimeofday () -. start_time) in
    let ruleset_count = List.length (cache_list cache) in
    respond_json
      (to_json
         (jobj
            [ "status",        jstr "ok";
              "uptime_sec",    jint uptime;
              "ruleset_count", jint ruleset_count;
              "platform",
              jstr (if Sys.win32 then "windows" else "linux") ]))

  (* ── list rulesets ───────────────────────────────────────────── *)
  | "/rulesets", `GET ->
    let rulesets =
      cache_list cache
      |> List.map (fun e ->
             jobj
               [ "ruleset_id", jstr e.id;
                 "rule_count", jint e.rule_count;
                 "languages",  jlist (List.map jstr e.languages);
                 "source",     jstr e.source;
                 "loaded_at",  jfloat e.loaded_at ])
    in
    respond_json (to_json (jobj [ "rulesets", jlist rulesets ]))

  (* ── load ruleset ────────────────────────────────────────────── *)
  | "/rulesets", `POST ->
    let* body_str = Cohttp_lwt.Body.to_string body in
    (match Yojson.Safe.from_string body_str with
    | exception _ ->
      respond_error `Bad_request "invalid_json"
        "request body is not valid JSON"
    | json ->
      (match Yojson.Safe.Util.(member "source" json) with
      | `String source_str ->
        (try
           let* (rules, languages, loaded_in_ms) =
             Lwt_preemptive.detach
               (fun () -> do_load_rules caps source_str)
               ()
           in
           let id    = next_id cache in
           let entry =
             { id;
               rules;
               rule_count = List.length rules;
               languages;
               source     = source_str;
               loaded_at  = Unix.gettimeofday () }
           in
           cache_add cache entry;
           Log.info (fun f ->
               f "Loaded ruleset %s: %d rules from %s in %dms" id
                 (List.length rules) source_str loaded_in_ms);
           respond_json
             (to_json
                (jobj
                   [ "ruleset_id",   jstr id;
                     "rule_count",   jint (List.length rules);
                     "languages",    jlist (List.map jstr languages);
                     "loaded_in_ms", jint loaded_in_ms ]))
         with exn ->
           respond_error `Internal_server_error "load_error"
             (Printexc.to_string exn))
      | _ ->
        respond_error `Bad_request "missing_source"
          {|field "source" (string) is required|}))

  (* ── drop ruleset ────────────────────────────────────────────── *)
  | path, `DELETE -> (
    match strip_prefix "/rulesets/" path with
    | None ->
      respond_error `Not_found "not_found"
        (Printf.sprintf "no route: DELETE %s" path)
    | Some id ->
      if cache_remove cache id then
        respond_json (to_json (jobj [ "dropped", jbool true ]))
      else
        respond_error `Not_found "ruleset_not_found"
          (Printf.sprintf "ruleset %s not found" id))

  (* ── scan ────────────────────────────────────────────────────── *)
  | "/scan", `POST ->
    let* body_str = Cohttp_lwt.Body.to_string body in
    (match Yojson.Safe.from_string body_str with
    | exception _ ->
      respond_error `Bad_request "invalid_json"
        "request body is not valid JSON"
    | json ->
      let u = Yojson.Safe.Util in
      let ruleset_id =
        match u.member "ruleset_id" json with
        | `String s -> s
        | _ -> ""
      in
      let targets =
        match u.member "targets" json with
        | `List l ->
          List.filter_map (function `String s -> Some s | _ -> None) l
        | _ -> []
      in
      let timeout_sec =
        match u.member "timeout_per_file" json with
        | `Int n -> n
        | `Float f -> int_of_float f
        | _ -> 30
      in
      let num_jobs =
        match u.member "num_jobs" json with
        | `Int n -> max 1 n
        | _ -> 1
      in
      if targets = [] then
        respond_error `Bad_request "missing_targets"
          {|field "targets" must be a non-empty array of paths|}
      else
        (match cache_find cache ruleset_id with
        | None when ruleset_id = "" ->
          respond_error `Bad_request "missing_ruleset_id"
            {|field "ruleset_id" is required — call POST /rulesets first|}
        | None ->
          respond_error `Not_found "ruleset_not_found"
            (Printf.sprintf
               "ruleset %s not found; call POST /rulesets first" ruleset_id)
        | Some entry ->
          handle_scan caps entry targets timeout_sec num_jobs))

  (* ── unknown route ───────────────────────────────────────────── *)
  | _ ->
    respond_error `Not_found "not_found"
      (Printf.sprintf "no route: %s %s"
         (Cohttp.Code.string_of_method meth)
         path)

(*****************************************************************************)
(* Preload *)
(*****************************************************************************)

let preload_sources caps cache sources =
  List.iter
    (fun src ->
      Log.info (fun f -> f "Preloading %s ..." src);
      (try
         let rules, languages, loaded_in_ms = do_load_rules caps src in
         let id    = next_id cache in
         let entry =
           { id;
             rules;
             rule_count = List.length rules;
             languages;
             source     = src;
             loaded_at  = Unix.gettimeofday () }
         in
         cache_add cache entry;
         Log.info (fun f ->
             f "Preloaded ruleset %s: %d rules (%s) in %dms" id
               (List.length rules)
               (String.concat ", " languages)
               loaded_in_ms)
       with exn ->
         Log.err (fun f ->
             f "Failed to preload %s: %s" src (Printexc.to_string exn))))
    sources

(*****************************************************************************)
(* Run *)
(*****************************************************************************)

let run_conf (caps : < caps; .. >) (conf : Server_CLI.conf) : Exit_code.t =
  CLI_common.setup_logging ~force_color:true ~level:conf.common.logging_level;
  Log.info (fun f ->
      f "opengrep server starting on %s:%d" conf.host conf.port);

  let cache      = make_cache conf.max_rulesets in
  let start_time = Unix.gettimeofday () in

  (* Preload rule sources given on the command line. *)
  preload_sources caps cache conf.preload;

  let callback = make_callback caps cache start_time in
  let server   = Cohttp_lwt_unix.Server.make ~callback () in
  let mode     = `TCP (`Port conf.port) in

  Log.info (fun f ->
      f "Listening on http://%s:%d  (max_rulesets=%d)"
        conf.host conf.port conf.max_rulesets);

  Lwt_platform.run
    (Cohttp_lwt_unix.Server.create ~mode server);

  Exit_code.ok ~__LOC__

(*****************************************************************************)
(* Entry point *)
(*****************************************************************************)

let main (caps : < caps; .. >) (argv : string array) : Exit_code.t =
  let conf = Server_CLI.parse_argv argv in
  run_conf caps conf
