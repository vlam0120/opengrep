(* Server subcommand CLI argument parsing.
 *
 * Copyright (C) 2025 Opengrep contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation, with the
 * special exception on linking described in file LICENSE.
 *)
module Arg = Cmdliner.Arg
module Term = Cmdliner.Term
module Cmd = Cmdliner.Cmd

(*****************************************************************************)
(* Types *)
(*****************************************************************************)

type conf = {
  host         : string;
  port         : int;
  max_rulesets : int;
  preload      : string list;
  idle_timeout : int;
  common       : CLI_common.conf;
}
[@@deriving show]

(*****************************************************************************)
(* Default values *)
(*****************************************************************************)

let default : conf = {
  host         = "127.0.0.1";
  port         = 7777;
  max_rulesets = 16;
  preload      = [];
  idle_timeout = 0;
  common       = CLI_common.default;
}

(*****************************************************************************)
(* Flags *)
(*****************************************************************************)

let o_host : string Term.t =
  let info = Arg.info [ "host" ] ~docv:"HOST"
    ~doc:"Address to bind the HTTP listener  (default: 127.0.0.1)." in
  Arg.value (Arg.opt Arg.string default.host info)

let o_port : int Term.t =
  let info = Arg.info [ "port" ] ~docv:"PORT"
    ~doc:"TCP port to listen on  (default: 7777)." in
  Arg.value (Arg.opt Arg.int default.port info)

let o_max_rulesets : int Term.t =
  let info = Arg.info [ "max-rulesets" ] ~docv:"N"
    ~doc:"Maximum rulesets to keep in memory; oldest is evicted when full \
          (default: 16)." in
  Arg.value (Arg.opt Arg.int default.max_rulesets info)

let o_preload : string list Term.t =
  let info = Arg.info [ "preload" ] ~docv:"SOURCE"
    ~doc:"Rule source to load at startup. May be repeated. \
          Accepts the same values as $(b,opengrep scan --config): \
          a local YAML file, a directory, or a registry pack such as \
          $(b,p/python)." in
  Arg.value (Arg.opt_all Arg.string [] info)

let o_idle_timeout : int Term.t =
  let info = Arg.info [ "idle-timeout" ] ~docv:"SEC"
    ~doc:"Exit after SEC seconds with no incoming request. \
          0 means never exit  (default: 0)." in
  Arg.value (Arg.opt Arg.int default.idle_timeout info)

(*****************************************************************************)
(* Command-line term *)
(*****************************************************************************)

let cmdline_term : conf Term.t =
  (* Parameters must be in alphabetical order to match $ o_xx $ below. *)
  let combine common host idle_timeout max_rulesets port preload =
    { common; host; idle_timeout; max_rulesets; port; preload }
  in
  Term.(const combine
    $ CLI_common.o_common
    $ o_host
    $ o_idle_timeout
    $ o_max_rulesets
    $ o_port
    $ o_preload)

let doc =
  "start a long-running HTTP server that loads rules once and serves \
   repeated scan requests without rule-loading overhead"

let man : Cmdliner.Manpage.block list =
  [
    `S Cmdliner.Manpage.s_description;
    `P "$(b,opengrep server) starts an HTTP listener on localhost (by default \
        $(b,127.0.0.1:7777)) and keeps rulesets in memory. Clients send \
        scan requests over HTTP; rules are reused across requests, eliminating \
        repeated YAML-parsing and grammar-loading overhead.";
    `P "Scan responses are streamed as newline-delimited JSON (NDJSON). \
        Each line is either a $(b,progress) event (one per file, with \
        findings) or a final $(b,done) event with aggregate statistics.";
    `S "ENDPOINTS";
    `Pre "POST   /rulesets          Load a ruleset; returns {ruleset_id}";
    `Pre "GET    /rulesets          List all loaded rulesets";
    `Pre "DELETE /rulesets/:id      Remove a ruleset from memory";
    `Pre "POST   /scan              Scan targets (NDJSON streaming response)";
    `Pre "GET    /health            Server status";
    `S "EXAMPLES";
    `Pre "# Start server on default port\nopengrep server";
    `Pre "# Preload rules at startup\n\
          opengrep server --preload rules/python.yaml --preload p/security-audit";
    `Pre "# Custom port\nopengrep server --port 8080";
  ]
  @ CLI_common.help_page_bottom

let cmdline_info : Cmd.info = Cmd.info "opengrep server" ~doc ~man

(*****************************************************************************)
(* Entry point *)
(*****************************************************************************)

let parse_argv (argv : string array) : conf =
  let cmd : conf Cmd.t = Cmd.v cmdline_info cmdline_term in
  CLI_common.eval_value ~argv cmd
