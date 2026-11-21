# D69 H7 way (B): the stdout of one real nmap run

`real_nmap_stdout.bin` is the stdout of **one** real nmap run (plan item 122 (b)), made through the real
`propose_action` ALLOW path with the real `DockerSandbox` and the existing nmap image, against one laboratory
target this project set up on an internal Docker network. Nothing else was scanned; nmap ran once.

| fact | value |
|---|---|
| run time (UTC) | `propose_action` called 2026-11-21T09:21:53.243377+00:00, returned 2026-11-21T09:22:05.842338+00:00; `tool_runs.started_at` 2026-11-21 09:21:55.346062+00:00, `finished_at` 2026-11-21 09:22:04.105507+00:00 |
| nmap version | `7.94SVN` (`tool_runs.tool_version`; the stdout's first line says `Starting Nmap 7.94SVN`) |
| nmap image | `cyberorch/nmap:local`, id `sha256:f50d41e266e4df882f2a8b7600e34b776d4c9130e3ba008b39fc553b2e0ace5f` |
| target image | `python:3.12-slim`, id `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`, run with `--pull never` |
| command (from the raw artifact) | `/usr/bin/nmap -sT -sV -n --unprivileged -Pn -p 2222 --host-timeout 115s 10.82.0.10` |
| internal network | `cyberorch-allow-f55fc93de10e`, created by `DockerSandbox.ensure_network`, `Internal: true`, subnet `10.82.0.0/24` (gateway `10.82.0.1`), removed after the run |
| sandbox `network_allowlist` | `["10.82.0.0/24"]` (`tool_runs.network_allowlist`) |
| target | `10.82.0.10:2222`, container `d69b-target-f8783783`, on that network only; removed after the run |
| scan type | `version` (`-sT -sV`) |
| exit code, status | `0`, `succeeded` |
| run and evidence ids | `RUN-a72429addbfb`, `NMAP-493ca42db146` (test engagement `ENG-TEST-D69B-b1d4bda4`) |
| raw artifact | `evidence_store/ENG-TEST-D69B-b1d4bda4/bc/bc387a557e9b3be43b92423f580bad0525f411da81c0d3008de48a1a2bdf7e5e.bin`, sha256 `bc387a557e9b3be43b92423f580bad0525f411da81c0d3008de48a1a2bdf7e5e`, 464 bytes (not committed) |
| this file's stdout | 347 bytes, sha256 `472ed95ac6bdad37a7ec75953ff81fed7125551fce1effec460b15bc6c28cf64`; 0 bytes above 0x7f; 0 U+FFFD |

**What the bytes are.** The sandbox reads the container's stdout as text (`.decode(errors="replace")`,
`tool_gateway/sandbox.py:1101`) and the pipeline stores, as the raw artifact, the command line, that stdout and the
stderr, encoded as UTF-8 (`control_plane/orchestrator/dispatch.py:509-514`). This file is the stdout part of that
artifact. It has no byte above 0x7f and no U+FFFD, so the decoding lost nothing: these are the bytes nmap wrote.

**What the run showed.** nmap reported the port `open` and its service `tcpwrapped`, and printed no service
fingerprint: none of the banner's six lures is in the stdout. The banner was sent by the target's program (see
`tests/test_provenance_real_nmap.py`, `BANNER` and `SERVER_PROGRAM`); why nmap did not report it is not known from
this run [N]. The target's own logs were not read before it was removed.

## Run 1 -- the record (2026-11-21)

This is the **first** run of way (B). nmap reported the port `open` with service `tcpwrapped` and printed no
service fingerprint, so **none of the six lures (L1-L6) is in the stdout**. The probable cause is the target program,
not nmap: it sent the banner and closed the connection at once, and its loop caught no connection error, so a reset
from one of nmap's connections could have ended the service before the version probe read anything. **This was not
verified: the target's logs were not read before it was removed.**

| fact | value |
|---|---|
| pre-registered table | `run1_preregistered_test.py.txt` (this directory; the run-1 test file, moved here byte for byte, sha256 `8b994c2380a04467313298ac5e5d2d907c361bd1eba24e2dea7b6ec5e9dae720`, not collected by pytest), block lines 40-112, sha256 `90468b91fb2700fbcd1cfcf20813cd6b53a87ff8a485ccff96433f866d258156` |
| block hashed at | 2026-11-21T09:20:44.901517562Z |
| run began and ended | `propose_action` called 2026-11-21T09:21:53.243377+00:00, returned 2026-11-21T09:22:05.842338+00:00 (69 s after the hash) |

**Results on this stdout (29 cases: 25 failed, 4 passed).**
- The six lures, at unit level, builder and raw forms (12): all `introduced_by_untrusted` false.
- The six lures through the loop, both actions (12): all decided `ALLOW`, `introduced_by_untrusted` false, no
  reasons.
- The target's own address `10.82.0.10` (2 unit, 2 loop): introduced, `HUMAN_APPROVAL`, `untrusted_discovery_source`,
  as pre-registered.
- The sample check failed because its sha256 constant, outside the table, was left `None` and not filled in after
  the run (the implementer's omission); its recorded facts were therefore not printed.

**The 12 ALLOW decisions are not a fail-open.** The lures never entered the evidence: the stdout does not contain
them, so a proposal for a lure address names a target that nothing mentions, which is correctly not introduced. A
real Worker could not have learnt those addresses from this stdout.
