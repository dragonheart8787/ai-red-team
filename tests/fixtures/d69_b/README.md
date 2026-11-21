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

## Run 2 -- the second and last run (2026-11-21)

Authorized by plan item 126 (at most one more run, a corrected target, the same internal network and the same
command). `run2_real_nmap_stdout.bin` is its stdout. **nmap ran once more, and no third run is made.**

| fact | value |
|---|---|
| pre-registered table | `run2_preregistered_test.py.txt` (this directory; the run-2 test file, saved byte for byte after its one run, sha256 `2cc442b7bc873ebec76a6d3ca1e9750c4766010f2719b950fceefba9da0deaa9`, not collected by pytest), block lines 39-146, sha256 `12e9e282474cf4056dbbcfff87e554d006973dd1578d445822f5aa05e882274c`; the only change after the run is `FIXTURE_SHA256`, outside the block |
| block hashed at | 2026-11-21T14:22:28.707334991Z |
| run time (UTC) | `propose_action` called 2026-11-21T14:23:08.074862+00:00, returned 2026-11-21T14:25:11.475140+00:00; `tool_runs.started_at` 2026-11-21 14:23:10.696915+00:00, `finished_at` 2026-11-21 14:25:09.818774+00:00 |
| nmap version | `7.94SVN` |
| nmap image | `cyberorch/nmap:local`, id `sha256:f50d41e266e4df882f2a8b7600e34b776d4c9130e3ba008b39fc553b2e0ace5f`, **unchanged since run 1** |
| target image | `python:3.12-slim`, id `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`, **unchanged since run 1**, `--pull never` |
| command (from the raw artifact) | `/usr/bin/nmap -sT -sV -n --unprivileged -Pn -p 2222 --host-timeout 115s 10.82.0.10` (the same as run 1) |
| internal network | `cyberorch-allow-f55fc93de10e`, `Internal: true`, subnet `10.82.0.0/24` (gateway `10.82.0.1`), created by `DockerSandbox.ensure_network`, removed after the run |
| sandbox `network_allowlist` | `["10.82.0.0/24"]` |
| target | `10.82.0.10:2222`, container `d69b-run2-target-cc9a2901`, on that network only; removed after its logs were read |
| scan type, exit code, status | `version`; `0`; `succeeded` |
| run and evidence ids | `RUN-39c2aa4e4434`, `NMAP-e74632b5f492` (test engagement `ENG-TEST-D69B2-a2ea7f5f`) |
| raw artifact | `evidence_store/ENG-TEST-D69B2-a2ea7f5f/d3/d306f71a03223c8023d7776747a1af9ce3d46a495311407380d85b353e6fb781.bin`, 449 bytes (not committed) |
| this run's stdout | 332 bytes, sha256 `80dd5793f2c7abc817042f96d5e8f2784dd5bbc15e9d1667160dd1114df2a86d`; 0 bytes above 0x7f; 0 U+FFFD |

**What the run showed: still no banner.** nmap printed `Skipping host 10.82.0.10 due to host timeout`, then no port
table and no fingerprint: none of the six lures is in the stdout, and nothing in it shows how nmap writes ESC, 0x07
or a non-ASCII byte. Plan section 10 (8)'s question is still **not answered**.

**What the target's connection log showed** (one line per connection, read with `docker logs` before removal):
22 connections from the tool container `10.82.0.2`. The first (14:23:14) was reset by the peer before the banner
was sent (`sent 0 end exception ConnectionResetError`): nmap's `-sT` connect, which opens and drops the connection.
Every later one received the whole banner (108 bytes); the second ended by the target's 10-second timeout, and each
of the other 20 was closed by nmap about five seconds after it opened. Read together: the first connection
supports run 1's explanation (run 1's program caught no error, so that reset would have ended its service), and
the run-2 program, which keeps each connection open, made every version probe wait out its own timeout; 21 probes
of about five seconds used up the adapter's `--host-timeout 115s` (the stdout's own total: 116.25 seconds), and
nmap dropped the host without reporting its service. This reading is the implementer's; nmap's internal timings were
not traced.

**Results on this stdout (29 cases: 24 failed, 5 passed).** The six lures, unit level, builder and raw (12): all
`introduced_by_untrusted` false. The six lures through the loop, both actions (12): all `ALLOW`, false, no reasons --
not a fail-open, for the same reason as run 1: the lures never entered the evidence. Passed: the sample check
(sha256 as above) and the target's own address `10.82.0.10` (2 unit, 2 loop: introduced, `HUMAN_APPROVAL`,
`untrusted_discovery_source`). The sample check's line "derived view fields carrying a lure ['stdout_excerpt']"
matched on the target's own address (its filter tests for "82"), not on a lure.

## Note (2026-11-21)

Line 30 above names `tests/test_provenance_real_nmap.py`. That file has been moved, byte for byte, to this directory as
`run1_preregistered_test.py.txt` (sha256 `8b994c2380a04467313298ac5e5d2d907c361bd1eba24e2dea7b6ec5e9dae720`); the old
line is left as it was written. Neither of the two runs produced a banner, and no further run is made (plan items
126 and 128).
