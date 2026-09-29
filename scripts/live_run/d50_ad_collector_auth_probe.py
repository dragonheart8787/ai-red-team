"""D50 -- probes behind docs/D50_AD_COLLECTOR_AUTH_GAP_INVESTIGATION.md.

Written as an investigation, not a fix: nothing here changes production code,
and every probe only *observes* how the real ``cyberorch/bloodhound:local`` image
(``bloodhound==1.9.0``) and the real D44 vault/sandbox path behave. It prints
observations, not pass/fail -- several of them are deliberately documenting
a defect, and a green exit would be the wrong signal for that.

**Status after the D50 follow-up (F1 + F3):** probes 1, 2, 4, 5 are unchanged and
still show the *tool's* behaviour. Probe 3 now shows the pre-fix separate-token
form as history (``build_plan`` emits the attached form since F3). Probe 6 now
shows ``build_plan`` *refusing* the uncredentialed capability (F1) instead of
running the dead command. Probes 2, 4 and 5 still document F2 (the secret is in
argv) -- that is undecided, pending the ADR addendum.

Needs: Docker running, ``cyberorch/bloodhound:local`` built
(``tool_gateway/images/build_bloodhound_image.sh``), Postgres provisioned
(only for probe 2, which uses the real vault). No domain controller needed.

    python scripts/live_run/d50_ad_collector_auth_probe.py            # all
    python scripts/live_run/d50_ad_collector_auth_probe.py --only 1 4
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.orchestrator.engagement import create_engagement  # noqa: E402
from control_plane.state.db import (  # noqa: E402
    credential_admin_scope,
    engagement_scope,
    registry_admin_scope,
)
from control_plane.vault import vault  # noqa: E402
from tool_gateway.adapters import ad_collector  # noqa: E402
from tool_gateway.sandbox import DockerSandbox  # noqa: E402

IMAGE = ad_collector.IMAGE
BH = ad_collector.BLOODHOUND_PYTHON_PATH
ACTOR = "d50-investigation"
LM_NT = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def docker_bh(args: list[str], *, network: str = "none", timeout: int = 20) -> tuple[int, str]:
    """Run the *real* bloodhound-python binary; DNS points at a blackhole so it
    stops at the DNS stage -- enough to see how far argument handling gets."""
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", network, "-i", IMAGE, "timeout", str(timeout),
         BH, "-d", "corp.test", "-c", "Group", "-ns", "192.0.2.1", "--dns-timeout", "1", "-v",
         *args],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def stage_of(out: str) -> str:
    if "expected one argument" in out:
        return "argparse rejected the value: 'expected one argument' (rc=2)"
    if "\nusage:" in "\n" + out:
        return "usage printed, exited before the AD object was built"
    for marker, label in (
        ("Authentication: username/password", "auth branch: username/password"),
        ("Authentication: NT hash", "auth branch: NT hash"),
        ("Authentication: Kerberos AES", "auth branch: Kerberos AES"),
    ):
        if marker in out:
            if "ValueError" in out:
                return f"{label}, then crashed parsing the value (before any DNS)"
            if "NoNameservers" in out or "LifetimeTimeout" in out:
                return f"{label} -> reached dns_resolve"
            return label
    for needle in ("error:", "ERROR:", "termios"):
        for line in out.splitlines():
            if needle in line:
                return f"refused: {line.strip()[:90]}"
    return "other"


# 1 ---------------------------------------------------------------------------

def probe_1_matrix() -> None:
    print("\n[1] Which credential shapes does the real binary accept? (no DC needed)")
    cases = [
        ("(no auth flag)  <- the pre-F1 uncredentialed command", []),
        ("--dns-tcp only", ["--dns-tcp"]),
        ("-no-pass only", ["-no-pass"]),
        ("-u alice -p secret", ["-u", "alice", "-p", "secret"]),
        ("-u alice --hashes LM:NT", ["-u", "alice", "--hashes", LM_NT]),
        ("-u alice --hashes <single hash>", ["-u", "alice", "--hashes", LM_NT.split(":")[1]]),
        ("-p secret (no -u)", ["-p", "secret"]),
        ("-k (no -u)", ["-k"]),
        ("-u alice -no-pass", ["-u", "alice", "-no-pass"]),
        ("-u alice -aesKey <hex>", ["-u", "alice", "-aesKey", "00112233445566778899aabbccddeeff"]),
    ]
    for label, args in cases:
        rc, out = docker_bh(args)
        print(f"  rc={rc}  {label:58s} {stage_of(out)}")


# 2 ---------------------------------------------------------------------------

_STUB = "#!/usr/local/bin/python3\nimport sys, json\nprint(json.dumps(sys.argv[1:]))\n"
_SECRETS = [
    ("plain", "password", "Passw0rd!"),
    ("spaces", "password", "a b  c"),
    ("shell metachars", "password", "$HOME $(id) `id` \"q\" 'q' \\ ; | & *"),
    ("leading dash", "password", "-abc123"),
    ("unicode", "password", "пароль密码"),
    ("trailing newline", "password", "abc\n"),
    ("LM:NT hash", "hashes", LM_NT),
]


def probe_2_delivery() -> None:
    print("\n[2] Does the vault-mounted secret reach the tool's argv intact?")
    print("    real: vault.store_credential/mount_for_run, ad_collector.build_plan,")
    print("          DockerSandbox.run")
    print("    stubbed: only the bloodhound binary (prints its argv)")
    load_dotenv()
    cidr = "10.93.0.0/24"
    eng = f"ENG-D50-{uuid.uuid4().hex[:8]}"
    with registry_admin_scope(eng) as conn:
        create_engagement(conn, engagement_id=eng, customer_id="CUST-D50", actor=ACTOR)
    box = DockerSandbox(image=IMAGE)
    box.ensure_image()
    box.ensure_network([cidr])
    tmp = Path(tempfile.mkdtemp(prefix="d50-stub-"))
    stub = tmp / "bloodhound-python"
    stub.write_text(_STUB)
    stub.chmod(0o755)
    try:
        for label, mode, sec in _SECRETS:
            cred_id = f"CRED-{uuid.uuid4().hex[:8]}"
            with credential_admin_scope(eng) as conn:
                vault.store_credential(
                    conn, engagement_id=eng, credential_id=cred_id, label="svc",
                    credential_type="ad_domain_bind", secret=sec, actor=ACTOR)
            run_id = f"RUN-{uuid.uuid4().hex[:8]}"
            with engagement_scope(eng) as conn:
                mounted = vault.mount_for_run(
                    conn, credential_id=cred_id, run_id=run_id, engagement_id=eng, actor=ACTOR)
            try:
                file_mode = oct(stat.S_IMODE(os.stat(mounted.host_path).st_mode))
                plan = ad_collector.build_plan(
                    constraints={"collection_methods": ["Group"], "domain_username": "alice",
                                 "auth_mode": mode},
                    budget={"max_duration_seconds": 30}, target="corp.test")
                res = box.run(
                    command=plan.command, network_allowlist=[cidr], max_duration_seconds=30,
                    run_id=run_id,
                    source_mounts={mounted.host_path: ad_collector.CONTAINER_CRED_PATH,
                                   str(stub): BH})
            finally:
                os.remove(mounted.host_path)
            argv = json.loads(res.stdout.strip().splitlines()[-1])
            prefix = "--password=" if mode == "password" else "--hashes="
            got = next(a for a in argv if a.startswith(prefix))[len(prefix):]
            verdict = "intact" if got == sec else f"DIFFERS, tool would receive {got!r}"
            print(f"  {label:18s} mounted file mode={file_mode}  -> {verdict}")
    finally:
        box.remove_network([cidr])


# 3 ---------------------------------------------------------------------------

def probe_3_argparse_dash() -> None:
    print("\n[3] A password starting with '-': the shell delivers it intact;")
    print("    does the tool's argument parser accept it?")
    for label, args in [
        ("-p -abc123   (the pre-F3 wrapper form)", ["-u", "alice", "-p", "-abc123"]),
        ("-p=-abc123", ["-u", "alice", "-p=-abc123"]),
        ("--password=-abc123", ["-u", "alice", "--password=-abc123"]),
    ]:
        rc, out = docker_bh(args)
        print(f"  rc={rc}  {label:40s} {stage_of(out)}")


# 4 ---------------------------------------------------------------------------

def _in_docker_top(canary: str, name: str) -> bool:
    top = subprocess.run(["docker", "top", name, "-eo", "pid,args"],
                         capture_output=True, text=True, check=False).stdout
    return canary in top


def probe_4_process_table() -> None:
    print("\n[4] Where can the secret be seen while the tool runs?  (ADR sec 2.1: 'never in argv')")
    canary = f"D50-canary-{secrets.token_hex(6)}"
    tmp = Path(tempfile.mkdtemp(prefix="d50-ps-"))
    secret_file, sleeper = tmp / "secret", tmp / "bloodhound-python"
    secret_file.write_text(canary)
    secret_file.chmod(0o644)
    sleeper.write_text("#!/usr/local/bin/python3\nimport time\ntime.sleep(25)\n")
    sleeper.chmod(0o755)
    plan = ad_collector.build_plan(
        constraints={"collection_methods": ["Group"], "domain_username": "alice"},
        budget={"max_duration_seconds": 60}, target="corp.test")

    name = "d50-ps-probe"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
         "-v", f"{secret_file}:{ad_collector.CONTAINER_CRED_PATH}:ro", "-v", f"{sleeper}:{BH}:ro",
         IMAGE, *plan.command], check=True, capture_output=True)
    time.sleep(3)
    inspect = subprocess.run(["docker", "inspect", name, "--format", "{{json .Config.Cmd}}"],
                             capture_output=True, text=True, check=False).stdout
    in_top = _in_docker_top(canary, name)
    host_lines = [ln.strip() for ln in subprocess.run(
        ["ps", "-eo", "args"], capture_output=True, text=True, check=False).stdout.splitlines()
        if canary in ln and ln.strip().startswith("/usr/local/bin/python3")]
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    print(f"  docker inspect Config.Cmd (what the daemon/control plane records) contains it: "
          f"{canary in inspect}")
    print(f"  docker top (host view of the container's processes) contains it: {in_top}")
    print(f"  host `ps` shows the tool process with the secret in argv:                      "
          f"{bool(host_lines)}")
    for ln in host_lines:
        print(f"      {ln[:110]}")


# 5 ---------------------------------------------------------------------------

def probe_5_inprocess_launcher() -> None:
    print("\n[5] Feasibility probe only: read the file in-process, then call bloodhound.main()")
    canary = f"D50-canary-{secrets.token_hex(6)}"
    tmp = Path(tempfile.mkdtemp(prefix="d50-inproc-"))
    secret_file = tmp / "secret"
    secret_file.write_text(canary)
    secret_file.chmod(0o644)
    launcher = (
        "import sys,bloodhound\n"
        "pw=open('/creds/secret').read()\n"
        "sys.argv=['bloodhound-python','-d','corp.test','-u','alice','--password='+pw,'-c','Group',"
        "'-ns','192.0.2.1','--dns-timeout','20','-v','--zip']\n"
        "bloodhound.main()\n"
    )
    name = "d50-inproc"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    subprocess.run(["docker", "run", "-d", "--name", name, "--read-only",
                    "-v", f"{secret_file}:/creds/secret:ro", IMAGE, "python3", "-c", launcher],
                   check=True, capture_output=True)
    time.sleep(4)
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True,
                          check=False)
    top = subprocess.run(["docker", "top", name, "-eo", "pid,args"], capture_output=True,
                         text=True, check=False).stdout
    host = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True,
                          check=False).stdout
    running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                             capture_output=True, text=True, check=False).stdout.strip()
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    combined = logs.stdout + logs.stderr
    reached = "Authentication: username/password" in combined
    print(f"  tool reached its auth branch: {reached}   still running (waiting on DNS): {running}")
    in_host_ps = any(
        canary in ln and "python3 -c" not in ln and "d50_ad_collector" not in ln
        for ln in host.splitlines())
    print(f"  secret visible in docker top: {canary in top}   in host ps: {in_host_ps}")


# 6 ---------------------------------------------------------------------------

def probe_6_uncredentialed_dispatch() -> None:
    print("\n[6] What happens to an ad.collect capability with no domain_username now (F1)?")
    print("    (before F1 this built a bare command; the real tool printed usage and exited 1)")
    for constraints in ({"collection_methods": ["Group", "ACL"]},
                        {"collection_methods": ["Group"], "domain_username": ""}):
        try:
            ad_collector.build_plan(
                constraints=constraints, budget={"max_duration_seconds": 30}, target="corp.test")
            print(f"  {constraints}: built a plan (UNEXPECTED -- F1 not in effect)")
        except ad_collector.AdapterError as exc:
            print(f"  {constraints}\n    -> refused: {str(exc)[:96]}...")


PROBES = {1: probe_1_matrix, 2: probe_2_delivery, 3: probe_3_argparse_dash,
          4: probe_4_process_table, 5: probe_5_inprocess_launcher,
          6: probe_6_uncredentialed_dispatch}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", type=int, nargs="*", choices=sorted(PROBES))
    args = parser.parse_args()
    for n in (args.only or sorted(PROBES)):
        PROBES[n]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
