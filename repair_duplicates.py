#!/usr/bin/env python3
"""GateHeal repo repair: keep the first complete copy of files that were applied as glued duplicates.
Run from repo root:  python3 repair_duplicates.py   (makes .bak copies; refuses unknown inputs)"""
import hashlib, pathlib, re, shutil, sys
FILES = {'src/gateheal/transport.py': '"""Isolated command transport layer preventing accidental host execution.', 'src/gateheal/lab_bringup.py': '"""WP5 real-lab conformance parser, SSH latency profiler, S', 'src/gateheal/agent.py': '"""Bounded LLM/Agentic proposal engines', 'lab/qemu/manage_vm.sh': '#!/usr/bin/env bash', 'lab/scripts/check_conformance.sh': '#!/usr/bin/env bash', 'lab/scripts/provision_guest.sh': '#!/usr/bin/env bash'}
HASHES = {'src/gateheal/transport.py': 'd50f7bd7c9d11cc3880b01aadc3a7a48d9ae1a1f34aa6bed647de57a0d2727d7', 'src/gateheal/lab_bringup.py': 'a2423d5807cee9c756ea6ed2f5f3475ece6a30d54f599ee1da11ab0397d51d94', 'src/gateheal/agent.py': '28418681d24ee730b1d96df3f317760affc06ee3288897dec3d8849c4012afd4', 'lab/qemu/manage_vm.sh': '6d57cae5400bce744736aef78016c0cd90859e655fae2878426d9ada7cf75371', 'lab/scripts/check_conformance.sh': '07b8b0c31e40a8b49955853193941ecc4dcf12e031d554e4cfb06a341f1c319d', 'lab/scripts/provision_guest.sh': 'cedec7ab10e1c1cf6385298a54428ce6e6c908c45fe44a665fb287048ac1b9ff'}
rc = 0
for f, key in FILES.items():
    p = pathlib.Path(f)
    if not p.exists():
        print("MISSING", f); rc = 1; continue
    raw = p.read_bytes()
    if hashlib.sha256(raw).hexdigest() != HASHES[f]:
        print("SKIP (content differs from the audited corrupted file)", f); rc = 1; continue
    t = raw.decode()
    idx = [m.start() for m in re.finditer(re.escape(key), t)]
    part = t[idx[0]:idx[1]] if len(idx) > 1 else t[idx[0]:]
    if f.endswith("lab_bringup.py"):
        part = re.sub(r"\n    \)lab_bringup\.py\s*$", "\n    )", part.rstrip("\n")) 
    if f.endswith("provision_guest.sh"):
        part = part.replace("printf 'from=\"127.0.0.1\" %s\\n'", "printf '%s\\n'")
        part = part.replace(' with from="127.0.0.1"', "")
        assert 'from="127.0.0.1"' not in part.split("PROVISION_OK")[0], "from= option still present"
    shutil.copy(p, str(p) + ".bak")
    p.write_text(part.rstrip("\n") + "\n")
    print("REPAIRED", f)
sys.exit(rc)
