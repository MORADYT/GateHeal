#!/usr/bin/env python3
"""Structural repair for glued duplicate shell scripts (no hash guard).
Run from repo root: python3 repair_shell_v2.py
For each lab/**/*.sh whose '#!/usr/bin/env bash' line occurs more than once, keep ONLY the first
copy (the newest complete one in every audited case), save <file>.bak, and verify with bash -n.
Also deletes the stray tests/lab/project-codebase.md / root project-codebase.md if present."""
import pathlib, re, shutil, subprocess, sys
SHEBANG = "#!/usr/bin/env bash"
rc = 0
for p in sorted(pathlib.Path("lab").rglob("*.sh")):
    t = p.read_text()
    idx = [m.start() for m in re.finditer(re.escape(SHEBANG), t)]
    if len(idx) <= 1:
        print("OK      ", p); continue
    first = t[idx[0]:idx[1]]
    shutil.copy(p, str(p) + ".bak")
    p.write_text(first.rstrip("\n") + "\n")
    ok = subprocess.run(["bash", "-n", str(p)]).returncode == 0
    print("REPAIRED" if ok else "STILL BROKEN", p, f"({len(idx)} copies -> 1, {first.count(chr(10))} lines)")
    rc |= 0 if ok else 1
for stray in ("project-codebase.md", "tests/lab/project-codebase.md"):
    q = pathlib.Path(stray)
    if q.exists():
        q.unlink(); print("DELETED stray", q)
print("Now delete *.bak files before packing:  find . -name '*.bak' -delete")
sys.exit(rc)
