#!/usr/bin/env bash
# Run from the GateHeal repo root BEFORE ruff/mypy/pytest and before packing the repo.
# Detects: syntax errors, files that contain two glued copies of themselves, and stray files.
set -u
fail=0
red() { printf 'INTEGRITY FAIL: %s\n' "$1"; fail=1; }

# 1. Python files must compile; shell scripts must parse.
while IFS= read -r f; do
    python3 -m py_compile "$f" 2>/dev/null || red "python syntax error: $f"
done < <(find src tests lab -name '*.py' -not -path '*/__pycache__/*')
while IFS= read -r f; do
    bash -n "$f" 2>/dev/null || red "shell syntax error: $f"
done < <(find lab -name '*.sh')

# 2. A file whose first line text appears again later in the same file is a duplicated/glued copy.
while IFS= read -r f; do
    first="$(head -n1 "$f")"
    [ "${#first}" -ge 12 ] || continue
    n="$(grep -cF -- "$first" "$f" || true)"
    [ "$n" -le 1 ] || red "first line repeated ${n}x (duplicated content): $f"
done < <(find src tests lab -type f \( -name '*.py' -o -name '*.sh' \) -not -path '*/__pycache__/*')

# 3. Stray files that must never be in the repo.
for p in project-codebase.md tests/lab/project-codebase.md fixtures test_wp5_real_lab.py \
         test_wp5_collector_on_real_fixtures.py; do
    [ -e "$p" ] && red "stray file or directory at repo root or tests/lab: $p"
done
find . -name 'project-codebase*.md' -not -path './.git/*' -not -path './.venv/*' | while read -r f; do
    printf 'INTEGRITY FAIL: packed-repo dump inside the repo: %s\n' "$f"
done | grep -q . && fail=1

# 4. A line 1 that starts with a bare file name glued to a docstring (e.g. lab_bringup.py"""...).
while IFS= read -r f; do
    head -n1 "$f" | grep -Eq '^[A-Za-z0-9_./-]+\.(py|sh)("""|#!)' && red "garbage file name glued to line 1: $f"
done < <(find src tests lab -type f \( -name '*.py' -o -name '*.sh' \) -not -path '*/__pycache__/*')

if [ "$fail" -eq 0 ]; then echo "INTEGRITY OK"; else echo "INTEGRITY FAILED"; exit 1; fi
