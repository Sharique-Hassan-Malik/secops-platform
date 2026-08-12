#!/usr/bin/env python3
"""
Compiles Python source fixtures to .pyc files for the test suite.
Each fixture demonstrates a specific obfuscation technique.

Run from the project root:
    python scripts/make_fixtures.py
"""

import marshal
import py_compile
import struct
import sys
import tempfile
import time
from pathlib import Path

OUT_DIR = Path(__file__).parent.parent / "tests" / "fixtures"


# ---------------------------------------------------------------------------
# Source fixtures
# ---------------------------------------------------------------------------

FIXTURES: dict[str, str] = {

"clean.py": '''\
"""A clean, unobfuscated module."""

def greet(name):
    return f"Hello, {name}!"

result = greet("world")
print(result)
''',

"chr_chain.py": '''\
# String hidden as chr() chain
secret = chr(104) + chr(101) + chr(108) + chr(108) + chr(111) + chr(32) + \
         chr(119) + chr(111) + chr(114) + chr(108) + chr(100)
print(secret)
''',

"exec_payload.py": '''\
import base64
_p = b"cHJpbnQoJ2hlbGxvJyk="
exec(base64.b64decode(_p).decode())
''',

"dynamic_import.py": '''\
_m = __import__("os")
_f = getattr(_m, "system")
_f("id")
''',

"mangled_names.py": '''\
lll1lll = 1
l1lll1l = 2
_0O0O0O0 = lll1lll + l1lll1l
IIIlIIl = str(_0O0O0O0)
llIllIll = len(IIIlIIl)
O0O0O0O0 = lll1lll * l1lll1l
''',

"opaque_predicates.py": '''\
# Constant-vs-constant comparisons always evaluate to the same result
if 1 == 1:
    x = "real code"
if 2 > 3:
    x = "never runs"
if True != False:
    y = "also real"
result = x
''',

"dead_code.py": '''\
def example():
    x = 1
    return x
    y = 2          # dead — after return
    z = x + y      # dead
    return z       # dead

example()
''',

"control_flow_flat.py": '''\
# Simulated control-flow flattening via state dispatcher
state = 0
result = []
while True:
    if state == 0:
        result.append("a")
        state = 1
    elif state == 1:
        result.append("b")
        state = 2
    elif state == 2:
        result.append("c")
        state = 3
    elif state == 3:
        result.append("d")
        state = 4
    elif state == 4:
        break
''',

}


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def compile_to_pyc(source: str, name: str, out_path: Path):
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(source)
        tmp = f.name
    try:
        pyc_tmp = tmp + "c"
        py_compile.compile(tmp, cfile=pyc_tmp, doraise=True)
        Path(pyc_tmp).rename(out_path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ok = 0
    for src_name, source in FIXTURES.items():
        pyc_name = src_name.replace(".py", ".pyc")
        out_path = OUT_DIR / pyc_name
        try:
            compile_to_pyc(source, src_name, out_path)
            print(f"  compiled  {out_path.name}")
            ok += 1
        except Exception as exc:
            print(f"  FAILED    {src_name}: {exc}")

    print(f"\n{ok}/{len(FIXTURES)} fixtures compiled to {OUT_DIR}/")


if __name__ == "__main__":
    main()
