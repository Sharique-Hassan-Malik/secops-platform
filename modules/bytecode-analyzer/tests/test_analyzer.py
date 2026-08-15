"""
Test suite for the bytecode obfuscation analyzer.

Tests operate on .pyc files compiled at test time from inline source
fixtures, so no pre-generated files are needed on disk.

Run with:
    python -m pytest tests/test_analyzer.py -v
"""

from __future__ import annotations

import marshal
import py_compile
import struct
import sys
import tempfile
from pathlib import Path
from types import CodeType

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from bytecode_config import AnalysisResult, ObfuscationKind
from analyzer.pyc_parser import PycParser, PycParseError
from analyzer.disassembler import Disassembler, walk_code_objects
from analyzer.decompiler import Decompiler
from analyzer.obfuscation import ObfuscationDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compile_source(source: str) -> bytes:
    """Compile Python source to .pyc bytes in memory."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(source)
        tmp = Path(f.name)
    pyc_path = tmp.with_suffix(".pyc")
    try:
        py_compile.compile(str(tmp), cfile=str(pyc_path), doraise=True)
        return pyc_path.read_bytes()
    finally:
        tmp.unlink(missing_ok=True)
        pyc_path.unlink(missing_ok=True)


def _disassemble_source(source: str):
    """Returns the root CodeObject for compiled source."""
    data = _compile_source(source)
    pyc  = PycParser().parse_bytes(data)
    return Disassembler().disassemble(pyc.code)


def _analyse_source(source: str) -> AnalysisResult:
    """Full pipeline: compile → parse → disassemble → detect."""
    data   = _compile_source(source)
    pyc    = PycParser().parse_bytes(data)
    root   = Disassembler().disassemble(pyc.code)
    result = AnalysisResult(path="<test>", python_version=pyc.python_version)
    ObfuscationDetector().analyse(root, result)
    return result


# ---------------------------------------------------------------------------
# PycParser tests
# ---------------------------------------------------------------------------

class TestPycParser:

    def test_parse_valid_pyc(self):
        data = _compile_source("x = 1")
        pyc  = PycParser().parse_bytes(data)
        assert pyc.python_version != "unknown"
        assert isinstance(pyc.code, CodeType)

    def test_magic_matches_running_python(self):
        data    = _compile_source("pass")
        pyc     = PycParser().parse_bytes(data)
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        assert pyc.python_version == version

    def test_too_short_raises(self):
        with pytest.raises(PycParseError):
            PycParser().parse_bytes(b"\x80\x02\r\n")

    def test_invalid_marshal_raises(self):
        # Valid header size but garbage marshal payload
        header = b"\x80\x02\r\n" + b"\x00" * 12
        with pytest.raises(PycParseError):
            PycParser().parse_bytes(header + b"\xff\xff\xff")

    def test_code_object_is_code_type(self):
        data = _compile_source("def f(): pass")
        pyc  = PycParser().parse_bytes(data)
        assert isinstance(pyc.code, CodeType)

    def test_timestamp_str_nonzero(self):
        s = PycParser.timestamp_str(1_700_000_000)
        assert "20" in s   # year starts with 20xx

    def test_timestamp_str_zero(self):
        assert PycParser.timestamp_str(0) == "N/A"


# ---------------------------------------------------------------------------
# Disassembler tests
# ---------------------------------------------------------------------------

class TestDisassembler:

    def test_instruction_list_nonempty(self):
        root = _disassemble_source("x = 1")
        assert len(root.instructions) > 0

    def test_stop_opcode_present(self):
        root = _disassemble_source("x = 1")
        names = [i.opname for i in root.instructions]
        assert "STOP_CODE" in names or "RETURN_VALUE" in names or "RESUME" in names

    def test_load_const_resolves_value(self):
        root   = _disassemble_source("x = 42")
        consts = [i for i in root.instructions if i.opname == "LOAD_CONST" and i.argval == 42]
        assert consts

    def test_load_name_resolves_string(self):
        root  = _disassemble_source("print(x)")
        names = [i for i in root.instructions
                 if i.opname in ("LOAD_NAME", "LOAD_GLOBAL") and i.argrepr == "print"]
        assert names

    def test_nested_function_creates_child(self):
        root = _disassemble_source("def f():\n    return 1")
        assert len(root.children) > 0

    def test_walk_visits_children(self):
        root = _disassemble_source("def f():\n    def g():\n        pass")
        all_names = [co.name for co in walk_code_objects(root)]
        assert "f" in all_names
        assert "g" in all_names

    def test_instruction_offsets_monotone(self):
        root    = _disassemble_source("a = 1\nb = 2\nc = 3")
        offsets = [i.offset for i in root.instructions]
        assert offsets == sorted(offsets)

    def test_code_object_name(self):
        root = _disassemble_source("def my_function(): pass")
        child_names = [c.name for c in root.children]
        assert "my_function" in child_names

    def test_argcount(self):
        root  = _disassemble_source("def f(a, b, c): pass")
        child = next(c for c in root.children if c.name == "f")
        assert child.argcount == 3


# ---------------------------------------------------------------------------
# Decompiler tests
# ---------------------------------------------------------------------------

class TestDecompiler:

    def test_assignment_appears(self):
        root = _disassemble_source("x = 42")
        out  = Decompiler().decompile(root)
        assert "x" in out
        assert "42" in out

    def test_function_signature_appears(self):
        root = _disassemble_source("def greet(name):\n    return name")
        out  = Decompiler().decompile(root)
        assert "def greet" in out

    def test_return_statement(self):
        root = _disassemble_source("def f():\n    return 99")
        child = root.children[0]
        out  = Decompiler().decompile(child, indent=1)
        assert "return" in out
        assert "99" in out

    def test_does_not_raise_on_complex(self):
        src = "x = [i*2 for i in range(10)]\nprint(x)"
        root = _disassemble_source(src)
        out  = Decompiler().decompile(root)   # should not raise
        assert isinstance(out, str)


# ---------------------------------------------------------------------------
# Obfuscation detector tests
# ---------------------------------------------------------------------------

class TestObfuscationDetector:

    def test_clean_code_no_findings(self):
        result = _analyse_source('"""Clean module."""\n\ndef greet(name):\n    return f"Hello {name}"\n')
        high_conf = [f for f in result.findings if f.confidence >= 0.7]
        assert not any(
            f.kind in (ObfuscationKind.EXEC_EVAL_USE, ObfuscationKind.DYNAMIC_IMPORT,
                       ObfuscationKind.CHR_CHAIN, ObfuscationKind.MANGLED_NAMES)
            for f in high_conf
        )

    def test_exec_eval_detected(self):
        result = _analyse_source('exec("x = 1")')
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.EXEC_EVAL_USE in kinds

    def test_dynamic_import_detected(self):
        result = _analyse_source('__import__("os")')
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.DYNAMIC_IMPORT in kinds

    def test_chr_chain_detected(self):
        chain  = " + ".join(f"chr({ord(c)})" for c in "hello world")
        result = _analyse_source(f"x = {chain}")
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.CHR_CHAIN in kinds

    def test_mangled_names_detected(self):
        src = (
            "lll1lll = 1\nl1lll1l = 2\n"
            "_0O0O0O0 = lll1lll + l1lll1l\n"
            "IIIlIIl = str(_0O0O0O0)\n"
            "llIllIll = len(IIIlIIl)\n"
        )
        result = _analyse_source(src)
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.MANGLED_NAMES in kinds

    def test_opaque_predicate_detected(self):
        src = "x = 0\nif 1 == 1:\n    x = 1\nif 2 > 3:\n    x = 2\nif 4 < 4:\n    x = 3\n"
        result = _analyse_source(src)
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.OPAQUE_PREDICATE in kinds

    def test_obfuscation_score_high_for_exec(self):
        result = _analyse_source('exec(compile("x=1","<s>","exec"))')
        assert result.obfuscation_score > 0.3

    def test_obfuscation_score_low_for_clean(self):
        result = _analyse_source("x = 1\ny = 2\nz = x + y\n")
        assert result.obfuscation_score < 0.4

    def test_code_objects_counted(self):
        result = _analyse_source("def f():\n    def g():\n        pass")
        assert result.code_objects >= 3   # module + f + g

    def test_base64_pattern_detected(self):
        src = (
            "import base64\n"
            "_d = b'aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgZW5vdWdoIHN0cmluZw=='\n"
            "x = base64.b64decode(_d)\n"
        )
        result = _analyse_source(src)
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.BASE64_ENCODED in kinds

    def test_control_flow_flat_detected(self):
        src = """\
state = 0
result = []
while True:
    if state == 0:
        result.append("a"); state = 1
    elif state == 1:
        result.append("b"); state = 2
    elif state == 2:
        result.append("c"); state = 3
    elif state == 3:
        result.append("d"); state = 4
    elif state == 4:
        break
"""
        result = _analyse_source(src)
        kinds  = [f.kind for f in result.findings]
        assert ObfuscationKind.CONTROL_FLOW_FLATTEN in kinds

    def test_obfuscated_property_true_for_exec(self):
        result = _analyse_source("eval('1+1')")
        assert result.obfuscated is True

    def test_result_has_no_error_for_valid_source(self):
        result = _analyse_source("x = 1")
        assert result.error == ""
