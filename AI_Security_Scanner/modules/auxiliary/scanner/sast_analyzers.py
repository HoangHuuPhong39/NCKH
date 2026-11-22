# -*- coding: utf-8 -*-
"""
modules/auxiliary/scanner/sast_analyzers.py - Deep SAST Analysis Engines

Cung cấp các tầng phân tích mã nguồn tĩnh chuyên sâu cho AICodeScanner:
  1. PythonASTAnalyzer (Tầng 1–4):
     - Tầng 1: AST Constant Folding & Static De-obfuscation (chuỗi, boolean, XOR, Base64, Hex)
     - Tầng 2: Symbolic Alias, Dynamic Import Loader Summary & **kwargs Dict Unpacking
     - Tầng 3: Mở rộng Sinks (compile+FunctionType, urllib/aiohttp SSRF & timeout, Vector DB Filter Injection)
     - Tầng 4: Intra-procedural Taint, Class Attribute Taint (self.<attr>), Decorator Sink & Sanitizers
  2. CrossFileTaintAnalyzer (Tầng 5):
     - Phân tích taint xuyên file trong scan_directory() bằng fixed-point iteration (tối đa 4 vòng),
       hỗ trợ import alias, relative import, chống circular import bằng tập visited.
  3. Multi-Format Analyzers:
     - YAML Analyzer (dùng yaml.safe_load() bung Anchor/Alias)
     - Modelfile Directive Parser (FROM / PARAMETER / SYSTEM block)
     - JS/TS Static Analyzer (Array.join folding, new Function RCE, Tagged Template Prompt Injection)

Lưu ý an toàn: Tuyệt đối KHÔNG gọi eval()/exec() thật lên mã nguồn đang quét.
"""

from __future__ import annotations

import ast
import base64
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import yaml

# Sentinel biểu thị biểu thức không thể gấp hằng tĩnh
_UNRESOLVED = object()

# Giới hạn chống DoS khi gấp hằng tĩnh
_MAX_SEQ_LEN = 512
_MAX_STR_LEN = 4096

# Bộ nhận diện bí mật sau khi giải mã / gấp hằng tĩnh
SECRET_VALUE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"sk-(?:proj-|ant-|live-|test-|prod-)?[a-zA-Z0-9_\-]{12,}"), "OpenAI / Anthropic API Key"),
    (re.compile(r"hf_[a-zA-Z0-9]{16,}"), "HuggingFace Access Token"),
    (re.compile(r"gsk_[a-zA-Z0-9]{16,}"), "Groq API Key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{20,}"), "Google AI API Key"),
    (re.compile(r"whsec_[a-zA-Z0-9_\-]{16,}"), "Webhook Signing Secret"),
    (
        re.compile(r"(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@"),
        "Hardcoded Database Credentials URI",
    ),
]

# Các hàm Sanitizer gỡ nhãn taint
SANITIZER_FUNCS: Set[str] = {
    "int",
    "float",
    "bool",
    "shlex.quote",
    "re.fullmatch",
    "ast.literal_eval",
    "bleach.clean",
    "html.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
}

# Các tên tham số thường đại diện cho dữ liệu đầu vào không tin cậy (taint sources)
TAINT_PARAM_RE = re.compile(
    r"(?:^|_)(?:user|customer|client|input|query|question|prompt|ticket|note|notes|text|msg|message|"
    r"req|request|body|payload|raw|url|uri|host|filter|filters|expr|expression|sql|cmd|command|code|"
    r"llm|ai|output|reply|response|blob|data|context|doc|content|comment|feedback|description|email|"
    r"subject|chat|history)(?:$|_|\d)",
    re.IGNORECASE,
)

# Các sink giải tuần tự hóa nguy hiểm
UNSAFE_DESER_SINKS: Set[str] = {
    "pickle.load",
    "pickle.loads",
    "_pickle.load",
    "_pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "dill.load",
    "dill.loads",
    "joblib.load",
    "torch.load",
}

# Các sink thực thi mã động nguy hiểm
UNSAFE_EXEC_SINKS: Set[str] = {
    "eval",
    "builtins.eval",
    "exec",
    "builtins.exec",
}

# Các sink gọi lệnh hệ thống
SUBPROCESS_SINKS: Set[str] = {
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}

# Các sink HTTP có thể dẫn tới SSRF / thiếu timeout
HTTP_CLIENT_SINKS: Set[str] = {
    "urllib.request.urlopen",
    "urllib.request.Request",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.request",
}

# Các phương thức truy vấn Vector DB
VECTOR_QUERY_METHODS: Set[str] = {
    "query",
    "similarity_search",
    "similarity_search_with_score",
    "search",
}

# Các khóa khóa cứng tenant trong Vector DB
TENANT_LOCK_KEYS: Set[str] = {"tenant_id", "org_id", "organization_id", "workspace_id", "owner_id", "account_id"}

# Các tool nguy hiểm trong cấu hình YAML Agent
YAML_DANGEROUS_EXEC_TOOLS: Set[str] = {
    "shell_exec",
    "bash",
    "bash_exec",
    "filesystem_write",
    "file_write",
    "code_exec",
    "python_repl",
    "eval",
    "os_command",
}
YAML_DANGEROUS_NET_TOOLS: Set[str] = {
    "http_fetch_any",
    "unrestricted_http",
    "fetch_url_any",
    "ssrf_fetch",
}


def _redact_secret(val: str) -> str:
    """Ẩn phần giữa của bí mật khi hiển thị bằng chứng."""
    if len(val) <= 12:
        return val[:4] + "****"
    return f"{val[:8]}...{val[-4:]}"


def match_secret_value(val: str) -> Optional[str]:
    """Kiểm tra chuỗi có khớp pattern bí mật đã biết hay không (bỏ qua mẫu toàn số 0)."""
    if not isinstance(val, str) or len(val) < 12 or len(val) > _MAX_STR_LEN:
        return None
    for pat, label in SECRET_VALUE_PATTERNS:
        m = pat.search(val)
        if m:
            matched = m.group(0)
            # Bỏ qua placeholder toàn số 0 như sk-proj-0000000000000000
            tail = re.sub(r"^(?:sk-(?:proj-|ant-|live-|test-|prod-)?|hf_|gsk_|whsec_|AIza)", "", matched)
            if tail and set(tail) <= {"0", "x", "X", "*"}:
                continue
            return label
    return None


def get_ast_func_name(func_node: ast.AST) -> str:
    """Lấy tên chuỗi đầy đủ của node hàm (ví dụ: urllib.request.urlopen)."""
    if isinstance(func_node, ast.Name):
        return func_node.id
    if isinstance(func_node, ast.Attribute):
        prefix = get_ast_func_name(func_node.value)
        return f"{prefix}.{func_node.attr}" if prefix else func_node.attr
    return ""


def _resolve_import_aliases(tree: ast.AST) -> Dict[str, str]:
    """Thu thập ánh xạ import alias trong module (import X as Y, from X import Y as Z)."""
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{mod}.{alias.name}" if mod else alias.name
    return aliases


def _canonicalize_name(name: str, import_aliases: Dict[str, str], var_aliases: Dict[str, str]) -> str:
    """Chuẩn hóa tên hàm theo biến alias cục bộ và import alias."""
    if not name:
        return ""
    if name in var_aliases:
        return var_aliases[name]
    parts = name.split(".")
    if parts[0] in var_aliases:
        resolved_head = var_aliases[parts[0]]
        return ".".join([resolved_head] + parts[1:])
    if name in import_aliases:
        return import_aliases[name]
    if parts[0] in import_aliases:
        return ".".join([import_aliases[parts[0]]] + parts[1:])
    return name


# ──────────────────────────────────────────────────────────────────────────────
# Tầng 1: AST Constant Folding & Static De-obfuscation
# ──────────────────────────────────────────────────────────────────────────────
def eval_static_expr(
    node: ast.AST,
    env: Dict[str, Any],
    import_aliases: Optional[Dict[str, str]] = None,
    depth: int = 0,
) -> Any:
    """
    Gấp hằng biểu thức Python AST hoàn toàn tĩnh (KHÔNG dùng eval/exec).
    Hỗ trợ: Constant, Name, Attribute (cls.X / self.X), List/Tuple/Dict (+ **unpack),
    BinOp (+, ^, |, *), UnaryOp (not, -), Compare (==, !=, <, >...), BoolOp,
    bool(), int(), str(), chr(), str.join(list / genexpr / listcomp),
    base64.b64decode(), bytes.fromhex().
    """
    if depth > 12 or node is None:
        return _UNRESOLVED

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        return env.get(node.id, _UNRESOLVED)

    if isinstance(node, ast.Attribute):
        full = get_ast_func_name(node)
        if full in env:
            return env[full]
        if isinstance(node.value, ast.Name) and node.value.id in ("cls", "self"):
            if f"__cls__.{node.attr}" in env:
                return env[f"__cls__.{node.attr}"]
            if node.attr in env:
                return env[node.attr]
        base_val = eval_static_expr(node.value, env, import_aliases, depth + 1)
        if isinstance(base_val, dict) and node.attr in base_val:
            return base_val[node.attr]
        return _UNRESOLVED

    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > _MAX_SEQ_LEN:
            return _UNRESOLVED
        vals = []
        for el in node.elts:
            v = eval_static_expr(el, env, import_aliases, depth + 1)
            if v is _UNRESOLVED:
                return _UNRESOLVED
            vals.append(v)
        return vals if isinstance(node, ast.List) else tuple(vals)

    if isinstance(node, ast.Dict):
        out: Dict[Any, Any] = {}
        for k_node, v_node in zip(node.keys, node.values):
            if k_node is None:
                # Dict unpacking {..., **other}
                unpacked = eval_static_expr(v_node, env, import_aliases, depth + 1)
                if isinstance(unpacked, dict):
                    out.update(unpacked)
                else:
                    return _UNRESOLVED
            else:
                k_val = eval_static_expr(k_node, env, import_aliases, depth + 1)
                v_val = eval_static_expr(v_node, env, import_aliases, depth + 1)
                if k_val is _UNRESOLVED:
                    return _UNRESOLVED
                out[k_val] = v_val
        return out

    if isinstance(node, ast.UnaryOp):
        operand = eval_static_expr(node.operand, env, import_aliases, depth + 1)
        if operand is _UNRESOLVED:
            return _UNRESOLVED
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub) and isinstance(operand, (int, float)):
            return -operand
        if isinstance(node.op, ast.UAdd) and isinstance(operand, (int, float)):
            return +operand
        return _UNRESOLVED

    if isinstance(node, ast.BinOp):
        left = eval_static_expr(node.left, env, import_aliases, depth + 1)
        right = eval_static_expr(node.right, env, import_aliases, depth + 1)
        if left is _UNRESOLVED or right is _UNRESOLVED:
            return _UNRESOLVED
        if isinstance(node.op, ast.Add):
            if isinstance(left, str) and isinstance(right, str):
                if len(left) + len(right) <= _MAX_STR_LEN:
                    return left + right
            elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
                return left + right
            elif isinstance(left, list) and isinstance(right, list):
                if len(left) + len(right) <= _MAX_SEQ_LEN:
                    return left + right
        elif isinstance(node.op, ast.BitXor) and isinstance(left, int) and isinstance(right, int):
            return left ^ right
        elif isinstance(node.op, ast.BitOr) and isinstance(left, dict) and isinstance(right, dict):
            return {**left, **right}
        elif isinstance(node.op, ast.Mult):
            if isinstance(left, str) and isinstance(right, int) and 0 <= right <= 256:
                if len(left) * right <= _MAX_STR_LEN:
                    return left * right
            elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
                return left * right
        return _UNRESOLVED

    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        left = eval_static_expr(node.left, env, import_aliases, depth + 1)
        right = eval_static_expr(node.comparators[0], env, import_aliases, depth + 1)
        if left is _UNRESOLVED or right is _UNRESOLVED:
            return _UNRESOLVED
        op = node.ops[0]
        try:
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.LtE):
                return left <= right
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.GtE):
                return left >= right
        except TypeError:
            return _UNRESOLVED
        return _UNRESOLVED

    if isinstance(node, ast.BoolOp):
        vals = [eval_static_expr(v, env, import_aliases, depth + 1) for v in node.values]
        if any(v is _UNRESOLVED for v in vals):
            return _UNRESOLVED
        if isinstance(node.op, ast.And):
            return all(vals)
        if isinstance(node.op, ast.Or):
            return any(vals)
        return _UNRESOLVED

    if isinstance(node, ast.Call):
        raw_fn = get_ast_func_name(node.func)
        fn_name = _canonicalize_name(raw_fn, import_aliases or {}, {})

        # <sep>.join(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and len(node.args) == 1:
            sep = eval_static_expr(node.func.value, env, import_aliases, depth + 1)
            if not isinstance(sep, str):
                return _UNRESOLVED
            arg0 = node.args[0]
            # Trường hợp GeneratorExp / ListComp (ví dụ: "".join(chr(b ^ MASK) for b in RAW_BUFFER))
            if isinstance(arg0, (ast.GeneratorExp, ast.ListComp)) and len(arg0.generators) == 1:
                gen = arg0.generators[0]
                if isinstance(gen.target, ast.Name) and not gen.ifs:
                    iter_val = eval_static_expr(gen.iter, env, import_aliases, depth + 1)
                    if isinstance(iter_val, (list, tuple, bytes)) and len(iter_val) <= _MAX_SEQ_LEN:
                        items: List[str] = []
                        for item in iter_val:
                            local_env = dict(env)
                            local_env[gen.target.id] = item
                            ev = eval_static_expr(arg0.elt, local_env, import_aliases, depth + 1)
                            if not isinstance(ev, str):
                                return _UNRESOLVED
                            items.append(ev)
                        joined = sep.join(items)
                        return joined if len(joined) <= _MAX_STR_LEN else _UNRESOLVED
                return _UNRESOLVED

            seq = eval_static_expr(arg0, env, import_aliases, depth + 1)
            if isinstance(seq, (list, tuple)) and len(seq) <= _MAX_SEQ_LEN and all(isinstance(x, str) for x in seq):
                joined = sep.join(seq)
                return joined if len(joined) <= _MAX_STR_LEN else _UNRESOLVED
            return _UNRESOLVED

        # bool(x), int(x), str(x), chr(x)
        if fn_name == "bool" and len(node.args) == 1:
            v = eval_static_expr(node.args[0], env, import_aliases, depth + 1)
            return bool(v) if v is not _UNRESOLVED else _UNRESOLVED
        if fn_name == "int" and len(node.args) == 1:
            v = eval_static_expr(node.args[0], env, import_aliases, depth + 1)
            try:
                return int(v) if v is not _UNRESOLVED else _UNRESOLVED
            except (ValueError, TypeError):
                return _UNRESOLVED
        if fn_name == "str" and len(node.args) == 1:
            v = eval_static_expr(node.args[0], env, import_aliases, depth + 1)
            return str(v) if v is not _UNRESOLVED else _UNRESOLVED
        if fn_name == "chr" and len(node.args) == 1:
            v = eval_static_expr(node.args[0], env, import_aliases, depth + 1)
            if isinstance(v, int) and 0 <= v <= 0x10FFFF:
                return chr(v)
            return _UNRESOLVED

        # base64.b64decode(...)
        if fn_name in ("base64.b64decode", "b64decode") and len(node.args) == 1:
            v = eval_static_expr(node.args[0], env, import_aliases, depth + 1)
            if isinstance(v, (str, bytes)) and len(v) <= _MAX_STR_LEN:
                try:
                    raw = base64.b64decode(v)
                    return raw.decode("utf-8", errors="ignore")
                except Exception:
                    return _UNRESOLVED

        # bytes.fromhex(...) / bytearray.fromhex(...)
        if fn_name in ("bytes.fromhex", "bytearray.fromhex") and len(node.args) == 1:
            v = eval_static_expr(node.args[0], env, import_aliases, depth + 1)
            if isinstance(v, str) and len(v) <= _MAX_STR_LEN:
                try:
                    raw = bytes.fromhex(v)
                    return raw.decode("utf-8", errors="ignore")
                except Exception:
                    return _UNRESOLVED

        # <bytes>.decode(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            base_v = eval_static_expr(node.func.value, env, import_aliases, depth + 1)
            if isinstance(base_v, bytes):
                return base_v.decode("utf-8", errors="ignore")
            if isinstance(base_v, str):
                return base_v

    return _UNRESOLVED


# ──────────────────────────────────────────────────────────────────────────────
# Tầng 1–4: Python AST Semantic & Taint Analyzer
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class DynamicLoaderSummary:
    """Tóm tắt một hàm helper tải symbol động qua importlib.import_module + getattr."""

    func_name: str
    mod_param_idx: int
    attr_param_idx: int
    attr_joined: bool = False
    join_sep: str = ""


@dataclass
class DecoratorSinkSummary:
    """Tóm tắt decorator gọi fn(...) rồi đẩy kết quả vào sink nguy hiểm."""

    decorator_name: str
    rule_id: str
    sink_name: str
    sink_line: int


@dataclass
class ClassAttrTaintInfo:
    """Theo dõi thuộc tính self.<attr> bị taint trong một class."""

    tainted_attrs: Set[str] = field(default_factory=set)
    tainting_methods: Dict[str, Set[str]] = field(default_factory=dict)  # method -> set of attrs tainted
    returning_attrs: Dict[str, Set[str]] = field(default_factory=dict)  # method -> set of attrs returned
    mixed_return_methods: Set[str] = field(default_factory=set)  # method nối/join self.<attr> thành prompt


class PythonASTAnalyzer:
    """
    Bộ phân tích AST Python 4 tầng nội bộ file:
      - Tầng 1: Constant Folding & De-obfuscation (XOR/Base64/Hex/String concat)
      - Tầng 2: Symbolic Alias, Dynamic Loader Summary & **kwargs Unpacking
      - Tầng 3: Mở rộng Sinks (compile+FunctionType, urllib/aiohttp, Vector DB Filter)
      - Tầng 4: Intra-procedural Taint, Class Attribute Taint, Decorator Sink & Sanitizers
    """

    def __init__(
        self,
        code: str,
        filename: str,
        lines: List[str],
        rules_by_id: Dict[str, Dict[str, Any]],
        format_snippet_fn: Callable[[List[str], int, Optional[int]], str],
        existing_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.code = code
        self.filename = filename
        self.lines = lines
        self.rules_by_id = rules_by_id
        self.format_snippet = format_snippet_fn
        self.existing_findings = existing_findings or []
        self.findings: List[Dict[str, Any]] = []
        self.import_aliases: Dict[str, str] = {}
        self.dynamic_loaders: Dict[str, DynamicLoaderSummary] = {}
        self.decorator_sinks: Dict[str, DecoratorSinkSummary] = {}
        self.class_taint: Dict[str, ClassAttrTaintInfo] = {}
        self.method_returns_external: Set[str] = set()  # method đọc dữ liệu ngoài (HTTP/RAG)
        self.method_passthrough_taint: Set[str] = set()  # method biến đổi chuỗi giữ nguyên taint

    def analyze(self) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(self.code, filename=self.filename)
        except SyntaxError:
            return []

        self.import_aliases = _resolve_import_aliases(tree)

        # Thu thập hằng số cấp module & cấp class
        module_env = self._collect_module_constants(tree)

        # Pass chuẩn bị: tóm tắt Dynamic Loaders, Decorator Sinks, Class Attribute Taint & Helper Methods
        self._summarize_dynamic_loaders(tree)
        self._summarize_decorator_sinks(tree)
        self._summarize_classes_and_helpers(tree)

        # Quét mức module (top-level statements)
        self._analyze_statements(
            tree.body,
            env=dict(module_env),
            var_aliases={},
            tainted_vars={},
            sanitized_vars=set(),
            dict_risk_vars={},
            dynamic_code_vars=set(),
            obj_class_map={},
            tainted_objs=set(),
        )

        # Quét từng class và method / function
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node, module_env, class_name=None, class_env=None)
            elif isinstance(node, ast.ClassDef):
                cls_env = self._collect_class_constants(node, module_env)
                # Kiểm tra secret ẩn ngay trong thân class (ví dụ class attribute)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function(item, module_env, class_name=node.name, class_env=cls_env)

        return self.findings

    # ── Helpers báo cáo & khử trùng lặp ───────────────────────────────────────
    def _already_reported(self, rule_id: str, line_no: int) -> bool:
        if any(
            f["rule_id"] == rule_id and abs(f["line"] - line_no) <= 2 and f["file"] == self.filename
            for f in self.existing_findings
        ):
            return True
        return any(
            f["rule_id"] == rule_id and f["line"] == line_no and f["file"] == self.filename
            for f in self.findings
        )

    def _emit(
        self,
        rule_id: str,
        line_no: int,
        end_line_no: Optional[int] = None,
        engine: str = "Python AST Semantic & Taint Analyzer",
        extra_detail: str = "",
        allow_enrich_existing: bool = False,
    ) -> None:
        if not allow_enrich_existing and self._already_reported(rule_id, line_no):
            return
        if allow_enrich_existing and any(
            f["rule_id"] == rule_id and abs(f["line"] - line_no) <= 2 and f["file"] == self.filename
            for f in self.findings
        ):
            return
        rule = self.rules_by_id.get(rule_id)
        if not rule:
            return
        code_line = self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else ""
        ctx_snip = self.format_snippet(self.lines, line_no, end_line_no)
        desc = rule["description"]
        if extra_detail:
            desc = f"{desc} [Chi tiết AST: {extra_detail}]"
        self.findings.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "owasp": rule["owasp"],
            "mitre": rule["mitre"],
            "cwe": rule["cwe"],
            "file": self.filename,
            "line": line_no,
            "code_line": code_line[:220],
            "context_snippet": ctx_snip,
            "description": desc,
            "remediation": rule["remediation"],
            "fix_example": rule["fix_example"],
            "engine": engine,
        })

    # ── Thu thập hằng số cấp module & class ──────────────────────────────────
    def _collect_module_constants(self, tree: ast.Module) -> Dict[str, Any]:
        env: Dict[str, Any] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                val = eval_static_expr(stmt.value, env, self.import_aliases)
                if val is not _UNRESOLVED:
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            env[t.id] = val
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
                val = eval_static_expr(stmt.value, env, self.import_aliases)
                if val is not _UNRESOLVED:
                    env[stmt.target.id] = val
        return env

    def _collect_class_constants(self, cls_node: ast.ClassDef, module_env: Dict[str, Any]) -> Dict[str, Any]:
        env = dict(module_env)
        for stmt in cls_node.body:
            if isinstance(stmt, ast.Assign):
                val = eval_static_expr(stmt.value, env, self.import_aliases)
                if val is not _UNRESOLVED:
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            env[t.id] = val
                            env[f"__cls__.{t.id}"] = val
                            env[f"{cls_node.name}.{t.id}"] = val
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
                val = eval_static_expr(stmt.value, env, self.import_aliases)
                if val is not _UNRESOLVED:
                    env[stmt.target.id] = val
                    env[f"__cls__.{stmt.target.id}"] = val
                    env[f"{cls_node.name}.{stmt.target.id}"] = val
        return env

    # ── Tầng 2: Tóm tắt tổng quát mọi Dynamic Loader (import_module + getattr) ─
    def _summarize_dynamic_loaders(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [a.arg for a in node.args.args]
            if not params:
                continue

            mod_vars: Dict[str, int] = {}  # local_var -> param_idx
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Call):
                    fn = _canonicalize_name(get_ast_func_name(sub.value.func), self.import_aliases, {})
                    if fn in ("importlib.import_module", "__import__") and sub.value.args:
                        arg0 = sub.value.args[0]
                        if isinstance(arg0, ast.Name) and arg0.id in params:
                            p_idx = params.index(arg0.id)
                            for tgt in sub.targets:
                                if isinstance(tgt, ast.Name):
                                    mod_vars[tgt.id] = p_idx

            for sub in ast.walk(node):
                if not isinstance(sub, ast.Return) or not isinstance(sub.value, ast.Call):
                    continue
                ret_call = sub.value
                ret_fn = _canonicalize_name(get_ast_func_name(ret_call.func), self.import_aliases, {})
                if ret_fn != "getattr" or len(ret_call.args) < 2:
                    continue

                # Tìm tham số module (qua biến mod_vars hoặc lồng trực tiếp import_module)
                mod_idx: Optional[int] = None
                obj_arg = ret_call.args[0]
                if isinstance(obj_arg, ast.Name) and obj_arg.id in mod_vars:
                    mod_idx = mod_vars[obj_arg.id]
                elif isinstance(obj_arg, ast.Call):
                    inner_fn = _canonicalize_name(get_ast_func_name(obj_arg.func), self.import_aliases, {})
                    if inner_fn in ("importlib.import_module", "__import__") and obj_arg.args:
                        if isinstance(obj_arg.args[0], ast.Name) and obj_arg.args[0].id in params:
                            mod_idx = params.index(obj_arg.args[0].id)

                if mod_idx is None:
                    continue

                # Tìm tham số tên thuộc tính (trực tiếp hoặc qua sep.join(param))
                attr_arg = ret_call.args[1]
                attr_idx: Optional[int] = None
                attr_joined = False
                join_sep = ""
                if isinstance(attr_arg, ast.Name) and attr_arg.id in params:
                    attr_idx = params.index(attr_arg.id)
                elif (
                    isinstance(attr_arg, ast.Call)
                    and isinstance(attr_arg.func, ast.Attribute)
                    and attr_arg.func.attr == "join"
                    and attr_arg.args
                    and isinstance(attr_arg.args[0], ast.Name)
                    and attr_arg.args[0].id in params
                ):
                    attr_idx = params.index(attr_arg.args[0].id)
                    attr_joined = True
                    sep_val = eval_static_expr(attr_arg.func.value, {}, self.import_aliases)
                    join_sep = sep_val if isinstance(sep_val, str) else ""

                if attr_idx is not None:
                    self.dynamic_loaders[node.name] = DynamicLoaderSummary(
                        func_name=node.name,
                        mod_param_idx=mod_idx,
                        attr_param_idx=attr_idx,
                        attr_joined=attr_joined,
                        join_sep=join_sep,
                    )

    # ── Tầng 4: Tóm tắt Decorator Sink ───────────────────────────────────────
    def _summarize_decorator_sinks(self, tree: ast.Module) -> None:
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.args.args:
                continue
            fn_param = node.args.args[0].arg

            for inner in node.body:
                if not isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                fn_result_vars: Set[str] = set()
                for stmt in ast.walk(inner):
                    if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                        if get_ast_func_name(stmt.value.func) == fn_param:
                            for t in stmt.targets:
                                if isinstance(t, ast.Name):
                                    fn_result_vars.add(t.id)
                if not fn_result_vars:
                    continue
                for sub in ast.walk(inner):
                    if not isinstance(sub, ast.Call):
                        continue
                    cname = _canonicalize_name(get_ast_func_name(sub.func), self.import_aliases, {})
                    uses_res = any(
                        isinstance(n, ast.Name) and n.id in fn_result_vars
                        for arg in sub.args
                        for n in ast.walk(arg)
                    )
                    if not uses_res:
                        continue
                    if cname.endswith(".execute") or cname.endswith(".executemany"):
                        self.decorator_sinks[node.name] = DecoratorSinkSummary(
                            decorator_name=node.name,
                            rule_id="AI-SAST-006",
                            sink_name=cname,
                            sink_line=getattr(sub, "lineno", node.lineno),
                        )
                    elif cname in UNSAFE_EXEC_SINKS:
                        self.decorator_sinks[node.name] = DecoratorSinkSummary(
                            decorator_name=node.name,
                            rule_id="AI-SAST-004",
                            sink_name=cname,
                            sink_line=getattr(sub, "lineno", node.lineno),
                        )

    # ── Tầng 4: Tóm tắt Class Attribute Taint & Helper Methods ───────────────
    def _summarize_classes_and_helpers(self, tree: ast.Module) -> None:
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            info = ClassAttrTaintInfo()
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = [a.arg for a in item.args.args if a.arg not in ("self", "cls")]
                param_set = set(params)

                # Kiểm tra method ghi tham số vào self.<attr>
                tainted_by_method: Set[str] = set()
                for sub in ast.walk(item):
                    # self.attr = ...
                    if isinstance(sub, ast.Assign):
                        for tgt in sub.targets:
                            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                                if self._expr_uses_any(sub.value, param_set):
                                    tainted_by_method.add(tgt.attr)
                    # self.attr += ...
                    elif isinstance(sub, ast.AugAssign):
                        tgt = sub.target
                        if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                            if self._expr_uses_any(sub.value, param_set):
                                tainted_by_method.add(tgt.attr)
                    # self.attr.append(...) / extend(...) / update(...)
                    elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        if sub.func.attr in ("append", "extend", "insert", "update", "add"):
                            owner = sub.func.value
                            if isinstance(owner, ast.Attribute) and isinstance(owner.value, ast.Name) and owner.value.id == "self":
                                if any(self._expr_uses_any(a, param_set) for a in sub.args):
                                    tainted_by_method.add(owner.attr)

                if tainted_by_method:
                    info.tainted_attrs.update(tainted_by_method)
                    info.tainting_methods[item.name] = tainted_by_method

                # Kiểm tra method đọc self.<attr> và trả về
                ret_attrs: Set[str] = set()
                is_mixed = False
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Return) and sub.value is not None:
                        for n in ast.walk(sub.value):
                            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self":
                                ret_attrs.add(n.attr)
                        if isinstance(sub.value, (ast.JoinedStr, ast.BinOp)):
                            is_mixed = True
                        elif isinstance(sub.value, ast.Call) and isinstance(sub.value.func, ast.Attribute):
                            if sub.value.func.attr in ("join", "format", "format_map"):
                                is_mixed = True
                if ret_attrs:
                    info.returning_attrs[item.name] = ret_attrs
                    if is_mixed:
                        info.mixed_return_methods.add(item.name)

                # Kiểm tra method đọc dữ liệu ngoài (HTTP / urlopen / requests / read)
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Call):
                        fn_raw = get_ast_func_name(sub.func)
                        fn_can = _canonicalize_name(fn_raw, self.import_aliases, {})
                        if (
                            fn_can in HTTP_CLIENT_SINKS
                            or fn_raw.endswith(".read")
                            or (fn_can == "getattr" and "urllib" in ast.dump(sub))
                        ):
                            self.method_returns_external.add(f"{node.name}.{item.name}")
                            self.method_returns_external.add(item.name)

                # Kiểm tra method biến đổi tham số đầu vào và trả về (passthrough taint, kể cả qua biến trung gian như cleaned = raw_uri.strip())
                local_tainted = set(param_set)
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Assign) and sub.value is not None:
                        if self._expr_uses_any(sub.value, local_tainted):
                            if not (
                                isinstance(sub.value, ast.Call)
                                and _canonicalize_name(get_ast_func_name(sub.value.func), self.import_aliases, {}) in SANITIZER_FUNCS
                            ):
                                for tgt in sub.targets:
                                    if isinstance(tgt, ast.Name):
                                        local_tainted.add(tgt.id)
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Return) and sub.value is not None:
                        if local_tainted and self._expr_uses_any(sub.value, local_tainted):
                            if not (isinstance(sub.value, ast.Call) and _canonicalize_name(get_ast_func_name(sub.value.func), self.import_aliases, {}) in SANITIZER_FUNCS):
                                self.method_passthrough_taint.add(f"{node.name}.{item.name}")
                                self.method_passthrough_taint.add(item.name)

            self.class_taint[node.name] = info

    @staticmethod
    def _expr_uses_any(node: ast.AST, names: Set[str]) -> bool:
        return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))

    @staticmethod
    def _is_str_annotation(ann: Optional[ast.AST]) -> bool:
        """Nhận diện chú thích kiểu str hoặc Optional[str] trên tham số hàm."""
        if ann is None:
            return False
        if isinstance(ann, ast.Name) and ann.id == "str":
            return True
        if isinstance(ann, ast.Subscript):
            base = get_ast_func_name(ann.value)
            if base in ("Optional", "typing.Optional") and isinstance(ann.slice, ast.Name) and ann.slice.id == "str":
                return True
        return False

    # ── Phân tích một hàm / phương thức ──────────────────────────────────────
    def _analyze_function(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        module_env: Dict[str, Any],
        class_name: Optional[str],
        class_env: Optional[Dict[str, Any]],
    ) -> None:
        env = dict(class_env if class_env is not None else module_env)
        var_aliases: Dict[str, str] = {}
        # tainted_vars[name] = set of tags: {"user", "llm", "external", "mixed_prompt"}
        tainted_vars: Dict[str, Set[str]] = {}
        sanitized_vars: Set[str] = set()
        dict_risk_vars: Dict[str, str] = {}
        dynamic_code_vars: Set[str] = set()
        obj_class_map: Dict[str, str] = {}
        tainted_objs: Set[str] = set()

        # Gắn nhãn taint ban đầu cho tham số hàm (Sink-first: mọi tham số chuỗi/nghiệp vụ chưa qua sanitizer đều được theo dõi)
        infra_param_names = {"client", "llm_client", "openai_client", "db", "conn", "db_conn", "cursor", "vector_db", "vector_store", "vdb", "session"}
        for arg in func_node.args.args:
            pname = arg.arg
            if pname in ("self", "cls"):
                continue
            low = pname.lower()
            if any(k in low for k in ("llm", "ai_", "generated", "model_out")):
                tainted_vars[pname] = {"llm"}
            elif TAINT_PARAM_RE.search(pname) or self._is_str_annotation(arg.annotation):
                tainted_vars[pname] = {"user"}
            elif low not in infra_param_names:
                tainted_vars[pname] = {"param"}

        # Kiểm tra Decorator Sink trên hàm (Tầng 4)
        if func_node.decorator_list:
            returns_llm = self._function_returns_llm_output(func_node)
            for dec in func_node.decorator_list:
                dec_name = get_ast_func_name(dec)
                if dec_name in self.decorator_sinks and returns_llm:
                    ds = self.decorator_sinks[dec_name]
                    self._emit(
                        ds.rule_id,
                        ds.sink_line,
                        engine="Python AST Decorator & Taint Analyzer",
                        extra_detail=f"Decorator @{dec_name} nhận đầu ra LLM từ `{func_node.name}()` và đưa trực tiếp vào `{ds.sink_name}()`",
                        allow_enrich_existing=False,
                    )

        self._analyze_statements(
            func_node.body,
            env=env,
            var_aliases=var_aliases,
            tainted_vars=tainted_vars,
            sanitized_vars=sanitized_vars,
            dict_risk_vars=dict_risk_vars,
            dynamic_code_vars=dynamic_code_vars,
            obj_class_map=obj_class_map,
            tainted_objs=tainted_objs,
        )

    def _function_returns_llm_output(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        llm_resp_vars: Set[str] = set()
        for sub in ast.walk(func_node):
            if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.Call):
                fn = get_ast_func_name(sub.value.func)
                if any(k in fn for k in ("completions.create", "chat.create", "generate", "invoke")):
                    for t in sub.targets:
                        if isinstance(t, ast.Name):
                            llm_resp_vars.add(t.id)
        for sub in ast.walk(func_node):
            if isinstance(sub, ast.Return) and sub.value is not None:
                dump = ast.dump(sub.value)
                if "choices" in dump or "message" in dump:
                    return True
                if any(isinstance(n, ast.Name) and n.id in llm_resp_vars for n in ast.walk(sub.value)):
                    return True
        return False

    # ── Phân tích tuần tự danh sách statements ───────────────────────────────
    def _analyze_statements(
        self,
        stmts: List[ast.stmt],
        env: Dict[str, Any],
        var_aliases: Dict[str, str],
        tainted_vars: Dict[str, Set[str]],
        sanitized_vars: Set[str],
        dict_risk_vars: Dict[str, str],
        dynamic_code_vars: Set[str],
        obj_class_map: Dict[str, str],
        tainted_objs: Set[str],
    ) -> None:
        for stmt in stmts:
            # 1. Nhận diện Guard Sanitizer: if not x.isalnum(): raise ... / return ...
            if isinstance(stmt, ast.If):
                guarded = self._extract_guard_sanitized_var(stmt)
                if guarded:
                    sanitized_vars.add(guarded)
                    tainted_vars.pop(guarded, None)
                self._analyze_statements(
                    stmt.body, env, var_aliases, tainted_vars, sanitized_vars,
                    dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )
                self._analyze_statements(
                    stmt.orelse, env, var_aliases, tainted_vars, sanitized_vars,
                    dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )
                continue

            # 2. Hỗ trợ khối With (ví dụ: with opener(target) as resp:)
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self._inspect_expr_calls(
                        item.context_expr, env, var_aliases, tainted_vars,
                        sanitized_vars, dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                    )
                self._analyze_statements(
                    stmt.body, env, var_aliases, tainted_vars, sanitized_vars,
                    dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )
                continue

            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                self._analyze_statements(
                    stmt.body, env, var_aliases, tainted_vars, sanitized_vars,
                    dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )
                continue

            if isinstance(stmt, ast.Try):
                self._analyze_statements(
                    stmt.body, env, var_aliases, tainted_vars, sanitized_vars,
                    dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )
                for h in stmt.handlers:
                    self._analyze_statements(
                        h.body, env, var_aliases, tainted_vars, sanitized_vars,
                        dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                    )
                continue

            # 3. Kiểm tra Assign / AnnAssign
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                val_node = stmt.value
                if val_node is None:
                    continue
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]

                # Kiểm tra secret giải mã tĩnh ở vế phải
                self._check_deobfuscated_secret(val_node, env, getattr(stmt, "lineno", 1))

                # Kiểm tra các lời gọi hàm bên trong vế phải
                self._inspect_expr_calls(
                    val_node, env, var_aliases, tainted_vars,
                    sanitized_vars, dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )

                # Cập nhật hằng số tĩnh
                folded = eval_static_expr(val_node, env, self.import_aliases)

                # Cập nhật Symbolic Alias (getattr, dynamic loader)
                resolved_alias = self._resolve_alias_from_expr(val_node, env)

                # Kiểm tra khởi tạo object của class có attribute taint (hỗ trợ cả @dataclass truyền thẳng arg/kwarg)
                created_cls = None
                ctor_tainted = False
                if isinstance(val_node, ast.Call):
                    cname = get_ast_func_name(val_node.func)
                    if cname in self.class_taint:
                        created_cls = cname
                        ctor_tainted = any(
                            self._infer_expr_taint(a, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                            for a in val_node.args
                        ) or any(
                            self._infer_expr_taint(kw.value, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                            for kw in val_node.keywords
                        )

                # Kiểm tra dict rủi ro cho Vector DB filter (Tầng 3)
                dict_risk = self._check_dict_filter_risk(val_node, tainted_vars)

                # Kiểm tra compile() / CodeType động
                is_dyn_code = self._is_dynamic_code_expr(val_node, dynamic_code_vars, env)

                # Tính taint truyền sang biến đích
                inferred_taint = self._infer_expr_taint(
                    val_node, tainted_vars, sanitized_vars, obj_class_map, tainted_objs
                )
                is_sanitized_call = self._is_sanitizer_call(val_node)

                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        tname = tgt.id
                        if folded is not _UNRESOLVED:
                            env[tname] = folded
                        if resolved_alias:
                            var_aliases[tname] = resolved_alias
                        if created_cls:
                            obj_class_map[tname] = created_cls
                            if ctor_tainted:
                                tainted_objs.add(tname)
                        if dict_risk:
                            dict_risk_vars[tname] = dict_risk
                        if is_dyn_code:
                            dynamic_code_vars.add(tname)
                        if is_sanitized_call:
                            sanitized_vars.add(tname)
                            tainted_vars.pop(tname, None)
                        elif inferred_taint:
                            tainted_vars[tname] = inferred_taint
                            sanitized_vars.discard(tname)
                continue

            # 4. Kiểm tra Return
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                self._check_deobfuscated_secret(stmt.value, env, getattr(stmt, "lineno", 1))
                self._inspect_expr_calls(
                    stmt.value, env, var_aliases, tainted_vars,
                    sanitized_vars, dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )
                continue

            # 5. Kiểm tra Expr (ví dụ: ctx.attach(user_ticket), d.update(user_filters), opener(target))
            if isinstance(stmt, ast.Expr):
                self._check_deobfuscated_secret(stmt.value, env, getattr(stmt, "lineno", 1))
                # Kiểm tra d.update(user_filters)
                if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
                    if stmt.value.func.attr == "update" and isinstance(stmt.value.func.value, ast.Name):
                        dict_var = stmt.value.func.value.id
                        if stmt.value.args and self._infer_expr_taint(
                            stmt.value.args[0], tainted_vars, sanitized_vars, obj_class_map, tainted_objs
                        ):
                            dict_risk_vars[dict_var] = f".update() từ nguồn chưa tin cậy"
                    # Kiểm tra obj.method(tainted_arg) ghi vào self.<attr> (Tầng 4)
                    if isinstance(stmt.value.func.value, ast.Name):
                        obj_name = stmt.value.func.value.id
                        m_name = stmt.value.func.attr
                        cls_n = obj_class_map.get(obj_name)
                        if cls_n and cls_n in self.class_taint:
                            cinfo = self.class_taint[cls_n]
                            if m_name in cinfo.tainting_methods:
                                if any(
                                    self._infer_expr_taint(a, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                                    for a in stmt.value.args
                                ):
                                    tainted_objs.add(obj_name)

                self._inspect_expr_calls(
                    stmt.value, env, var_aliases, tainted_vars,
                    sanitized_vars, dict_risk_vars, dynamic_code_vars, obj_class_map, tainted_objs,
                )

    # ── Kiểm tra bí mật giải mã tĩnh (Tầng 1) ────────────────────────────────
    def _check_deobfuscated_secret(self, expr: ast.AST, env: Dict[str, Any], line_no: int) -> None:
        # Bỏ qua hằng chuỗi đơn thuần (đã có regex xử lý) để tránh báo trùng;
        # chỉ giải mã các biểu thức obfuscated (BinOp, Call, Join/XOR/Base64/Hex)
        if isinstance(expr, ast.Constant):
            return
        folded = eval_static_expr(expr, env, self.import_aliases)
        if isinstance(folded, str):
            label = match_secret_value(folded)
            if label:
                self._emit(
                    "AI-SAST-002",
                    line_no,
                    getattr(expr, "end_lineno", line_no),
                    engine="Python AST De-obfuscation Engine",
                    extra_detail=f"Phát hiện {label} bị che giấu tĩnh (giá trị giải mã: {_redact_secret(folded)})",
                )

    # ── Tầng 2: Resolve Alias từ getattr / dynamic loader ────────────────────
    def _resolve_alias_from_expr(self, expr: ast.AST, env: Dict[str, Any]) -> Optional[str]:
        if not isinstance(expr, ast.Call):
            return None
        raw_fn = get_ast_func_name(expr.func)
        fn_can = _canonicalize_name(raw_fn, self.import_aliases, {})

        # getattr(mod, "url" + "open")
        if fn_can == "getattr" and len(expr.args) >= 2:
            mod_name = _canonicalize_name(get_ast_func_name(expr.args[0]), self.import_aliases, {})
            attr_val = eval_static_expr(expr.args[1], env, self.import_aliases)
            if mod_name and isinstance(attr_val, str):
                return f"{mod_name}.{attr_val}"

        # Gọi hàm Dynamic Loader đã tóm tắt (vd _load_runtime_callable("pic"+"kle", ["lo","ads"]))
        if raw_fn in self.dynamic_loaders:
            dl = self.dynamic_loaders[raw_fn]
            if len(expr.args) > max(dl.mod_param_idx, dl.attr_param_idx):
                mod_val = eval_static_expr(expr.args[dl.mod_param_idx], env, self.import_aliases)
                attr_val = eval_static_expr(expr.args[dl.attr_param_idx], env, self.import_aliases)
                if isinstance(mod_val, str):
                    if dl.attr_joined and isinstance(attr_val, (list, tuple)) and all(isinstance(x, str) for x in attr_val):
                        attr_str = dl.join_sep.join(attr_val)
                        return f"{mod_val}.{attr_str}"
                    if isinstance(attr_val, str):
                        return f"{mod_val}.{attr_val}"
        return None

    # ── Tầng 2: Bung **kwargs cho ast.Call ───────────────────────────────────
    def _resolve_call_kwargs(self, call_node: ast.Call, env: Dict[str, Any]) -> Dict[str, Any]:
        resolved: Dict[str, Any] = {}
        for kw in call_node.keywords:
            if kw.arg is None:
                unpacked = eval_static_expr(kw.value, env, self.import_aliases)
                if isinstance(unpacked, dict):
                    for k, v in unpacked.items():
                        if isinstance(k, str):
                            resolved[k] = v
            else:
                v = eval_static_expr(kw.value, env, self.import_aliases)
                resolved[kw.arg] = v
        return resolved

    # ── Tầng 3: Kiểm tra rủi ro Vector DB Filter Dict ────────────────────────
    def _check_dict_filter_risk(self, expr: ast.AST, tainted_vars: Dict[str, Set[str]]) -> Optional[str]:
        # 1. {..., **user_filters}
        if isinstance(expr, ast.Dict):
            saw_tainted_unpack = False
            locked_after_unpack = False
            for k_node, v_node in zip(expr.keys, expr.values):
                if k_node is None:
                    if self._expr_uses_any(v_node, set(tainted_vars.keys())):
                        saw_tainted_unpack = True
                        locked_after_unpack = False
                elif saw_tainted_unpack:
                    if isinstance(k_node, ast.Constant) and str(k_node.value).lower() in TENANT_LOCK_KEYS:
                        locked_after_unpack = True
            if saw_tainted_unpack and not locked_after_unpack:
                return "trộn trực tiếp dict unpacking (**user_filters) mà không khóa cứng tenant_id sau unpack"

        # 2. base | user_filters
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):
            if self._expr_uses_any(expr.right, set(tainted_vars.keys())):
                return "trộn trực tiếp bộ lọc người dùng bằng toán tử hợp dict (|)"
        return None

    # ── Tầng 3: Nhận diện compile() & CodeType động ──────────────────────────
    def _is_dynamic_code_expr(
        self, expr: ast.AST, dynamic_code_vars: Set[str], env: Dict[str, Any]
    ) -> bool:
        if isinstance(expr, ast.Call):
            fn = _canonicalize_name(get_ast_func_name(expr.func), self.import_aliases, {})
            if fn in ("compile", "builtins.compile") and len(expr.args) >= 3:
                mode = eval_static_expr(expr.args[2], env, self.import_aliases)
                src_static = eval_static_expr(expr.args[0], env, self.import_aliases)
                if mode in ("exec", "eval", "single") and src_static is _UNRESOLVED:
                    return True
            # next(c for c in code_obj.co_consts if isinstance(c, types.CodeType))
            if fn == "next" and self._expr_uses_any(expr, dynamic_code_vars):
                return True
        if self._expr_uses_any(expr, dynamic_code_vars):
            return True
        return False

    # ── Tầng 4: Guard Sanitizer & Sanitizer Call ─────────────────────────────
    @staticmethod
    def _extract_guard_sanitized_var(if_node: ast.If) -> Optional[str]:
        """Nhận diện guard như: if not hostname.replace(".", "").isalnum(): raise ValueError(...)"""
        if not isinstance(if_node.test, ast.UnaryOp) or not isinstance(if_node.test.op, ast.Not):
            return None
        if not any(isinstance(s, (ast.Raise, ast.Return)) for s in if_node.body):
            return None
        inner = if_node.test.operand
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            if inner.func.attr in ("isalnum", "isalpha", "isdigit", "isidentifier"):
                # Lấy biến gốc ở đầu chuỗi gọi (vd hostname.replace(...).isalnum())
                cur = inner.func.value
                while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
                    cur = cur.func.value
                if isinstance(cur, ast.Name):
                    return cur.id
            if inner.func.attr == "fullmatch" and len(inner.args) >= 2 and isinstance(inner.args[1], ast.Name):
                return inner.args[1].id
        return None

    def _is_sanitizer_call(self, expr: ast.AST) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        fn = _canonicalize_name(get_ast_func_name(expr.func), self.import_aliases, {})
        return fn in SANITIZER_FUNCS

    # ── Tầng 4: Suy luận nhãn taint cho biểu thức ────────────────────────────
    def _infer_expr_taint(
        self,
        expr: ast.AST,
        tainted_vars: Dict[str, Set[str]],
        sanitized_vars: Set[str],
        obj_class_map: Dict[str, str],
        tainted_objs: Set[str],
    ) -> Set[str]:
        if isinstance(expr, ast.Name):
            if expr.id in sanitized_vars:
                return set()
            return set(tainted_vars.get(expr.id, set()))

        if isinstance(expr, ast.Call):
            if self._is_sanitizer_call(expr):
                return set()
            fn_raw = get_ast_func_name(expr.func)
            fn_can = _canonicalize_name(fn_raw, self.import_aliases, {})

            # Gọi LLM API -> kết quả là "llm"
            if any(k in fn_can for k in ("completions.create", "chat.create")):
                return {"llm"}

            # Gọi method đọc nguồn ngoài (RAG fetch)
            if isinstance(expr.func, ast.Attribute):
                m_name = expr.func.attr
                if m_name in self.method_returns_external:
                    return {"external"}
                # Gọi object method trả về self.<attr> bị taint (vd ctx.compile_payload())
                if isinstance(expr.func.value, ast.Name):
                    obj_name = expr.func.value.id
                    cls_n = obj_class_map.get(obj_name)
                    if obj_name in tainted_objs and cls_n and cls_n in self.class_taint:
                        cinfo = self.class_taint[cls_n]
                        if m_name in cinfo.returning_attrs:
                            tags = {"user"}
                            if m_name in cinfo.mixed_return_methods:
                                tags.add("mixed_prompt")
                            return tags
                # .format(...) / .format_map(...) -> lan truyền taint + đánh dấu mixed_prompt
                if m_name in ("format", "format_map"):
                    tags: Set[str] = set()
                    for a in expr.args:
                        tags |= self._infer_expr_taint(a, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                    for kw in expr.keywords:
                        tags |= self._infer_expr_taint(kw.value, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                    if tags:
                        tags.add("mixed_prompt")
                    return tags
                # .join(...)
                if m_name == "join" and expr.args:
                    tags = self._infer_expr_taint(expr.args[0], tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                    if tags:
                        tags.add("mixed_prompt")
                    return tags
                # Helper passthrough (vd self._normalize_uri(source_url))
                if m_name in self.method_passthrough_taint:
                    tags = set()
                    for a in expr.args:
                        tags |= self._infer_expr_taint(a, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                    return tags
                # json.loads(raw_reply) -> giữ taint của đầu vào
                if fn_can == "json.loads" and expr.args:
                    return self._infer_expr_taint(expr.args[0], tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                # dict.get(...) -> giữ taint của dict
                if m_name == "get":
                    return self._infer_expr_taint(expr.func.value, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)

            # Kiểm tra các đối số của lời gọi bất kỳ
            return set()

        # f-string có chứa biến taint -> mixed_prompt
        if isinstance(expr, ast.JoinedStr):
            tags = set()
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    tags |= self._infer_expr_taint(v.value, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            if tags:
                tags.add("mixed_prompt")
            return tags

        # Phép cộng chuỗi với biến taint -> mixed_prompt
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            lt = self._infer_expr_taint(expr.left, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            rt = self._infer_expr_taint(expr.right, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            tags = lt | rt
            if tags:
                tags.add("mixed_prompt")
            return tags

        # Truy cập thuộc tính / subscript (vd response.choices[0].message.content)
        if isinstance(expr, (ast.Attribute, ast.Subscript)):
            base = expr.value
            tags = self._infer_expr_taint(base, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            if isinstance(expr, ast.Attribute) and expr.attr == "content" and "choices" in ast.dump(expr):
                tags.add("llm")
            return tags

        if isinstance(expr, ast.Dict):
            tags = set()
            for v in expr.values:
                tags |= self._infer_expr_taint(v, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            return tags

        if isinstance(expr, (ast.List, ast.Tuple)):
            tags = set()
            for el in expr.elts:
                tags |= self._infer_expr_taint(el, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            return tags

        return set()

    # ── Kiểm tra toàn bộ lời gọi hàm (Sinks) trong biểu thức ────────────────
    def _inspect_expr_calls(
        self,
        expr: ast.AST,
        env: Dict[str, Any],
        var_aliases: Dict[str, str],
        tainted_vars: Dict[str, Set[str]],
        sanitized_vars: Set[str],
        dict_risk_vars: Dict[str, str],
        dynamic_code_vars: Set[str],
        obj_class_map: Dict[str, str],
        tainted_objs: Set[str],
    ) -> None:
        for node in ast.walk(expr):
            if not isinstance(node, ast.Call):
                continue
            line_no = getattr(node, "lineno", 1)
            end_line_no = getattr(node, "end_lineno", line_no)
            raw_fn = get_ast_func_name(node.func)
            fn_can = _canonicalize_name(raw_fn, self.import_aliases, var_aliases)
            resolved_kw = self._resolve_call_kwargs(node, env)

            # 1. AI-SAST-003: Deserialization không an toàn (trực tiếp hoặc qua dynamic import alias)
            if fn_can in UNSAFE_DESER_SINKS:
                has_weights_only = resolved_kw.get("weights_only") is True
                if not has_weights_only:
                    detail = f"Gọi `{fn_can}()`" + (f" thông qua alias `{raw_fn}`" if raw_fn != fn_can else "")
                    self._emit("AI-SAST-003", line_no, end_line_no, extra_detail=detail)

            # 2. AI-SAST-004: eval / exec (trực tiếp hoặc qua dynamic import alias)
            elif fn_can in UNSAFE_EXEC_SINKS:
                detail = f"Gọi `{fn_can}()`" + (f" thông qua alias `{raw_fn}`" if raw_fn != fn_can else "")
                self._emit("AI-SAST-004", line_no, end_line_no, extra_detail=detail)

            # 3. AI-SAST-004: compile(..., "exec"|"eval") + types.FunctionType(...)
            elif fn_can in ("types.FunctionType", "FunctionType"):
                if node.args and self._expr_uses_any(node.args[0], dynamic_code_vars):
                    self._emit(
                        "AI-SAST-004",
                        line_no,
                        end_line_no,
                        extra_detail="Thực thi mã động qua `compile()` + `types.FunctionType()` (bypass phát hiện eval/exec)",
                    )

            # 4. AI-SAST-004: subprocess.* với shell=True (kể cả qua **kwargs & bool(1))
            elif fn_can in SUBPROCESS_SINKS:
                if resolved_kw.get("shell") is True:
                    self._emit(
                        "AI-SAST-004",
                        line_no,
                        end_line_no,
                        extra_detail=f"Gọi `{fn_can}()` với `shell=True` (đã giải nén qua **kwargs / hằng boolean)",
                    )

            # 5. AI-SAST-005: from_pretrained(..., trust_remote_code=True) (kể cả qua **kwargs)
            elif fn_can.endswith("from_pretrained"):
                if resolved_kw.get("trust_remote_code") is True and "revision" not in resolved_kw:
                    self._emit(
                        "AI-SAST-005",
                        line_no,
                        end_line_no,
                        extra_detail="Bật `trust_remote_code=True` (đã giải nén qua **kwargs / biểu thức động) mà không ghim `revision`",
                    )

            # 6. AI-SAST-006 (SSRF) & AI-SAST-007 (Missing Timeout) cho HTTP clients (urllib/requests/httpx/aiohttp)
            elif fn_can in HTTP_CLIENT_SINKS or fn_can.endswith(".urlopen"):
                url_arg = node.args[0] if node.args else None
                if url_arg is not None:
                    url_taint = self._infer_expr_taint(url_arg, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
                    if url_taint - {"param"} or ("param" in url_taint and not isinstance(url_arg, ast.Constant)):
                        detail = f"SSRF qua `{fn_can}()`" + (f" (alias `{raw_fn}`)" if raw_fn != fn_can else "") + " nhận URL chưa lọc IP nội bộ / metadata"
                        self._emit("AI-SAST-006", line_no, end_line_no, extra_detail=detail)

                has_timeout = "timeout" in resolved_kw or (fn_can.endswith("urlopen") and len(node.args) >= 3)
                if not has_timeout:
                    if fn_can.endswith("urlopen"):
                        self._emit(
                            "AI-SAST-007",
                            line_no,
                            end_line_no,
                            extra_detail=f"Gọi `{fn_can}()` thiếu tham số `timeout` (tiềm ẩn treo luồng / DoS)",
                        )
                    elif fn_can in ("requests.post", "requests.get", "httpx.post", "httpx.get"):
                        call_block = "\n".join(self.lines[max(0, line_no - 1):min(len(self.lines), end_line_no)])
                        if re.search(
                            r"(?:11434|api/generate|api/chat|chat/completions|completions|openai\.com|anthropic\.com|huggingface\.co|v1/models|prompt|messages)",
                            call_block,
                            re.IGNORECASE,
                        ):
                            self._emit("AI-SAST-007", line_no, end_line_no)

            # 7. AI-SAST-006: SQL Injection từ đầu ra LLM hoặc chuỗi bẩn (không phụ thuộc tên biến)
            elif fn_can.endswith(".execute") or fn_can.endswith(".executemany"):
                if node.args:
                    sql_taint = self._infer_expr_taint(
                        node.args[0], tainted_vars, sanitized_vars, obj_class_map, tainted_objs
                    )
                    if "llm" in sql_taint or "mixed_prompt" in sql_taint:
                        self._emit(
                            "AI-SAST-006",
                            line_no,
                            end_line_no,
                            extra_detail=f"Truyền dữ liệu bị taint ({', '.join(sorted(sql_taint))}) trực tiếp vào `{fn_can}()`",
                        )

            # 8. AI-SAST-008: Vector DB Filter Injection (where= / filter=)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in VECTOR_QUERY_METHODS:
                for kw in node.keywords:
                    if kw.arg in ("where", "filter"):
                        risk_reason: Optional[str] = None
                        if isinstance(kw.value, ast.Name):
                            if kw.value.id in dict_risk_vars:
                                risk_reason = dict_risk_vars[kw.value.id]
                            elif kw.value.id in tainted_vars:
                                risk_reason = f"truyền thẳng biến đầu vào `{kw.value.id}` vào `{kw.arg}=`"
                        else:
                            risk_reason = self._check_dict_filter_risk(kw.value, tainted_vars)
                        if risk_reason:
                            self._emit(
                                "AI-SAST-008",
                                line_no,
                                end_line_no,
                                extra_detail=f"Vector DB Filter Injection / Cross-Tenant Leak tại `{raw_fn}(..., {kw.arg}=...)`: {risk_reason}",
                            )

            # 9. AI-SAST-001: Prompt Injection (kiểm tra Role Separation & trộn ngữ cảnh/RAG)
            elif any(k in fn_can for k in ("completions.create", "chat.create")):
                self._check_llm_messages_injection(
                    node, line_no, end_line_no, tainted_vars, sanitized_vars, obj_class_map, tainted_objs
                )

    def _check_llm_messages_injection(
        self,
        call_node: ast.Call,
        line_no: int,
        end_line_no: int,
        tainted_vars: Dict[str, Set[str]],
        sanitized_vars: Set[str],
        obj_class_map: Dict[str, str],
        tainted_objs: Set[str],
    ) -> None:
        messages_node = None
        for kw in call_node.keywords:
            if kw.arg == "messages":
                messages_node = kw.value
                break
        if not isinstance(messages_node, (ast.List, ast.Tuple)):
            return

        has_clean_system_role = False
        suspicious_user_content = False
        system_tainted = False
        taint_reasons: List[str] = []

        for item in messages_node.elts:
            if not isinstance(item, ast.Dict):
                continue
            role_val = None
            content_node = None
            for k_n, v_n in zip(item.keys, item.values):
                if isinstance(k_n, ast.Constant):
                    if k_n.value == "role" and isinstance(v_n, ast.Constant):
                        role_val = str(v_n.value).lower()
                    elif k_n.value == "content":
                        content_node = v_n
            if content_node is None:
                continue

            ctaint = self._infer_expr_taint(content_node, tainted_vars, sanitized_vars, obj_class_map, tainted_objs)
            if role_val == "system":
                if ctaint:
                    system_tainted = True
                    taint_reasons.append("chèn dữ liệu chưa tin cậy vào `role: system`")
                else:
                    has_clean_system_role = True
            elif role_val == "user":
                # Chỉ báo khi content trộn chỉ thị/template hoặc dữ liệu RAG bên ngoài (mixed_prompt / external)
                # KHÔNG báo nếu chỉ truyền raw user_query kèm role: system sạch (tránh FP ở false_positive_trap.py)
                if "mixed_prompt" in ctaint or "external" in ctaint:
                    suspicious_user_content = True
                    taint_reasons.append(
                        f"trộn ngữ cảnh/chỉ thị với dữ liệu bị taint ({', '.join(sorted(ctaint))}) vào `role: user`"
                    )

        if system_tainted or (suspicious_user_content and not has_clean_system_role):
            self._emit(
                "AI-SAST-001",
                line_no,
                end_line_no,
                extra_detail="; ".join(taint_reasons),
            )
        elif suspicious_user_content and has_clean_system_role:
            # Trường hợp có system role nhưng vẫn trộn external RAG context vào user template -> Indirect Prompt Injection
            if any("external" in r for r in taint_reasons):
                self._emit(
                    "AI-SAST-001",
                    line_no,
                    end_line_no,
                    extra_detail="Indirect Prompt Injection (RAG Poisoning): " + "; ".join(taint_reasons),
                )


# ──────────────────────────────────────────────────────────────────────────────
# Tầng 5: Cross-File Taint Analyzer (Fixed-Point Iteration)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class CrossFileFuncSummary:
    module_key: str
    file_rel: str
    func_name: str
    line_no: int
    params: List[str]
    # param_idx -> set of tags propagated to return value (e.g. {"user", "mixed_prompt"})
    return_taint_from_param: Dict[int, Set[str]] = field(default_factory=dict)
    # param_idx -> list of (rule_id, sink_file, sink_line, sink_desc, extra_tags, hops)
    sink_from_param: Dict[int, List[Tuple[str, str, int, str, Tuple[str, ...], Tuple[str, ...]]]] = field(default_factory=dict)
    # Calls inside this function
    call_sites: List[Dict[str, Any]] = field(default_factory=list)


class CrossFileTaintAnalyzer:
    """
    Phân tích luồng taint xuyên file Python trong cùng thư mục dự án:
      - Hỗ trợ `import mod as alias`, `from mod import fn as alias`, relative import (`from .utils import ...`).
      - Chạy fixed-point iteration (tối đa 4 vòng, dừng sớm khi hội tụ).
      - Dùng tập `visited` chống vòng lặp vô hạn khi gặp circular import.
    """

    def __init__(
        self,
        py_files: List[Tuple[Path, str, str]],  # (abs_path, rel_name, content)
        rules_by_id: Dict[str, Dict[str, Any]],
        format_snippet_fn: Callable[[List[str], int, Optional[int]], str],
    ) -> None:
        self.py_files = py_files
        self.rules_by_id = rules_by_id
        self.format_snippet = format_snippet_fn
        self.file_lines: Dict[str, List[str]] = {}
        self.module_to_rel: Dict[str, str] = {}
        self.rel_to_module: Dict[str, str] = {}
        self.summaries: Dict[Tuple[str, str], CrossFileFuncSummary] = {}  # (module_key, func_name) -> summary
        self.trees: Dict[str, ast.Module] = {}

    def analyze(self) -> List[Dict[str, Any]]:
        if len(self.py_files) < 2:
            return []

        # 1. Lập chỉ mục module & parse AST
        for _, rel_name, content in self.py_files:
            norm_rel = rel_name.replace("\\", "/")
            self.file_lines[norm_rel] = content.splitlines()
            mod_key = self._rel_to_module_key(norm_rel)
            self.module_to_rel[mod_key] = norm_rel
            self.rel_to_module[norm_rel] = mod_key
            # Hỗ trợ import theo tên file ngắn (ví dụ: `from utils import ...` trong cùng thư mục)
            short_key = Path(norm_rel).stem
            if short_key not in self.module_to_rel:
                self.module_to_rel[short_key] = norm_rel
            try:
                self.trees[norm_rel] = ast.parse(content, filename=norm_rel)
            except SyntaxError:
                continue

        # 2. Pass 1: Tóm tắt cục bộ từng hàm & thu thập danh sách lời gọi xuyên file
        for norm_rel, tree in self.trees.items():
            mod_key = self.rel_to_module[norm_rel]
            local_imports = self._resolve_cross_file_imports(tree, norm_rel)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    summary = self._summarize_function_local(mod_key, norm_rel, node, local_imports)
                    self.summaries[(mod_key, node.name)] = summary

        # 3. Fixed-point iteration (tối đa 4 vòng, dừng sớm khi hội tụ)
        for _ in range(4):
            changed = False
            for key, summary in list(self.summaries.items()):
                if self._propagate_summary_step(summary):
                    changed = True
            if not changed:
                break

        # 4. Truy vết luồng xuyên file từ entry/caller functions
        findings: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str, int]] = set()

        for (mod_key, fn_name), summary in self.summaries.items():
            # Khởi đầu từ các hàm có tham số mang tính đầu vào (user_query, raw_input...)
            entry_tainted_params = {
                idx for idx, p in enumerate(summary.params) if TAINT_PARAM_RE.search(p)
            }
            if not entry_tainted_params:
                continue

            # Mô phỏng luồng biến cục bộ qua các call_sites trong hàm entry
            var_taint: Dict[str, Tuple[Set[str], List[str]]] = {
                summary.params[idx]: ({"user"}, [f"{summary.file_rel}:{summary.func_name}({summary.params[idx]})"])
                for idx in entry_tainted_params
            }

            for cs in summary.call_sites:
                target_key = (cs["callee_mod"], cs["callee_fn"])
                callee = self.summaries.get(target_key)
                if not callee:
                    continue

                # Kiểm tra các đối số truyền vào callee
                arg_taints: Dict[int, Tuple[Set[str], List[str]]] = {}
                for arg_idx, arg_vars in cs["arg_vars"].items():
                    merged_tags: Set[str] = set()
                    merged_trace: List[str] = []
                    for av in arg_vars:
                        if av in var_taint:
                            t_tags, t_trace = var_taint[av]
                            merged_tags |= t_tags
                            for step in t_trace:
                                if step not in merged_trace:
                                    merged_trace.append(step)
                    if merged_tags:
                        arg_taints[arg_idx] = (merged_tags, merged_trace)

                # Nếu callee trả về taint -> gán cho biến đích kèm trace
                if cs["assign_to"]:
                    for arg_idx, (a_tags, a_trace) in arg_taints.items():
                        if arg_idx in callee.return_taint_from_param:
                            out_tags = a_tags | callee.return_taint_from_param[arg_idx]
                            step = f"{callee.file_rel}:{callee.func_name}()"
                            out_trace = list(a_trace)
                            if step not in out_trace:
                                out_trace.append(step)
                            var_taint[cs["assign_to"]] = (out_tags, out_trace)

                # Nếu callee đưa đối số bị taint vào sink -> phát hiện lỗ hổng xuyên file!
                for arg_idx, (a_tags, a_trace) in arg_taints.items():
                    if arg_idx in callee.sink_from_param:
                        for rule_id, sink_file, sink_line, sink_desc, extra_tags, extra_hops in callee.sink_from_param[arg_idx]:
                            combined_tags = a_tags | set(extra_tags)
                            # Đảm bảo thực sự xuyên ít nhất 2 file khác nhau
                            if sink_file == summary.file_rel and len(a_trace) < 2 and not extra_hops:
                                continue
                            # Đối với AI-SAST-001, yêu cầu có mixed_prompt hoặc external hoặc thiếu role separation
                            if rule_id == "AI-SAST-001" and not (
                                "mixed_prompt" in combined_tags or "external" in combined_tags or "no_system_role" in sink_desc
                            ):
                                continue

                            full_trace = list(a_trace)
                            for hop in extra_hops:
                                if hop not in full_trace:
                                    full_trace.append(hop)
                            sink_step = f"{sink_file} [L{sink_line}]"
                            if not any(sink_file in s and f"L{sink_line}" in s for s in full_trace):
                                full_trace.append(sink_step)
                            trace_str = " -> ".join(full_trace)

                            dedup_k = (rule_id, sink_file, sink_line)
                            if dedup_k in seen_keys:
                                continue
                            seen_keys.add(dedup_k)

                            rule = self.rules_by_id.get(rule_id)
                            if not rule:
                                continue
                            target_lines = self.file_lines.get(sink_file, [])
                            code_line = target_lines[sink_line - 1].strip() if 0 < sink_line <= len(target_lines) else ""
                            ctx_snip = self.format_snippet(target_lines, sink_line, sink_line)
                            findings.append({
                                "rule_id": rule["rule_id"],
                                "title": f"{rule['title']} (Cross-File Taint)",
                                "severity": rule["severity"],
                                "risk_score": rule["risk_score"],
                                "owasp": rule["owasp"],
                                "mitre": rule["mitre"],
                                "cwe": rule["cwe"],
                                "file": sink_file,
                                "line": sink_line,
                                "code_line": code_line[:220],
                                "context_snippet": f"{ctx_snip}\n    [Cross-File Trace] {trace_str}",
                                "description": f"{rule['description']} [Cross-File Taint Trace: {trace_str}]",
                                "remediation": rule["remediation"],
                                "fix_example": rule["fix_example"],
                                "engine": "Cross-File Taint Flow Analyzer",
                            })

        return findings

    @staticmethod
    def _rel_to_module_key(norm_rel: str) -> str:
        p = norm_rel[:-3] if norm_rel.endswith(".py") else norm_rel
        return p.replace("/", ".")

    def _resolve_cross_file_imports(self, tree: ast.Module, norm_rel: str) -> Dict[str, Tuple[str, Optional[str]]]:
        """
        Trả về map local_name -> (target_module_key, symbol_name_or_None).
        Hỗ trợ relative import (from .utils import ...) và import alias.
        """
        cur_dir_parts = Path(norm_rel).parent.parts
        resolved: Dict[str, Tuple[str, Optional[str]]] = {}

        def find_mod_key(mod_name: str, level: int) -> Optional[str]:
            candidates: List[str] = []
            if level > 0:
                up = max(0, len(cur_dir_parts) - (level - 1))
                prefix_parts = list(cur_dir_parts[:up])
                if mod_name:
                    prefix_parts.extend(mod_name.split("."))
                candidates.append(".".join(prefix_parts))
            else:
                if cur_dir_parts and cur_dir_parts != (".",):
                    candidates.append(".".join(list(cur_dir_parts) + mod_name.split(".")))
                candidates.append(mod_name)

            for cand in candidates:
                if cand in self.module_to_rel:
                    return self.rel_to_module[self.module_to_rel[cand]]
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mk = find_mod_key(alias.name, 0)
                    if mk:
                        resolved[alias.asname or alias.name] = (mk, None)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                mk = find_mod_key(mod, node.level or 0)
                if mk:
                    for alias in node.names:
                        resolved[alias.asname or alias.name] = (mk, alias.name)
        return resolved

    def _summarize_function_local(
        self,
        mod_key: str,
        norm_rel: str,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        local_imports: Dict[str, Tuple[str, Optional[str]]],
    ) -> CrossFileFuncSummary:
        params = [a.arg for a in func_node.args.args]
        summary = CrossFileFuncSummary(
            module_key=mod_key,
            file_rel=norm_rel,
            func_name=func_node.name,
            line_no=getattr(func_node, "lineno", 1),
            params=params,
        )

        # Theo dõi tham số nào ảnh hưởng đến biến cục bộ
        var_from_param: Dict[str, Tuple[Set[int], Set[str]]] = {
            p: ({i}, {"user"}) for i, p in enumerate(params)
        }

        for stmt in func_node.body:
            # Ghi nhận lời gọi xuyên file (assign hoặc expr)
            call_node: Optional[ast.Call] = None
            assign_target: Optional[str] = None
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                call_node = stmt.value
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    assign_target = stmt.targets[0].id
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call_node = stmt.value
            elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                call_node = stmt.value

            if call_node is not None:
                callee_resolved = self._resolve_callee(call_node.func, local_imports)
                if callee_resolved:
                    c_mod, c_fn = callee_resolved
                    arg_vars: Dict[int, Set[str]] = {}
                    arg_param_flows: Dict[int, Tuple[Set[int], Set[str]]] = {}
                    for idx, a in enumerate(call_node.args):
                        arg_vars[idx] = {n.id for n in ast.walk(a) if isinstance(n, ast.Name)}
                        p_idxs_a, tags_a = self._collect_param_flow(a, var_from_param)
                        if p_idxs_a:
                            arg_param_flows[idx] = (p_idxs_a, tags_a)
                    summary.call_sites.append({
                        "callee_mod": c_mod,
                        "callee_fn": c_fn,
                        "arg_vars": arg_vars,
                        "arg_param_flows": arg_param_flows,
                        "assign_to": assign_target,
                        "line_no": getattr(call_node, "lineno", 1),
                    })

            # Lan truyền param -> biến cục bộ
            if isinstance(stmt, ast.Assign) and stmt.value is not None:
                p_idxs, tags = self._collect_param_flow(stmt.value, var_from_param)
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and p_idxs:
                        var_from_param[t.id] = (p_idxs, tags)

            # Kiểm tra Return có trả về dữ liệu từ param không
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                p_idxs, tags = self._collect_param_flow(stmt.value, var_from_param)
                for idx in p_idxs:
                    summary.return_taint_from_param.setdefault(idx, set()).update(tags)

            # Kiểm tra Sinks nhận dữ liệu từ param
            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue
                fn_raw = get_ast_func_name(sub.func)
                ln = getattr(sub, "lineno", 1)
                if any(k in fn_raw for k in ("completions.create", "chat.create")):
                    for kw in sub.keywords:
                        if kw.arg == "messages":
                            p_idxs, p_tags = self._collect_param_flow(kw.value, var_from_param)
                            has_sys = "system" in ast.dump(kw.value)
                            desc = "llm_messages" if has_sys else "llm_messages_no_system_role"
                            hop = (f"{norm_rel}:{func_node.name}() [L{ln}]",)
                            for idx in p_idxs:
                                summary.sink_from_param.setdefault(idx, []).append(
                                    ("AI-SAST-001", norm_rel, ln, desc, tuple(sorted(p_tags)), hop)
                                )
                elif fn_raw.endswith(".execute") or fn_raw.endswith(".executemany"):
                    if sub.args:
                        p_idxs, p_tags = self._collect_param_flow(sub.args[0], var_from_param)
                        hop = (f"{norm_rel}:{func_node.name}() [L{ln}]",)
                        for idx in p_idxs:
                            summary.sink_from_param.setdefault(idx, []).append(
                                ("AI-SAST-006", norm_rel, ln, "sql_execute", tuple(sorted(p_tags)), hop)
                            )
                elif fn_raw in ("eval", "exec"):
                    if sub.args:
                        p_idxs, p_tags = self._collect_param_flow(sub.args[0], var_from_param)
                        hop = (f"{norm_rel}:{func_node.name}() [L{ln}]",)
                        for idx in p_idxs:
                            summary.sink_from_param.setdefault(idx, []).append(
                                ("AI-SAST-004", norm_rel, ln, "code_exec", tuple(sorted(p_tags)), hop)
                            )

        return summary

    @staticmethod
    def _resolve_callee(
        func_node: ast.AST, local_imports: Dict[str, Tuple[str, Optional[str]]]
    ) -> Optional[Tuple[str, str]]:
        if isinstance(func_node, ast.Name) and func_node.id in local_imports:
            mk, sym = local_imports[func_node.id]
            if sym:
                return (mk, sym)
        if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            head = func_node.value.id
            if head in local_imports:
                mk, sym = local_imports[head]
                if sym is None:
                    return (mk, func_node.attr)
        return None

    @staticmethod
    def _collect_param_flow(
        expr: ast.AST, var_from_param: Dict[str, Tuple[Set[int], Set[str]]]
    ) -> Tuple[Set[int], Set[str]]:
        p_idxs: Set[int] = set()
        tags: Set[str] = set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in var_from_param:
                idxs, t = var_from_param[n.id]
                p_idxs |= idxs
                tags |= t
            if isinstance(n, ast.JoinedStr):
                tags.add("mixed_prompt")
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("format", "format_map", "join"):
                tags.add("mixed_prompt")
            elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                tags.add("mixed_prompt")
        return p_idxs, tags

    def _propagate_summary_step(self, summary: CrossFileFuncSummary) -> bool:
        """Một bước fixed-point lan truyền sink/return taint qua call_sites (chống circular bằng visited)."""
        changed = False
        visited: Set[Tuple[str, str]] = {(summary.module_key, summary.func_name)}
        var_params: Dict[str, Tuple[Set[int], Set[str]]] = {
            p: ({i}, {"user"}) for i, p in enumerate(summary.params)
        }

        for cs in summary.call_sites:
            ckey = (cs["callee_mod"], cs["callee_fn"])
            if ckey in visited:
                continue
            callee = self.summaries.get(ckey)
            if not callee:
                continue
            visited.add(ckey)

            for arg_idx, arg_vars in cs["arg_vars"].items():
                src_pidxs: Set[int] = set()
                src_tags: Set[str] = set()
                for av in arg_vars:
                    if av in var_params:
                        pi, pt = var_params[av]
                        src_pidxs |= pi
                        src_tags |= pt
                # Kết hợp param flow từ biến cục bộ và từ call_sites trước đó
                if arg_idx in cs.get("arg_param_flows", {}):
                    pi, pt = cs["arg_param_flows"][arg_idx]
                    src_pidxs |= pi
                    src_tags |= pt
                if not src_pidxs:
                    continue

                # Lan truyền return taint
                if cs["assign_to"] and arg_idx in callee.return_taint_from_param:
                    new_tags = src_tags | callee.return_taint_from_param[arg_idx]
                    prev = var_params.get(cs["assign_to"])
                    if prev != (src_pidxs, new_tags):
                        var_params[cs["assign_to"]] = (src_pidxs, new_tags)
                        changed = True

                # Lan truyền sink từ callee lên caller (kèm bước trung gian)
                if arg_idx in callee.sink_from_param:
                    cur_hop = f"{summary.file_rel}:{summary.func_name}()"
                    for rule_id, s_file, s_line, s_desc, s_tags, s_hops in callee.sink_from_param[arg_idx]:
                        merged_tags = tuple(sorted(set(s_tags) | src_tags))
                        merged_hops = (cur_hop,) + tuple(h for h in s_hops if h != cur_hop)
                        propagated = (rule_id, s_file, s_line, s_desc, merged_tags, merged_hops)
                        for pidx in src_pidxs:
                            lst = summary.sink_from_param.setdefault(pidx, [])
                            if not any(x[0] == rule_id and x[1] == s_file and x[2] == s_line for x in lst):
                                lst.append(propagated)
                                changed = True
        return changed


# ──────────────────────────────────────────────────────────────────────────────
# Bộ phân tích phi-Python: YAML, Modelfile, JS/TS
# ──────────────────────────────────────────────────────────────────────────────
def analyze_yaml_config(
    code: str,
    filename: str,
    lines: List[str],
    rules_by_id: Dict[str, Dict[str, Any]],
    format_snippet_fn: Callable[[List[str], int, Optional[int]], str],
    existing_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Phân tích tệp YAML bằng yaml.safe_load() để bung toàn bộ Anchor/Alias (&, <<: *)
    và kiểm tra các khóa cấu hình rủi ro AI Agent / LLM.
    """
    try:
        data = yaml.safe_load(code)
    except Exception:
        return []
    if not isinstance(data, (dict, list)):
        return []

    results: List[Dict[str, Any]] = []
    reported_keys: Set[Tuple[str, str]] = set()

    def find_line(key: str, val_hint: Optional[str] = None) -> int:
        # Ưu tiên tìm dòng khớp cả key và val_hint, sau đó dòng khớp key, cuối cùng mới tìm val_hint
        key_re = re.compile(rf"^\s*{re.escape(key)}\s*:", re.IGNORECASE)
        if val_hint is not None:
            for idx, ln in enumerate(lines, start=1):
                if key_re.search(ln) and val_hint.lower() in ln.lower():
                    return idx
        for idx, ln in enumerate(lines, start=1):
            if key_re.search(ln):
                return idx
        if val_hint:
            for idx, ln in enumerate(lines, start=1):
                if val_hint.lower() in ln.lower():
                    return idx
        return 1

    def emit(rule_id: str, path_str: str, key: str, detail: str, val_hint: Optional[str] = None) -> None:
        line_no = find_line(key, val_hint)
        # Bỏ qua nếu đã có finding cùng rule ở cùng dòng (ví dụ từ regex)
        if any(f["rule_id"] == rule_id and abs(f["line"] - line_no) <= 1 and f["file"] == filename for f in existing_findings):
            return
        # Tránh báo lặp cùng rule cho cả block anchor gốc (_base_runtime) và block kế thừa (production)
        if (rule_id, key.lower()) in reported_keys:
            return
        reported_keys.add((rule_id, key.lower()))

        rule = rules_by_id.get(rule_id)
        if not rule:
            return
        code_line = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else f"{key}: {val_hint or ''}"
        results.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "owasp": rule["owasp"],
            "mitre": rule["mitre"],
            "cwe": rule["cwe"],
            "file": filename,
            "line": line_no,
            "code_line": code_line[:220],
            "context_snippet": format_snippet_fn(lines, line_no, line_no),
            "description": f"{rule['description']} [YAML Config `{path_str}`: {detail}]",
            "remediation": rule["remediation"],
            "fix_example": rule["fix_example"],
            "engine": "YAML Anchor-Resolved Config Analyzer",
        })

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            # Ưu tiên duyệt các block triển khai thực tế trước các block anchor ẩn (_base_*)
            ordered_items = sorted(obj.items(), key=lambda kv: str(kv[0]).startswith("_"))
            for k, v in ordered_items:
                k_str = str(k)
                k_low = k_str.lower()
                cur_path = f"{path}.{k_str}" if path else k_str

                if k_low == "trust_remote_code" and v is True:
                    emit("AI-SAST-005", cur_path, k_str, "Bật `trust_remote_code: true` (kể cả qua kế thừa YAML Anchor)", "true")
                elif k_low in ("verify_ssl", "ssl_verify", "tls_verify") and v is False:
                    emit("AI-SAST-009", cur_path, k_str, "Vô hiệu hóa xác thực TLS (`verify_ssl: false`)", "false")
                elif k_low == "sandbox_mode" and (v is False or str(v).lower() in ("off", "false", "disabled", "none")):
                    emit("AI-SAST-004", cur_path, k_str, f"Tắt cơ chế cách ly Agent (`sandbox_mode: {v}`)", str(v))
                elif k_low in ("max_tokens", "num_predict") and isinstance(v, (int, float)) and (v <= 0 or v >= 100000):
                    emit("AI-SAST-007", cur_path, k_str, f"Không giới hạn hoặc giới hạn token quá lớn (`{k_str}: {v}`)", str(v))
                elif k_low == "system_prompt_override" and v is True:
                    emit("AI-SAST-001", cur_path, k_str, "Cho phép ghi đè System Prompt (`system_prompt_override: true`)", "true")
                elif k_low == "allowed_tools" and isinstance(v, list):
                    tools_low = [str(t).lower() for t in v]
                    exec_hits = [t for t in tools_low if t in YAML_DANGEROUS_EXEC_TOOLS]
                    net_hits = [t for t in tools_low if t in YAML_DANGEROUS_NET_TOOLS]
                    if exec_hits:
                        emit(
                            "AI-SAST-004",
                            cur_path,
                            "allowed_tools",
                            f"Cấp công cụ thực thi/ghi hệ thống nguy hiểm cho Agent: {', '.join(exec_hits)}",
                            exec_hits[0],
                        )
                    if net_hits:
                        emit(
                            "AI-SAST-006",
                            cur_path,
                            "allowed_tools",
                            f"Cấp công cụ truy cập HTTP không giới hạn (rủi ro SSRF): {', '.join(net_hits)}",
                            net_hits[0],
                        )
                elif isinstance(v, str):
                    sec_label = match_secret_value(v)
                    if sec_label:
                        emit("AI-SAST-002", cur_path, k_str, f"Lộ {sec_label} trong cấu hình YAML ({_redact_secret(v)})", v[:10])
                walk(v, cur_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{path}[{idx}]")

    walk(data)
    return results


def analyze_modelfile(
    code: str,
    filename: str,
    lines: List[str],
    rules_by_id: Dict[str, Dict[str, Any]],
    format_snippet_fn: Callable[[List[str], int, Optional[int]], str],
    existing_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Parse Ollama Modelfile theo directive (FROM, PARAMETER, SYSTEM block nhiều dòng):
      - PARAMETER num_predict -1 / num_ctx >= 65536 -> AI-SAST-007
      - Bí mật (DB URI, webhook secret, API key) trong block SYSTEM -> AI-SAST-002
      - Lệnh backdoor / override an toàn trong block SYSTEM -> AI-SAST-010
    """
    results: List[Dict[str, Any]] = []

    def emit(rule_id: str, line_no: int, detail: str) -> None:
        if any(
            f["rule_id"] == rule_id and f["line"] == line_no and f["file"] == filename
            for f in (existing_findings + results)
        ):
            return
        rule = rules_by_id.get(rule_id)
        if not rule:
            return
        code_line = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        results.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "owasp": rule["owasp"],
            "mitre": rule["mitre"],
            "cwe": rule["cwe"],
            "file": filename,
            "line": line_no,
            "code_line": code_line[:220],
            "context_snippet": format_snippet_fn(lines, line_no, line_no),
            "description": f"{rule['description']} [Modelfile Audit: {detail}]",
            "remediation": rule["remediation"],
            "fix_example": rule["fix_example"],
            "engine": "Modelfile Directive Security Parser",
        })

    in_system_block = False
    backdoor_re = re.compile(
        r"(?:ignore\s+all\s+(?:prior|previous)\s+safety|dump\s+the\s+full\s+system\s+context|"
        r"debug_override|override\s+all\s+(?:rules|instructions)|bypass\s+safety)",
        re.IGNORECASE,
    )

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or (not in_system_block and stripped.startswith("#")):
            continue

        # Xử lý khối SYSTEM """ ... """
        if not in_system_block and re.match(r"^SYSTEM\s+\"\"\"", stripped, re.IGNORECASE):
            in_system_block = True
            after_open = stripped[stripped.find('"""') + 3:]
            if '"""' in after_open:
                in_system_block = False
            continue

        if in_system_block:
            if '"""' in stripped:
                in_system_block = False
            sec_label = match_secret_value(stripped)
            if sec_label:
                emit("AI-SAST-002", idx, f"Phát hiện {sec_label} nhúng cứng trong khối SYSTEM của Modelfile")
            if backdoor_re.search(stripped):
                emit("AI-SAST-010", idx, "Phát hiện điều kiện Backdoor / Prompt Override trong khối SYSTEM của Modelfile")
            continue

        # Xử lý directive PARAMETER
        m_param = re.match(r"^PARAMETER\s+([a-zA-Z0-9_]+)\s+([^\s#]+)", stripped, re.IGNORECASE)
        if m_param:
            pname = m_param.group(1).lower()
            pval_str = m_param.group(2)
            try:
                pval = float(pval_str)
            except ValueError:
                continue
            if pname == "num_predict" and (pval <= 0 or pval > 16384):
                emit("AI-SAST-007", idx, f"Cấu hình `PARAMETER num_predict {pval_str}` không giới hạn đầu ra (Unbounded Consumption)")
            elif pname == "num_ctx" and pval >= 65536:
                emit("AI-SAST-007", idx, f"Cấu hình `PARAMETER num_ctx {pval_str}` mở cửa sổ ngữ cảnh quá lớn (rủi ro DoS bộ nhớ)")

    return results


def analyze_js_ts(
    code: str,
    filename: str,
    lines: List[str],
    rules_by_id: Dict[str, Dict[str, Any]],
    format_snippet_fn: Callable[[List[str], int, Optional[int]], str],
    existing_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    r"""
    Phân tích tĩnh chuyên biệt cho JavaScript / TypeScript:
      1. Gấp mảng nối chuỗi tĩnh: const arr = ["sk", "ant", ...]; arr.join("-") -> AI-SAST-002
      2. Phát hiện `new Function(...)` / `Function(...)` RCE -> AI-SAST-004
      3. Phát hiện Tagged Template Prompt Injection (`buildPrompt\`...\${userInput}\``) -> AI-SAST-001
    """
    results: List[Dict[str, Any]] = []

    def emit(rule_id: str, line_no: int, detail: str) -> None:
        if any(
            f["rule_id"] == rule_id and f["line"] == line_no and f["file"] == filename
            for f in (existing_findings + results)
        ):
            return
        rule = rules_by_id.get(rule_id)
        if not rule:
            return
        code_line = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        results.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "owasp": rule["owasp"],
            "mitre": rule["mitre"],
            "cwe": rule["cwe"],
            "file": filename,
            "line": line_no,
            "code_line": code_line[:220],
            "context_snippet": format_snippet_fn(lines, line_no, line_no),
            "description": f"{rule['description']} [JS/TS Static Analyzer: {detail}]",
            "remediation": rule["remediation"],
            "fix_example": rule["fix_example"],
            "engine": "JS/TS Static Security Analyzer",
        })

    # 1. Thu thập các mảng chuỗi hằng: const keyChunks = ["sk", "ant", ...]
    array_env: Dict[str, List[str]] = {}
    arr_decl_re = re.compile(r"\b(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[([^\]]{1,2000})\]")
    str_item_re = re.compile(r"""["']([^"']*)["']""")

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for m in arr_decl_re.finditer(line):
            var_name = m.group(1)
            items = str_item_re.findall(m.group(2))
            if items:
                array_env[var_name] = items

        # Kiểm tra var.join("sep")
        for m in re.finditer(r"""\b([a-zA-Z_$][a-zA-Z0-9_$]*)\.join\(\s*["']([^"']*)["']\s*\)""", line):
            var_name, sep = m.group(1), m.group(2)
            if var_name in array_env:
                folded = sep.join(array_env[var_name])
                sec_label = match_secret_value(folded)
                if sec_label:
                    emit("AI-SAST-002", idx, f"Phát hiện {sec_label} bị tách mảnh qua `{var_name}.join('{sep}')` ({_redact_secret(folded)})")

        # Kiểm tra inline ["sk", "ant", ...].join("-")
        for m in re.finditer(r"""\[([^\]]{1,2000})\]\.join\(\s*["']([^"']*)["']\s*\)""", line):
            items = str_item_re.findall(m.group(1))
            if items:
                folded = m.group(2).join(items)
                sec_label = match_secret_value(folded)
                if sec_label:
                    emit("AI-SAST-002", idx, f"Phát hiện {sec_label} bị tách mảnh qua Array.join ({_redact_secret(folded)})")

        # 2. Phát hiện new Function(...) RCE
        if re.search(r"\bnew\s+Function\s*\(", line):
            emit("AI-SAST-004", idx, "Sử dụng `new Function(...)` để thực thi mã JavaScript động (tương đương eval() RCE)")

        # 3. Phát hiện Tagged Template Prompt Injection hoặc template nối input vào prompt
        m_tag = re.search(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)`([^`]*\$\{[^}]+\}[^`]*)`", line)
        if m_tag:
            tag_fn, tpl_body = m_tag.group(1), m_tag.group(2)
            if re.search(r"(?:prompt|analyze|instruction|system|summarize|return|question|user)", tag_fn + " " + tpl_body, re.IGNORECASE):
                emit("AI-SAST-001", idx, f"Tagged Template Injection `{tag_fn}\\`...\\`` nối trực tiếp biến đầu vào vào chuỗi Prompt")

    return results
