import re
from typing import Any, Dict, List, Optional, Set, Tuple


def _detect_function_defs(lines: List[Tuple[int, str]], parser: str) -> List[Tuple[int, str]]:
    """
    Returns list of (line_no, function_name).
    """
    parser = (parser or "python").lower()

    patterns = []
    if parser == "python":
        patterns = [re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(")]
    elif parser in {"js", "javascript", "ts", "typescript"}:
        patterns = [
            re.compile(r"^\s*function\s+([A-Za-z_$][\w$]*)\s*\("),
            re.compile(r"^\s*(?:export\s+)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*=\s*\(?.*=>"),
        ]
    elif parser == "go":
        patterns = [re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([A-Za-z_]\w*)\s*\(")]
    elif parser == "java":
        patterns = [re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?[\w<>,\\[\\]]+\s+([A-Za-z_]\w*)\s*\(")]
    else:
        patterns = [re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(")]

    out = []
    for ln, text in lines:
        for pat in patterns:
            m = pat.search(text)
            if m:
                out.append((ln, m.group(1)))
                break
    return out


def _extract_calls(text: str, candidates: Set[str]) -> Set[str]:
    found: Set[str] = set()
    if not candidates:
        return found
    # Very lightweight: look for `name(`.
    for name in candidates:
        if re.search(rf"\b{re.escape(name)}\s*\(", text):
            found.add(name)
    return found


def build_call_graph_from_structured_changes(
    structured_changes: Dict[str, Any],
    max_depth: int = 3,
    cross_file: bool = False,
    parser: str = "python",
) -> Dict[str, Any]:
    """
    Build an intra-diff call graph. This is a placeholder RAG implementation:
    - Nodes are functions detected in added lines.
    - Edges are calls detected in added lines, attributed to the nearest preceding function def in the same file.
    """
    max_depth = int(max_depth or 0)
    if max_depth <= 0:
        max_depth = 1

    added_lines_by_file: Dict[str, List[Tuple[int, str]]] = {}
    for file_path, fd in (structured_changes or {}).items():
        changes = (fd or {}).get("changes") or []
        added = []
        for ch in changes:
            if not isinstance(ch, dict):
                continue
            if ch.get("type") != "add":
                continue
            ln = ch.get("new_line")
            if ln is None:
                continue
            added.append((int(ln), str(ch.get("content") or "")))
        if added:
            added_lines_by_file[str(file_path)] = sorted(added, key=lambda x: x[0])

    # 1) Collect function definitions across all files.
    funcs_by_file: Dict[str, List[Tuple[int, str]]] = {}
    all_funcs: Set[str] = set()
    for file_path, lines in added_lines_by_file.items():
        defs = _detect_function_defs(lines, parser=parser)
        if defs:
            funcs_by_file[file_path] = defs
            all_funcs.update([name for _, name in defs])

    # 2) Build edges within each file by scanning in line order and tracking current function.
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

    def add_node(node_id: str, label: str, node_type: str) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label, "type": node_type}

    for file_path, lines in added_lines_by_file.items():
        file_node = f"file:{file_path}"
        add_node(file_node, file_path, "file")

        defs = funcs_by_file.get(file_path) or []
        def_iter = iter(sorted(defs, key=lambda x: x[0]))
        next_def = next(def_iter, None)
        current_func: Optional[str] = None

        for ln, text in lines:
            # Advance current func if we reached its def line.
            if next_def and ln >= next_def[0]:
                current_func = next_def[1]
                add_node(f"fn:{current_func}", current_func, "function")
                # Link file -> function (ownership)
                edges.append({"from": file_node, "to": f"fn:{current_func}", "type": "defines"})
                next_def = next(def_iter, None)

            # Calls to any detected function.
            calls = _extract_calls(text, all_funcs)
            for callee in sorted(calls):
                add_node(f"fn:{callee}", callee, "function")
                caller_id = f"fn:{current_func}" if current_func else file_node
                edges.append({"from": caller_id, "to": f"fn:{callee}", "type": "calls"})
                evidence.append({
                    "file": file_path,
                    "line": ln,
                    "caller": current_func or file_path,
                    "callee": callee,
                    "snippet": text.strip(),
                    "source": "code_context",
                })

    # 3) (Optional) Cross-file is currently a placeholder knob.
    # We keep it in the response so the UI can show it in "RAG sources".
    rag_sources = ["code_context"]
    if cross_file:
        rag_sources.append("cross_file_placeholder")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "evidence": evidence[:200],
        "params": {"max_depth": max_depth, "cross_file": bool(cross_file), "parser": parser},
        "sources": rag_sources,
        "note": "Call graph is built from diff added lines only (placeholder RAG).",
    }
