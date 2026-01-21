import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from langchain_text_splitters import RecursiveCharacterTextSplitter
import config.core_config as core_config
from services import settings_store

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _require_langchain() -> None:
    try:
        import langchain  # noqa: F401
        import langchain_community  # noqa: F401
    except Exception as e:
        raise RuntimeError("LangChain 依赖未安装。请先执行: pip install -r requirements.txt") from e


def _rag_index_key(project_key: str, source: str) -> str:
    return f"{core_config.REDIS_KEY_PREFIX}rag:lc:index:{project_key}:{source}"


def _kb_paths(project_key: str, source: str) -> List[Path]:
    """
    Search order:
    1) knowledge_base/projects/<project_key>/<source>/**/*.md
    2) knowledge_base/<source>/**/*.md
    """
    base = Path("knowledge_base")
    out: List[Path] = []
    candidates = [
        base / "projects" / project_key / source,
        base / source,
    ]
    for root in candidates:
        if not root.exists():
            continue
        out.extend([p for p in root.rglob("*.md") if p.is_file()])
    # de-dup
    return sorted(set(out))


def _load_documents(project_key: str, source: str) -> List[Dict[str, Any]]:
    """
    Returns a list of serializable doc dicts:
      { "text": "...", "meta": {...} }
    """
    docs: List[Dict[str, Any]] = []
    for p in _kb_paths(project_key, source):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not (text or "").strip():
            continue
        docs.append({
            "text": text,
            "meta": {
                "path": str(p.as_posix()),
                "source": source,
                "project_key": project_key,
            },
        })
    return docs


def _split_documents(raw_docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    _require_langchain()
    splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=120)
    chunks: List[Dict[str, Any]] = []
    for d in raw_docs:
        text = str(d.get("text") or "")
        meta = d.get("meta") or {}
        for i, chunk in enumerate(splitter.split_text(text)):
            chunks.append({
                "text": chunk,
                "meta": {**meta, "chunk": i},
            })
    return chunks


def rebuild_index(project_key: str, source: str) -> Dict[str, Any]:
    """
    LangChain-only (simplified):
    - Load markdown docs from knowledge_base
    - Split into chunks
    - Persist chunks to Redis (or memory fallback)
    Retrieval uses LangChain BM25Retriever on demand.
    """
    source = (source or "").strip()
    if source not in {"project_docs", "dependency_docs"}:
        raise ValueError(f"Unsupported RAG source: {source}")

    raw_docs = _load_documents(project_key, source)
    chunks = _split_documents(raw_docs) if raw_docs else []
    payload = {
        "version": 1,
        "created_at": _now_iso(),
        "project_key": project_key,
        "source": source,
        "documents": chunks,
    }

    if core_config.redis_client:
        core_config.redis_client.set(_rag_index_key(project_key, source), json.dumps(payload, ensure_ascii=False))
    return payload


def load_index(project_key: str, source: str) -> Optional[Dict[str, Any]]:
    if not project_key or not source:
        return None
    if core_config.redis_client:
        raw = core_config.redis_client.get(_rag_index_key(project_key, source))
        if raw:
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return None
    return None


def ensure_index(project_key: str, source: str) -> Dict[str, Any]:
    idx = load_index(project_key, source)
    if idx:
        return idx
    return rebuild_index(project_key, source)


def project_key(vcs_type: str, identifier: str) -> Optional[str]:
    if not vcs_type or not identifier:
        return None
    base = vcs_type.split("_", 1)[0].lower()
    if base == "github":
        return f"github:{identifier}"
    if base == "gitlab":
        return f"gitlab:{identifier}"
    return None


def effective_rag_config(project_key: str) -> Dict[str, Any]:
    """
    Combine:
    - global policy (app_configs.RAG_TRIGGER_POLICY)
    - agent settings (dashboard toggles)
    - project settings (project modal toggles)
    """
    policy = str(core_config.app_configs.get("RAG_TRIGGER_POLICY", "on_demand") or "on_demand").lower()
    if policy == "never":
        return {"enabled": False, "sources": []}

    agent = settings_store.get_agent_settings().get("rag") or {}
    proj = settings_store.get_project_settings(project_key).get("rag") or {}

    proj_enabled = bool(proj.get("enabled"))
    agent_enabled = bool(agent.get("enabled"))
    enabled = proj_enabled and (policy == "auto" or agent_enabled)
    if not enabled:
        return {"enabled": False, "sources": []}

    agent_sources = (agent.get("sources") or {}) if isinstance(agent.get("sources"), dict) else {}
    proj_sources = (proj.get("sources") or {}) if isinstance(proj.get("sources"), dict) else {}

    def _on(src_key: str, default: bool) -> bool:
        if policy == "auto":
            return bool(proj_sources.get(src_key, default))
        return bool(proj_sources.get(src_key, default)) and bool(agent_sources.get(src_key, default))

    sources: List[str] = []
    if _on("docs", False):
        sources.append("project_docs")
    if _on("deps", False):
        sources.append("dependency_docs")
    return {"enabled": True, "sources": sources}


def _build_retriever(chunks: List[Dict[str, Any]]):
    _require_langchain()
    from langchain_community.retrievers import BM25Retriever
    from langchain_core.documents import Document

    docs = [Document(page_content=str(d.get("text") or ""), metadata=d.get("meta") or {}) for d in (chunks or [])]
    # BM25Retriever returns docs in relevance order; scores are not exposed in a stable API.
    return BM25Retriever.from_documents(docs)


def retrieve(
    project_key: str,
    query: str,
    *,
    sources: List[str],
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    if not project_key or not query or not sources:
        return []
    top_k = max(1, min(int(top_k or 5), 10))

    hits: List[Dict[str, Any]] = []
    for src in sources:
        idx = ensure_index(project_key, src)
        chunks = (idx or {}).get("documents") or []
        if not chunks:
            continue
        retriever = _build_retriever(chunks)
        try:
            docs = retriever.invoke(query)  # LangChain 1.x
        except Exception:
            docs = retriever.get_relevant_documents(query)  # older compat

        for rank, d in enumerate((docs or [])[:top_k], start=1):
            meta = getattr(d, "metadata", {}) or {}
            text = getattr(d, "page_content", "") or ""
            hits.append({
                "score": 1.0 / float(rank),
                "source": src,
                "doc": {
                    "text": text,
                    "meta": meta,
                },
            })

    hits.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
    return hits[:top_k]


def build_rag_context_for_file(
    vcs_type: str,
    identifier: str,
    file_path: str,
    file_data: Dict[str, Any],
    *,
    top_k: int = 4,
    max_chars: int = 2600,
) -> Dict[str, Any]:
    pk = project_key(vcs_type, identifier)
    if not pk:
        return {"enabled": False, "sources": [], "hits": [], "context": ""}

    cfg = effective_rag_config(pk)
    if not cfg.get("enabled"):
        return {"enabled": False, "sources": [], "hits": [], "context": ""}

    sources = list(cfg.get("sources") or [])
    if not sources:
        return {"enabled": True, "sources": [], "hits": [], "context": ""}

    # Build a retrieval query from the diff context + added lines (same idea as before).
    parts = [str(file_path or "")]
    ctx = (file_data or {}).get("context") or {}
    for k in ("old", "new"):
        v = ctx.get(k)
        if v:
            parts.append(str(v))
    for ch in (file_data or {}).get("changes") or []:
        if isinstance(ch, dict) and ch.get("type") == "add" and ch.get("content"):
            parts.append(str(ch.get("content")))
    query = "\n".join(parts)

    hits = retrieve(pk, query, sources=sources, top_k=top_k)
    context_parts: List[str] = []
    for i, h in enumerate(hits, start=1):
        doc = (h.get("doc") or {})
        meta = doc.get("meta") or {}
        text = str(doc.get("text") or "").strip()
        if not text:
            continue
        head = f"[{i}] source={h.get('source')} path={meta.get('path','')}".strip()
        snippet = text[:800]
        context_parts.append(head + "\n" + snippet)

    context = "\n\n".join(context_parts)
    if len(context) > max_chars:
        context = context[:max_chars] + "\n...(truncated)"

    return {"enabled": True, "sources": sources, "hits": hits, "context": context}


def index_status(project_key: str) -> Dict[str, Any]:
    out = {"project_key": project_key, "sources": {}}
    for src in ("project_docs", "dependency_docs"):
        idx = load_index(project_key, src)
        out["sources"][src] = {
            "indexed": bool(idx),
            "documents": len((idx or {}).get("documents") or []),
            "created_at": (idx or {}).get("created_at"),
        }
    return out
