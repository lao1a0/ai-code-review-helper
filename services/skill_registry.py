import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


@dataclass(frozen=True)
class SkillInfo:
    name: str
    version: str
    description: str
    tags: List[str]
    skill_dir: str
    doc_path: str
    updated_at: float


def _repo_root() -> Path:
    # This file lives in services/, so repo root is parent of that.
    return Path(__file__).resolve().parents[1]


def _skills_root() -> Path:
    return _repo_root() / "skills"


def _parse_front_matter(markdown_text: str) -> Tuple[Dict[str, Any], str]:
    """
    Very small front-matter parser:
      ---\n
      yaml...\n
      ---\n
      markdown body...
    """
    text = markdown_text.lstrip("\ufeff")
    if not text.startswith("---"):
        return {}, markdown_text

    parts = text.split("\n")
    if len(parts) < 3:
        return {}, markdown_text

    # Find second '---' line.
    end_idx = None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            end_idx = i
            break
    if end_idx is None:
        return {}, markdown_text

    fm_text = "\n".join(parts[1:end_idx])
    body = "\n".join(parts[end_idx + 1:])
    try:
        data = yaml.safe_load(fm_text) or {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    return data, body


def list_skills() -> List[SkillInfo]:
    root = _skills_root()
    if not root.exists():
        return []

    skills: List[SkillInfo] = []
    for entry in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_dir():
            continue
        doc = entry / "SKILL.md"
        if not doc.exists():
            continue
        try:
            content = doc.read_text(encoding="utf-8")
        except OSError:
            continue

        fm, _ = _parse_front_matter(content)
        name = str(fm.get("name") or entry.name)
        version = str(fm.get("version") or "0.0.0")
        description = str(fm.get("description") or "")
        tags_raw = fm.get("tags") or []
        if isinstance(tags_raw, str):
            tags = [tags_raw]
        elif isinstance(tags_raw, list):
            tags = [str(x) for x in tags_raw]
        else:
            tags = []

        try:
            updated_at = os.path.getmtime(doc)
        except OSError:
            updated_at = 0.0

        skills.append(SkillInfo(
            name=name,
            version=version,
            description=description,
            tags=tags,
            skill_dir=str(entry),
            doc_path=str(doc),
            updated_at=updated_at,
        ))

    return skills


def read_skill_doc(skill_name: str) -> Optional[str]:
    if not skill_name:
        return None
    for s in list_skills():
        if s.name == skill_name or Path(s.skill_dir).name == skill_name:
            try:
                return Path(s.doc_path).read_text(encoding="utf-8")
            except OSError:
                return None
    return None


def list_skill_dicts() -> List[Dict[str, Any]]:
    out = []
    for s in list_skills():
        out.append({
            "name": s.name,
            "version": s.version,
            "description": s.description,
            "tags": s.tags,
            "updated_at": s.updated_at,
        })
    return out
