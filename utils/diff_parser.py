import logging
import re

logger = logging.getLogger(__name__)


def parse_single_file_diff(diff_text: str, file_path: str, old_file_path: str | None = None) -> dict:
    """
    Parse one unified diff (the "patch" field) into:
    - changes: add/delete lines with old/new line numbers
    - context: a small window of nearby lines (last 20)
    """
    file_changes = {
        "path": file_path,
        "old_path": old_file_path,
        "changes": [],
        "context": {"old": [], "new": []},
        "lines_changed": 0,
    }

    old_line_num_current = 0
    new_line_num_current = 0
    hunk_context_lines = []

    lines = (diff_text or "").splitlines()
    for line in lines:
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith("@@ "):
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                old_line_num_current = int(match.group(1))
                new_line_num_current = int(match.group(3))
                if hunk_context_lines:
                    file_changes["context"]["old"].extend(hunk_context_lines)
                    file_changes["context"]["new"].extend(hunk_context_lines)
                    hunk_context_lines = []
            else:
                logger.warning("Failed to parse hunk header for %s: %s", file_path, line)
                old_line_num_current = 0
                new_line_num_current = 0
            continue

        if line.startswith("+"):
            file_changes["changes"].append({"type": "add", "old_line": None, "new_line": new_line_num_current, "content": line[1:]})
            new_line_num_current += 1
            continue
        if line.startswith("-"):
            file_changes["changes"].append({"type": "delete", "old_line": old_line_num_current, "new_line": None, "content": line[1:]})
            old_line_num_current += 1
            continue
        if line.startswith(" "):
            hunk_context_lines.append(f"{old_line_num_current} -> {new_line_num_current}: {line[1:]}")
            old_line_num_current += 1
            new_line_num_current += 1

    if hunk_context_lines:
        file_changes["context"]["old"].extend(hunk_context_lines)
        file_changes["context"]["new"].extend(hunk_context_lines)

    limit = 20
    file_changes["context"]["old"] = "\n".join(file_changes["context"]["old"][-limit:])
    file_changes["context"]["new"] = "\n".join(file_changes["context"]["new"][-limit:])
    file_changes["lines_changed"] = len([c for c in file_changes["changes"] if c["type"] in ["add", "delete"]])
    return file_changes

