from pathlib import Path
from .config import settings

def artifact_root() -> Path:
    root = Path(getattr(settings, 'browser_artifacts_dir', 'data/artifacts'))
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()

def run_dir(run_id:int) -> Path:
    d = artifact_root() / 'runs' / str(run_id)
    d.mkdir(parents=True, exist_ok=True)
    return d

def write_text_artifact(run_id:int, name:str, content:str) -> str:
    safe = ''.join(c for c in name if c.isalnum() or c in '._-')
    p = (run_dir(run_id) / safe).resolve()
    if artifact_root() not in p.parents:
        raise ValueError('artifact path traversal blocked')
    p.write_text(content, errors='ignore')
    return str(p.relative_to(Path.cwd()))
