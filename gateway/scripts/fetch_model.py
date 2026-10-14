"""Make sure the trained classifier is in place before the gateway starts
(module 10). Run by the compose `model` service.

    python -m scripts.fetch_model

The checkpoint (~740 MB) isn't in git. On the machine that trained it, it is
already at training/checkpoints/final/ (mounted at THREAT_MODEL_DIR) and this
exits at once. Anywhere else it is downloaded from the project's private
Hugging Face repo, which needs a read token in HF_TOKEN. Without one, this
fails with a message saying how to provide the model, and the gateway (which
can't run without it) doesn't start.

Environment: THREAT_MODEL_DIR (where the gateway reads it), HF_TOKEN,
HF_MODEL_REPO (default Chinmayyyyy/genai-gateway-classifier),
HF_MODEL_SUBDIR (default classifier_v2, the shipped model).
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

DEFAULT_REPO = "Chinmayyyyy/genai-gateway-classifier"
DEFAULT_SUBDIR = "classifier_v2"


def main() -> None:
    target = Path(os.environ.get("THREAT_MODEL_DIR") or "/models/threat-classifier")
    if (target / "config.json").exists():
        print(f"fetch_model: classifier present at {target}", flush=True)
        return

    token = os.environ.get("HF_TOKEN", "")
    repo = os.environ.get("HF_MODEL_REPO", DEFAULT_REPO)
    subdir = os.environ.get("HF_MODEL_SUBDIR", DEFAULT_SUBDIR)
    if not token:
        sys.exit(
            "fetch_model: the trained classifier is missing (training/checkpoints/final/).\n"
            "  Either copy that folder from the machine that has it, or set HF_TOKEN in .env\n"
            f"  to a Hugging Face read token with access to {repo}, then start again."
        )

    from huggingface_hub import snapshot_download

    print(f"fetch_model: downloading {repo}/{subdir} (~740 MB)", flush=True)
    target.mkdir(parents=True, exist_ok=True)
    # Staged inside the target (same filesystem, so the moves are renames).
    with tempfile.TemporaryDirectory(dir=target, prefix=".download-") as staging:
        snapshot_download(repo, allow_patterns=[f"{subdir}/*"], local_dir=staging, token=token)
        # Moved in file by file, config.json last: a download cut short never
        # looks like a complete checkpoint to the check above.
        files = sorted(Path(staging, subdir).iterdir(), key=lambda p: p.name == "config.json")
        for file in files:
            shutil.move(str(file), target / file.name)
    print(f"fetch_model: classifier ready at {target}", flush=True)


if __name__ == "__main__":
    main()
