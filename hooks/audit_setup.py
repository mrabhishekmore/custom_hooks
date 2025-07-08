import os
import shutil
from pathlib import Path

def main():
    hooks_dir = Path(".git/hooks")
    hooks_dir.mkdir(parents=True, exist_ok=True)

    prepare_hook_path = hooks_dir / "prepare-commit-msg"
    source_script_path = Path(__file__).parent / "prepare_commit_msg.sh"

    try:
        shutil.copyfile(source_script_path, prepare_hook_path)
        os.chmod(prepare_hook_path, 0o755)
        print(f"✔️ prepare-commit-msg hook installed at {prepare_hook_path}")
    except Exception as e:
        print(f"❌ Failed to install prepare-commit-msg hook: {e}")
        return 1

    return 0
