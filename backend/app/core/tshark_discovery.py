import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple


def discover_tshark_path() -> Optional[Path]:
    """
    Locates the TShark binary on the host system.
    Checks:
    1. TSHARK_PATH environment variable
    2. PATH environment variable via shutil.which
    3. Windows standard installation path (C:\\Program Files\\Wireshark\\tshark.exe)
    """
    # 1. Custom ENV override
    env_path = os.getenv("TSHARK_PATH")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    # 2. System PATH
    which_path = shutil.which("tshark")
    if which_path and Path(which_path).is_file():
        return Path(which_path)

    # 3. Standard Windows location
    win_std_path = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if win_std_path.is_file():
        return win_std_path

    return None


def get_tshark_version() -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Executes 'tshark --version' using array subprocess (no shell=True).
    Returns (available, version_string, binary_path_str)
    """
    tshark_bin = discover_tshark_path()
    if not tshark_bin:
        return False, None, None

    try:
        result = subprocess.run(
            [str(tshark_bin), "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        first_line = result.stdout.splitlines()[0] if result.stdout else "Unknown version"
        return True, first_line.strip(), str(tshark_bin)
    except (subprocess.SubprocessError, Exception) as e:
        return False, f"Execution error: {str(e)}", str(tshark_bin)
