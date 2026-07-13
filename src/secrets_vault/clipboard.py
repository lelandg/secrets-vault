"""Best-effort clipboard: pyperclip, then WSL clip.exe. Never raises."""
import shutil
import subprocess


def _pyperclip_copy(text: str) -> None:
    import pyperclip
    pyperclip.copy(text)


def copy(text: str) -> bool:
    try:
        _pyperclip_copy(text)
        return True
    except Exception:
        pass
    clip = shutil.which("clip.exe")
    if clip:
        try:
            subprocess.run([clip], input=text.encode(), check=True, timeout=5)
            return True
        except Exception:
            return False
    return False
