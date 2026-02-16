from __future__ import annotations
import os
import shutil
import subprocess
from typing import Optional

def start_capture(iface: str, out_file: str, bpf_filter: str = "icmp") -> Optional[subprocess.Popen]:
    '''
    Starts tcpdump (if available) and writes packets to out_file.
    Returns Popen handle or None if tcpdump is unavailable.
    '''
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return None

    cmd = [tcpdump, "-i", iface, bpf_filter, "-w", out_file]
    # stdout/stderr suppressed to keep console clean
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_capture(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
