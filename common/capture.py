from __future__ import annotations
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from scapy.all import AsyncSniffer, PcapWriter  # type: ignore


@dataclass
class CaptureHandle:
    proc: Optional[subprocess.Popen] = None
    sniffer: Optional[AsyncSniffer] = None
    writer: Optional[PcapWriter] = None


def _start_tcpdump_capture(tcpdump: str, iface: str, out_file: str, bpf_filter: str) -> CaptureHandle:
    cmd = [tcpdump, "-i", iface, bpf_filter, "-w", out_file]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return CaptureHandle(proc=proc)


def _start_scapy_capture(iface: str, out_file: str, bpf_filter: str) -> CaptureHandle:
    writer = PcapWriter(out_file, append=False, sync=True)
    sniffer = AsyncSniffer(iface=iface, filter=bpf_filter, store=False, prn=writer.write)
    try:
        sniffer.start()
    except Exception:
        writer.close()
        raise
    return CaptureHandle(sniffer=sniffer, writer=writer)


def start_capture(iface: str, out_file: str, bpf_filter: str = "icmp") -> Optional[CaptureHandle]:
    '''
    Starts a local packet capture and writes packets to out_file.
    Prefers tcpdump when available and falls back to Scapy-based capture.
    '''
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        return _start_tcpdump_capture(tcpdump, iface, out_file, bpf_filter)

    try:
        return _start_scapy_capture(iface, out_file, bpf_filter)
    except Exception:
        return None


def stop_capture(handle: Optional[CaptureHandle]) -> None:
    if not handle:
        return

    if handle.proc and handle.proc.poll() is None:
        handle.proc.terminate()
        try:
            handle.proc.wait(timeout=2)
        except Exception:
            handle.proc.kill()

    if handle.sniffer:
        try:
            handle.sniffer.stop()
        except Exception:
            pass

    if handle.writer:
        handle.writer.close()
