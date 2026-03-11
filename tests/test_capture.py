from pathlib import Path

from common import capture


def test_start_capture_falls_back_to_scapy(monkeypatch, tmp_path):
    started = {}

    class FakeWriter:
        def __init__(self, path, append, sync):
            started["path"] = path
            started["append"] = append
            started["sync"] = sync
            self.closed = False

        def write(self, pkt):
            started["last_pkt"] = pkt

        def close(self):
            self.closed = True
            started["closed"] = True

    class FakeSniffer:
        def __init__(self, iface, filter, store, prn):
            started["iface"] = iface
            started["filter"] = filter
            started["store"] = store
            started["prn"] = prn
            self.stopped = False

        def start(self):
            started["started"] = True

        def stop(self):
            self.stopped = True
            started["stopped"] = True

    monkeypatch.setattr(capture.shutil, "which", lambda name: None)
    monkeypatch.setattr(capture, "PcapWriter", FakeWriter)
    monkeypatch.setattr(capture, "AsyncSniffer", FakeSniffer)

    out_file = tmp_path / "captures" / "receiver.pcap"
    handle = capture.start_capture("\\Device\\NPF_Loopback", str(out_file), bpf_filter="icmp")

    assert handle is not None
    assert started["path"] == str(out_file)
    assert started["iface"] == "\\Device\\NPF_Loopback"
    assert started["filter"] == "icmp"
    assert started["store"] is False
    assert started["started"] is True

    capture.stop_capture(handle)
    assert started["stopped"] is True
    assert started["closed"] is True


def test_start_capture_uses_tcpdump_when_available(monkeypatch, tmp_path):
    launched = {}

    class FakeProc:
        def poll(self):
            return 0

    def fake_popen(cmd, stdout, stderr):
        launched["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(capture.shutil, "which", lambda name: "/usr/sbin/tcpdump")
    monkeypatch.setattr(capture.subprocess, "Popen", fake_popen)

    out_file = tmp_path / "sender.pcap"
    handle = capture.start_capture("eth0", str(out_file), bpf_filter="udp and port 53")

    assert handle is not None
    assert handle.proc is not None
    assert launched["cmd"] == ["/usr/sbin/tcpdump", "-i", "eth0", "udp and port 53", "-w", str(out_file)]
