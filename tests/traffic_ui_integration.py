#!/usr/bin/env python3
"""Root/BTF integration: real socket counters in a 44-column terminal."""

import argparse
import ctypes
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import termios
import threading
import time


ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


class Terminal:
    def __init__(self, binary, *options, tid=None, ui=True, term="xterm-256color"):
        self.interactive = ui and term != "dumb"
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 44, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        self.output = bytearray()
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            [str(binary), "--traffic-ui" if ui else "--traffic",
             "--proto", "udp", "--pid", str(tid or os.getpid()),
             *options],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env={**os.environ, "TERM": term}, start_new_session=True,
        )

    @property
    def text(self):
        return ANSI.sub(b"", bytes(self.output)).decode("utf-8", "replace").replace("\r", "")

    @property
    def frame(self):
        return self.text.rsplit("ANETTRACE / TRAFFIC LAB", 1)[-1]

    def pump(self, seconds=0.1):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], max(0, deadline - time.monotonic()))[0]:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.output.extend(chunk)

    def until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if predicate():
                return
            if self.process.poll() is not None:
                break
        raise AssertionError(self.text)

    def key(self, key):
        os.write(self.master, key.encode())

    def finish(self):
        deadline = time.monotonic() + 6
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        assert self.process.poll() is not None, self.text
        self.pump()
        assert self.process.returncode == 0, self.text
        assert termios.tcgetattr(self.slave) == self.original, "terminal settings not restored"
        if self.interactive:
            assert b"\x1b[?25h" in self.output, "cursor not restored"
            assert b"\x1b[?1049l" in self.output, "alternate screen not restored"
        else:
            assert b"\x1b[?1049" not in self.output, "plain mode changed screen"
            assert "ANETTRACE / TRAFFIC LAB" not in self.text

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.pump()
        print(self.text, end="")
        os.close(self.master)
        os.close(self.slave)


def socket_counters_and_controls(binary):
    assert ctypes.CDLL(None).prctl(15, b"traffic-main", 0, 0, 0) == 0
    terminal = Terminal(binary)
    try:
        terminal.until(lambda: "THREAD VIEW" in terminal.frame)
        payload = b"x" * 16384
        errors = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(("127.0.0.1", 0))
            server.settimeout(3)
            client.settimeout(3)

            def replies():
                try:
                    for _ in range(64):
                        request, peer = server.recvfrom(1)
                        assert request == b"?"
                        server.sendto(payload, peer)
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=replies)
            worker.start()
            for _ in range(64):
                client.sendto(b"?", server.getsockname())
                assert client.recv(32768) == payload
            worker.join(timeout=5)
            assert not worker.is_alive() and not errors, errors
            # --pid selects the main TID: the reply thread is deliberately excluded.
            terminal.until(lambda: re.search(r"累计接收\s+1\.00 MiB", terminal.frame))
            terminal.until(lambda: f"TID {os.getpid()} traffic-main" in terminal.frame
                           and f"127.0.0.1:{server.getsockname()[1]}" in terminal.frame)
            terminal.until(lambda: re.search(r"RX\s+0 B/s", terminal.frame)
                           and re.search(r"累计接收\s+1\.00 MiB", terminal.frame))
            terminal.key("f")
            remote = f"127.0.0.1:{server.getsockname()[1]}"
            terminal.until(lambda: "THREAD VIEW" in terminal.frame and remote in terminal.frame)
            terminal.key("p")
            terminal.until(lambda: "PROCESS VIEW" in terminal.frame
                           and re.search(r"累计发送\s+64 B", terminal.frame))
        terminal.key("q")
        terminal.finish()
        summary = terminal.text.rsplit("Traffic session complete", 1)[-1]
        assert re.search(r"RX session\s+1\.00 MiB", summary), summary
        assert re.search(r"TX session\s+64 B", summary), summary
    finally:
        terminal.close()
    print("traffic terminal: real counters, idle rates, process/flow controls and q PASS")


def worker_thread_identity(binary):
    ready, run = threading.Event(), threading.Event()
    observed, errors = {}, []
    payload = b"x" * 4096
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(5)

        def request():
            try:
                assert ctypes.CDLL(None).prctl(15, b"net-rx-worker", 0, 0, 0) == 0
                observed["tid"] = threading.get_native_id()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(5)
                    ready.set()
                    assert run.wait(10)
                    client.sendto(b"worker", server.getsockname())
                    assert client.recv(8192) == payload
            except Exception as error:
                errors.append(error)
                ready.set()

        worker = threading.Thread(target=request, daemon=True)
        worker.start()
        assert ready.wait(5) and not errors, errors
        terminal = Terminal(binary, tid=observed["tid"])
        try:
            terminal.until(lambda: "THREAD VIEW" in terminal.frame)
            run.set()
            data, peer = server.recvfrom(64)
            assert data == b"worker"
            server.sendto(payload, peer)
            worker.join(timeout=5)
            assert not worker.is_alive() and not errors, errors
            # Unconnected UDP getsockname may still report the wildcard address.
            local = f"{peer[0]}:{peer[1]}"
            remote = f"127.0.0.1:{server.getsockname()[1]}"
            terminal.until(lambda: f"TID {observed['tid']} net-rx-worker" in terminal.frame
                           and f"PID {os.getpid()}" in terminal.frame
                           and local in terminal.frame and remote in terminal.frame)
            assert observed["tid"] != os.getpid()
            assert re.search(r"累计接收\s+4\.00 KiB", terminal.frame), terminal.frame
            assert re.search(r"累计发送\s+6 B", terminal.frame), terminal.frame
            sampled_time = re.search(r"时间 (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", terminal.frame)
            last_io = re.search(r"最近 (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", terminal.frame)
            assert sampled_time and last_io, terminal.frame
            terminal.pump(12)
            # The worker has exited: its identity and totals must survive the old 10s cutoff.
            assert f"TID {observed['tid']} net-rx-worker" in terminal.frame, terminal.frame
            assert local in terminal.frame and remote in terminal.frame, terminal.frame
            assert "空闲" in terminal.frame and "累计接收 4.00 KiB" in terminal.frame, terminal.frame
            assert last_io.group(0) in terminal.frame, terminal.frame
            assert sampled_time.group(0) not in terminal.frame, terminal.frame
            terminal.key("h")
            terminal.until(lambda: "历史: 最近 60 次采样" in terminal.frame)
            assert f"TID {observed['tid']} net-rx-worker" in terminal.frame, terminal.frame
            assert "h 返回" in terminal.frame and "q 退出" in terminal.frame, terminal.frame
            # Scroll to the first few samples, before the long idle period.
            for _ in range(12):
                terminal.key("k")
                terminal.pump(0.06)
            terminal.until(lambda: "RX 4.00 KiB" in terminal.frame and "TX 6 B" in terminal.frame)
            assert "1.00 MiB" not in terminal.frame, terminal.frame
            terminal.key("h")
            terminal.until(lambda: "h 历史" in terminal.frame)
            terminal.key("q")
            terminal.finish()
        finally:
            run.set()
            worker.join(timeout=6)
            terminal.close()
    print("traffic terminal: exited worker retained past 10s, timed history and both endpoints PASS")



def legacy_and_dumb_terminals(binary):
    for ui, term in ((False, "xterm-256color"), (True, "dumb")):
        terminal = Terminal(binary, "--count", "2", ui=ui, term=term)
        try:
            terminal.until(lambda: "APP_RX_KB" in terminal.text)
            assert termios.tcgetattr(terminal.slave) == terminal.original
            terminal.finish()
            assert terminal.text.count("cumulative application payload per flow") == 2
            assert "APP_TX_KB" in terminal.text and "LADDR:PORT" in terminal.text
        finally:
            terminal.close()
    result = subprocess.run(
        [str(binary), "--traffic-ui", "--proto", "udp", "--pid", str(os.getpid()),
         "--count", "1"], capture_output=True, text=True, timeout=15,
        env={**os.environ, "TERM": "xterm-256color"},
    )
    assert result.returncode == 0, result.stderr
    assert "APP_RX_KB" in result.stdout and "ANETTRACE / TRAFFIC LAB" not in result.stdout
    assert "\x1b[?1049" not in result.stdout
    print("traffic terminal: legacy default, dumb terminal and redirected UI fallback PASS")


def report_limit_and_signal(binary):
    terminal = Terminal(binary, "--interval", "2", "--count", "2")
    try:
        terminal.until(lambda: "THREAD VIEW" in terminal.frame)
        for key in "fpfpjk":
            terminal.key(key)
            terminal.pump(0.12)
        assert terminal.process.poll() is None, "view switches consumed report count"
        terminal.finish()
        assert time.monotonic() - terminal.started >= 3.8, \
            "reports ran before the configured intervals"
    finally:
        terminal.close()
    terminal = Terminal(binary, "--interval", "30")
    try:
        terminal.until(lambda: "THREAD VIEW" in terminal.frame)
        terminal.process.send_signal(signal.SIGINT)
        terminal.finish()
    finally:
        terminal.close()
    print("traffic terminal: interval/count semantics and SIGINT cleanup PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    legacy_and_dumb_terminals(binary)
    socket_counters_and_controls(binary)
    worker_thread_identity(binary)
    report_limit_and_signal(binary)
