#!/usr/bin/env python3
"""Root/BTF integration: real socket counters in a 44-column terminal."""

import argparse
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
    def __init__(self, binary, *options):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 44, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        self.output = bytearray()
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            [str(binary), "--traffic", "--proto", "udp", "--pid", str(os.getpid()),
             *options],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env={**os.environ, "TERM": "xterm-256color"}, start_new_session=True,
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
        assert b"\x1b[?25h" in self.output, "cursor not restored"
        assert b"\x1b[?1049l" in self.output, "alternate screen not restored"

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
    terminal = Terminal(binary)
    try:
        terminal.until(lambda: "PROCESS VIEW" in terminal.frame)
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
            terminal.until(lambda: re.search(r"RX session\s+1\.00 MiB", terminal.frame))
            terminal.until(lambda: re.search(r"RX now\s+0 B/s", terminal.frame)
                           and re.search(r"RX session\s+1\.00 MiB", terminal.frame))
            terminal.key("f")
            remote = f"127.0.0.1:{server.getsockname()[1]}"
            terminal.until(lambda: "FLOW VIEW" in terminal.frame and remote in terminal.frame)
            terminal.key("p")
            terminal.until(lambda: "PROCESS VIEW" in terminal.frame
                           and re.search(r"TX session\s+64 B", terminal.frame))
        terminal.key("q")
        terminal.finish()
        summary = terminal.text.rsplit("Traffic session complete", 1)[-1]
        assert re.search(r"RX session\s+1\.00 MiB", summary), summary
        assert re.search(r"TX session\s+64 B", summary), summary
    finally:
        terminal.close()
    print("traffic terminal: real counters, idle rates, process/flow controls and q PASS")


def report_limit_and_signal(binary):
    terminal = Terminal(binary, "--interval", "2", "--count", "2")
    try:
        terminal.until(lambda: "PROCESS VIEW" in terminal.frame)
        for key in "fpfpfp":
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
        terminal.until(lambda: "PROCESS VIEW" in terminal.frame)
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
    socket_counters_and_controls(binary)
    report_limit_and_signal(binary)
