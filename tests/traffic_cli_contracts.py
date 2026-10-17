#!/usr/bin/env python3
"""Check the opt-in traffic UI CLI without loading BPF programs."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = str(parser.parse_args().binary.resolve())
    help_result = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=10)
    assert help_result.returncode == 0, help_result.stderr
    assert "--traffic-ui" in help_result.stdout
    assert "legacy scrolling table" in help_result.stdout
    assert "implies --traffic" in help_result.stdout
    cases = [
        (["--traffic-ui", "--proto", "icmp"], "--traffic supports only --proto tcp or --proto udp"),
        (["--traffic", "--traffic-ui", "--proto", "icmp"], "--traffic supports only --proto tcp or --proto udp"),
        (["--traffic-ui", "--interval", "0"], "--interval must be between 1 and 3600 seconds"),
        (["--traffic-ui", "--interval", "3601"], "--interval must be between 1 and 3600 seconds"),
        (["--traffic-ui", "--basic"], "--traffic cannot be combined with packet or socket trace modes"),
        (["--traffic-ui", "--perfetto-events", "/tmp/unused-events.jsonl"], "--traffic cannot be combined with --perfetto-events"),
        (["--traffic-ui", "--capture-trace", "--trace-profile", "invalid"], "--trace-profile must be full or sched"),
        (["--capture-trace", "--system-trace-only", "--traffic-ui"], "--system-trace-only cannot be combined with --traffic-ui"),
    ]
    for options, expected in cases:
        result = subprocess.run([binary, *options], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0, options
        assert expected in result.stdout + result.stderr, (options, result.stdout, result.stderr)
    print("traffic CLI: opt-in flag, legacy help, filters and mode conflicts PASS")


if __name__ == "__main__":
    main()
