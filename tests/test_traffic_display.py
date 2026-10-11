"""Exercise the real terminal renderer and its lifecycle through a pseudo-terminal."""
from pathlib import Path
import errno
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

HARNESS = r'''
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "traffic_display.h"
static volatile sig_atomic_t stopped;
static void stop(int number) { (void)number; stopped = 1; }
int main(int argc, char **argv) {
    struct traffic_display display = {0};
    struct traffic_display_row rows[12] = {0};
    struct traffic_display_snapshot snapshot = {
        .rows = rows, .row_count = 12,
        .rx_bytes = 5ULL * 1024 * 1024 * 1024,
        .tx_bytes = 64000, .rx_rate = 16 * 1024 * 1024, .tx_rate = 1280,
        .elapsed_seconds = 92, .interval_seconds = 1,
        .protocol = "TCP/UDP", .filter = "UID 0",
    };
    assert(argc == 2);
    if (!strcmp(argv[1], "math")) {
        uint64_t big = 5ULL * 1024 * 1024 * 1024;
        assert(traffic_bytes_per_second(3000, 1500000000) == 2000);
        assert(traffic_bytes_per_second(big, 1000000000) == (double)big);
        assert(traffic_bytes_per_second(big, 0) == 0);
        puts("counter math passed"); return 0;
    }
    for (unsigned i = 0; i < 12; i++) {
        rows[i].pid = 4291 + i; rows[i].tid = 4300 + i;
        rows[i].flow_count = 4;
        strcpy(rows[i].comm, i ? "download-worker" : "curl\033[2J\007\n");
        strcpy(rows[i].protocol, "TCP");
        strcpy(rows[i].local, "[2001:db8:1111:2222:3333:4444:5555:6666]:54321");
        strcpy(rows[i].remote, "[2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff]:65535");
        rows[i].rx_bytes = snapshot.rx_bytes;
        rows[i].tx_bytes = snapshot.tx_bytes;
        rows[i].rx_rate = snapshot.rx_rate;
        rows[i].tx_rate = snapshot.tx_rate;
        rows[i].idle_seconds = i ? 4 : 0;
    }
    if (!strcmp(argv[1], "threads")) {
        snapshot.flows = true;
        snapshot.row_count = 2;
        rows[0] = rows[1];
        rows[0].pid = rows[1].pid = 1234;
        rows[0].tid = 5678; rows[1].tid = 5679;
    }
    if (!strcmp(argv[1], "empty")) {
        snapshot.row_count = 0;
        snapshot.rx_rate = snapshot.tx_rate = 0;
        snapshot.warning = "Partial totals: 8 inflight drops; 12 process-map drops; "
            "some retained connection records are unavailable; global counters "
            "remain independent of the connection record cache.";
    }
    if (!traffic_display_open(&display)) {
        puts("legacy output");
        traffic_display_close(&display, &snapshot);
        return 0;
    }
    signal(SIGINT, stop); signal(SIGTERM, stop);
    traffic_display_render(&display, &snapshot);
    fprintf(stderr, "READY\n"); fflush(stderr);
    if (strcmp(argv[1], "once")) {
        for (unsigned i = 0; i < 3000 && !stopped; i++) {
            int key = traffic_display_read_key(&display);
            if (key) {
                fprintf(stderr, "KEY %c\n", key); fflush(stderr);
                if (key == 'q') break;
                if (key == 'f' || key == 'p') {
                    snapshot.flows = key == 'f';
                    display.first_row = 0;
                } else if (key == 'j') {
                    display.first_row++;
                } else if (key == 'k' && display.first_row) {
                    display.first_row--;
                }
                traffic_display_render(&display, &snapshot);
            }
            struct timespec delay = {.tv_nsec = 10000000};
            nanosleep(&delay, NULL);
        }
    }
    traffic_display_close(&display, &snapshot);
    traffic_display_close(&display, &snapshot);
    return 0;
}
'''


class TrafficDisplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="anettrace-traffic-display-")
        cls.addClassCleanup(cls.tmp.cleanup)
        base = Path(cls.tmp.name)
        harness = base / "display.c"
        harness.write_text(HARNESS)
        cls.binary = base / "display"
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=c11", "-D_POSIX_C_SOURCE=200809L",
            "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src"),
            str(harness), str(ROOT / "src/traffic_display.c"),
            "-o", str(cls.binary),
        ], check=True, capture_output=True, text=True)

    def test_large_counters_and_actual_sample_duration(self):
        result = subprocess.run([self.binary, "math"], check=True, capture_output=True)
        self.assertIn(b"counter math passed", result.stdout)

    def test_redirected_output_stays_plain(self):
        result = subprocess.run([self.binary, "once"], check=True,
                                capture_output=True, env={**os.environ, "TERM": "xterm"})
        self.assertEqual(result.stdout, b"legacy output\n")

    def start_terminal(self, columns=44, rows=45, term="xterm-256color", input_tty=True,
                       mode="interactive"):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        original = termios.tcgetattr(slave)
        process = subprocess.Popen([self.binary, mode],
                                   stdin=slave if input_tty else subprocess.PIPE,
                                   stdout=slave, stderr=subprocess.PIPE, bufsize=0,
                                   env={**os.environ, "TERM": term})
        self.master = master
        self.pending_output = bytearray()
        self.addCleanup(self.stop_process, process, master)
        return process, master, slave, original

    def stop_process(self, process, master):
        if process.poll() is None:
            process.terminate()
            deadline = time.monotonic() + 3
            while process.poll() is None and time.monotonic() < deadline:
                self.drain(master)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        if process.stdin:
            process.stdin.close()
        process.stderr.close()

    def message(self, process, expected):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            ready = select.select([process.stderr, self.master], [], [], .1)[0]
            if self.master in ready:
                self.pending_output.extend(os.read(self.master, 65536))
            if process.stderr in ready:
                self.assertEqual(process.stderr.readline(), expected)
                return
        self.fail("renderer stalled")

    def drain(self, master):
        result = self.pending_output
        self.pending_output = bytearray()
        while select.select([master], [], [], .05)[0]:
            try:
                result.extend(os.read(master, 65536))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
        return bytes(result)

    def assert_restored(self, slave, original):
        restored = termios.tcgetattr(slave)
        # BSD marks pending canonical input after restoring ICANON itself.
        # PENDIN is kernel bookkeeping; compare every user-controlled setting.
        pending = getattr(termios, "PENDIN", 0)
        restored[3] &= ~pending
        expected = original.copy()
        expected[3] &= ~pending
        self.assertEqual(restored, expected)

    def assert_frame_fits(self, output, columns, rows):
        visible = ANSI.sub(b"", output).replace(b"\r", b"")
        lines = visible.split(b"\n")
        self.assertLessEqual(len(lines) - 1, rows - 1)
        self.assertTrue(all(len(line) <= columns - 1 for line in lines), visible)
        self.assertNotIn(b"\x1b", visible)
        return visible

    def test_phone_layout_switching_resize_and_quit_restore_terminal(self):
        process, master, slave, original = self.start_terminal()
        self.message(process, b"READY\n")
        active = termios.tcgetattr(slave)
        self.assertFalse(active[3] & (termios.ECHO | termios.ICANON))
        self.assertEqual(active[3] & termios.ISIG, original[3] & termios.ISIG)
        self.assertEqual(active[6][termios.VMIN], 0)
        self.assertEqual(active[6][termios.VTIME], 0)
        output = self.drain(master)
        visible = self.assert_frame_fits(output, 44, 45)
        self.assertIn(b"16.0 MiB/s", visible)
        self.assertIn(b"5.00 GiB", visible)
        self.assertIn(b"recent flows", visible)
        self.assertIn(b"more", visible)
        self.assertNotIn(b"\a", visible)
        os.write(master, b"f")
        self.message(process, b"KEY f\n")
        visible = self.assert_frame_fits(self.drain(master), 44, 45)
        self.assertIn(b"THREAD VIEW", visible)
        self.assertIn(b"Local  [2001:db8", visible)
        self.assertIn(b"Remote [2001:db8", visible)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 16, 100, 0, 0))
        os.write(master, b"p")
        self.message(process, b"KEY p\n")
        visible = self.assert_frame_fits(self.drain(master), 100, 16)
        self.assertIn(b"PROCESS VIEW", visible)
        self.assertIn(b"RX/s", visible)
        os.write(master, b"q")
        self.message(process, b"KEY q\n")
        process.wait(timeout=3)
        self.assert_restored(slave, original)
        output = self.drain(master)
        self.assertEqual(output.count(b"\x1b[?1049l"), 1)
        self.assertEqual(output.count(b"Traffic session complete"), 1)
        self.assertIn(b"5.00 GiB", output)

    def test_signal_cleanup_and_tiny_terminal(self):
        process, master, slave, original = self.start_terminal(columns=20, rows=5)
        self.message(process, b"READY\n")
        self.assert_frame_fits(self.drain(master), 20, 5)
        process.send_signal(signal.SIGINT)
        process.wait(timeout=3)
        self.assert_restored(slave, original)
        self.assertIn(b"\x1b[?25h", self.drain(master))

    def test_thread_names_and_complete_ipv6_endpoints_at_phone_and_desktop_widths(self):
        for columns in (32, 44, 100, 110):
            with self.subTest(columns=columns):
                process, master, slave, original = self.start_terminal(
                    columns=columns, mode="threads")
                self.message(process, b"READY\n")
                visible = self.assert_frame_fits(self.drain(master), columns, 45)
                self.assertIn(b"THREAD VIEW", visible)
                self.assertIn(b"download-worker", visible)
                self.assertIn(b"5678", visible)
                self.assertIn(b"5679", visible)
                self.assertIn(b"1234", visible)
                # Continuation lines must preserve every address byte and port.
                joined = b"".join(visible.split())
                self.assertIn(b"[2001:db8:1111:2222:3333:4444:5555:6666]:54321", joined)
                self.assertIn(b"[2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff]:65535", joined)
                self.assertIn(b"Local", visible)
                self.assertIn(b"Remote", visible)
                os.write(master, b"q")
                self.message(process, b"KEY q\n")
                process.wait(timeout=3)
                self.assert_restored(slave, original)

    def test_scroll_reaches_hidden_threads_and_view_switch_resets_position(self):
        process, master, slave, original = self.start_terminal()
        self.message(process, b"READY\n")
        self.drain(master)
        os.write(master, b"f")
        self.message(process, b"KEY f\n")
        self.drain(master)
        for _ in range(11):
            os.write(master, b"j")
            self.message(process, b"KEY j\n")
            visible = self.assert_frame_fits(self.drain(master), 44, 45)
        self.assertIn(b"TID 4311 download-worker", visible)
        self.assertIn(b"Rows 12-12/12", visible)
        os.write(master, b"k")
        self.message(process, b"KEY k\n")
        self.assertIn(b"TID 4310 download-worker", self.drain(master))
        os.write(master, b"p")
        self.message(process, b"KEY p\n")
        visible = self.drain(master)
        self.assertIn(b"PROCESS VIEW", visible)
        self.assertIn(b"Rows 1-", visible)
        os.write(master, b"q")
        self.message(process, b"KEY q\n")
        process.wait(timeout=3)
        self.assert_restored(slave, original)

    def test_empty_interval_and_long_warning_keep_session_totals_visible(self):
        process, master, slave, original = self.start_terminal(mode="empty", rows=20)
        self.message(process, b"READY\n")
        visible = self.assert_frame_fits(self.drain(master), 44, 20)
        self.assertIn(b"RX now      0 B/s", visible)
        self.assertIn(b"RX session  5.00 GiB", visible)
        self.assertIn(b"Waiting for socket traffic", visible)
        self.assertIn(b"Partial totals", visible)
        self.assertIn(b"...", visible)
        os.write(master, b"q")
        self.message(process, b"KEY q\n")
        process.wait(timeout=3)
        self.assert_restored(slave, original)

    def test_dumb_terminal_leaves_modes_and_output_alone(self):
        process, master, slave, original = self.start_terminal(term="dumb")
        process.wait(timeout=3)
        self.assertEqual(termios.tcgetattr(slave), original)
        self.assertEqual(self.drain(master).replace(b"\r", b""), b"legacy output\n")

    def test_redirected_input_is_not_read_or_advertised(self):
        process, master, slave, original = self.start_terminal(input_tty=False)
        self.message(process, b"READY\n")
        self.assertEqual(termios.tcgetattr(slave), original)
        visible = self.assert_frame_fits(self.drain(master), 44, 45)
        self.assertIn(b"Ctrl-C", visible)
        self.assertNotIn(b"p process", visible)
        process.stdin.write(b"q")
        process.stdin.flush()
        self.assertFalse(select.select([process.stderr], [], [], .1)[0])
        self.assertIsNone(process.poll())
        process.terminate()
        process.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
