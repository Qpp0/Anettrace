"""Event-loss callbacks must not shorten a timed Perfetto capture."""
import unittest

from tests import test_flow_identity as helpers


class TraceDurationTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def run_capture(self, mode, ring=False):
        source = (helpers.ROOT / "src/trace.c").read_text()
        code = r'''
#include <time.h>
#include <unistd.h>
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
static struct {
    bool stop;
    struct {
        bool capture_trace, ring_buffer, traffic;
        char *perfetto_events;
        u32 duration, count;
    } args;
} trace_ctx;
static u64 lost_events, now_ns, poll_deadline_ns;
static void perfetto_export_lost(int cpu, u64 count) {
    (void)cpu;
    lost_events += count;
}
static void trace_stop(void) { trace_ctx.stop = true; }
static int capture_clock_gettime(clockid_t clock, struct timespec *now) {
    (void)clock;
    now->tv_sec = now_ns / 1000000000ULL;
    now->tv_nsec = now_ns % 1000000000ULL;
    return 0;
}
#define clock_gettime capture_clock_gettime
static int traffic_poll(void) { return 0; }
static struct { u64 event_count; } bpf_args;
#define get_bpf_args() (&bpf_args)
''' + helpers.function(source, "trace_on_lost")
        code += helpers.function(source, "poll_timeout")
        return self.run_source(code, f'''
trace_ctx.args.capture_trace = {int(mode == 'capture')};
trace_ctx.args.perfetto_events = {'"events.jsonl"' if mode == 'events' else 'NULL'};
trace_ctx.args.ring_buffer = {int(ring)};
trace_ctx.args.duration = 30;
poll_deadline_ns = 130ULL * 1000000000ULL;
now_ns = 110ULL * 1000000000ULL;
trace_on_lost(NULL, 2, 7);
trace_on_lost(NULL, 3, 5);
printf("%d %llu %d ", trace_ctx.stop, lost_events, poll_timeout(0));
now_ns = 129999999999ULL;
printf("%d ", poll_timeout(0));
now_ns = poll_deadline_ns;
printf("%d ", poll_timeout(0));
trace_ctx.stop = true;
printf("%d", poll_timeout(0));
''')

    def test_capture_and_jsonl_keep_running_until_thirty_seconds_after_loss(self):
        for mode in ("capture", "events"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_capture(mode), ["0", "12", "0", "0", "1", "1"])

    def test_ring_capture_keeps_running_past_window_until_interrupted(self):
        self.assertEqual(self.run_capture("capture", ring=True), ["0", "12", "0", "0", "0", "1"])

    def test_terminal_trace_preserves_stop_on_loss(self):
        self.assertEqual(self.run_capture("terminal"), ["1", "12", "1", "1", "1", "1"])


if __name__ == "__main__":
    unittest.main()
