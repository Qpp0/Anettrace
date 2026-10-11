"""Exercise traffic snapshot accounting from the production C helpers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.test_flow_identity import function

ROOT = Path(__file__).resolve().parents[1]


class TrafficSamplesTest(unittest.TestCase):
    def run_source(self, names, body, extra=""):
        source = (ROOT / "src/traffic.c").read_text()
        prelude = r'''
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#include "src/progs/traffic_shared.h"
#include "src/traffic_display.h"
struct traffic_row { traffic_flow_key_t key; traffic_flow_value_t value; };
struct traffic_process_row { traffic_process_key_t key; traffic_process_value_t value; };
'''
        code = prelude + extra + "".join(function(source, name) for name in names)
        code += "\nint main(void) {\n" + body + "\n}\n"
        with tempfile.TemporaryDirectory(prefix="anettrace-traffic-samples-") as tmp:
            cfile, binary = Path(tmp) / "samples.c", Path(tmp) / "samples"
            cfile.write_text(code)
            built = subprocess.run([
                "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-Wno-unused-function", "-I", str(ROOT), str(cfile),
                "-o", str(binary),
            ], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_counter_deltas_do_not_recount_missing_or_rebuilt_samples(self):
        self.run_source(("traffic_sample_deltas",), r'''
traffic_flow_value_t old={.rx_bytes=1000,.tx_bytes=100,.first_seen_ns=1};
traffic_flow_value_t now={.rx_bytes=1600,.tx_bytes=200,.first_seen_ns=1};
u64 rx=0,tx=0; bool incomplete=false;
traffic_sample_deltas(&now,&old,100,&rx,&tx,&incomplete);
assert(rx==600 && tx==100 && !incomplete);
/* A missed snapshot is not evidence that all old traffic just arrived. */
traffic_sample_deltas(&now,NULL,100,&rx,&tx,&incomplete);
assert(rx==0 && tx==0 && incomplete);
/* A new generation can count its bytes only when born in this interval. */
incomplete=false; now.first_seen_ns=101; now.rx_bytes=40; now.tx_bytes=20;
traffic_sample_deltas(&now,&old,100,&rx,&tx,&incomplete);
assert(rx==40 && tx==20 && !incomplete);
now.first_seen_ns=90;
traffic_sample_deltas(&now,&old,100,&rx,&tx,&incomplete);
assert(rx==0 && tx==0 && incomplete);
/* A counter decrease in one generation is incomplete, never unsigned wrap. */
incomplete=false; now.first_seen_ns=old.first_seen_ns;
traffic_sample_deltas(&now,&old,100,&rx,&tx,&incomplete);
assert(rx==0 && tx==0 && incomplete);
''')

    def test_flow_snapshots_deduplicate_concurrent_iteration_and_keep_generations(self):
        self.run_source(("traffic_flow_key_compare", "traffic_unique_flows"), r'''
struct traffic_row rows[4]={0};
rows[0].key.tgid=42; rows[0].key.process_start_ns=100;
rows[0].value=(traffic_flow_value_t){.rx_bytes=100,.first_seen_ns=1,.last_seen_ns=3};
rows[1]=rows[0]; rows[1].value.rx_bytes=150; rows[1].value.last_seen_ns=4;
rows[2]=rows[0]; rows[2].key.process_start_ns=200;
rows[3]=rows[0]; rows[3].value=(traffic_flow_value_t){.rx_bytes=5,.first_seen_ns=5,.last_seen_ns=5};
int count=traffic_unique_flows(rows,4);
assert(count==2);
struct traffic_row key={.key={.tgid=42,.process_start_ns=100}};
struct traffic_row *found=bsearch(&key,rows,count,sizeof(*rows),traffic_flow_key_compare);
assert(found && found->value.first_seen_ns==5 && found->value.rx_bytes==5);
''')

    def test_process_baselines_distinguish_pid_reuse(self):
        self.run_source(("traffic_process_key_compare", "traffic_unique_processes"), r'''
struct traffic_process_row rows[3]={0};
rows[0].key=(traffic_process_key_t){.tgid=42,.start_time_ns=100};
rows[0].value.counters=(traffic_flow_value_t){.rx_bytes=100,.last_seen_ns=5};
rows[1]=rows[0]; rows[1].value.counters.rx_bytes=150; rows[1].value.counters.last_seen_ns=6;
rows[2]=rows[0]; rows[2].key.start_time_ns=200;
int count=traffic_unique_processes(rows,3);
assert(count==2);
struct traffic_process_row key={.key={.tgid=42,.start_time_ns=100}};
struct traffic_process_row *found=bsearch(&key,rows,count,sizeof(*rows),traffic_process_key_compare);
assert(found && found->value.counters.rx_bytes==150);
key.key.start_time_ns=300;
assert(!bsearch(&key,rows,count,sizeof(*rows),traffic_process_key_compare));
''')

    def test_recent_rows_sort_by_current_rate_then_last_activity(self):
        self.run_source(("traffic_display_row_compare",), r'''
struct traffic_display_row rows[3]={
    {.pid=1,.rx_bytes=999999,.rx_rate=0,.idle_seconds=2},
    {.pid=2,.rx_bytes=5,.rx_rate=5,.idle_seconds=0},
    {.pid=3,.rx_bytes=50,.rx_rate=0,.idle_seconds=1},
};
qsort(rows,3,sizeof(*rows),traffic_display_row_compare);
assert(rows[0].pid==2 && rows[1].pid==3 && rows[2].pid==1);
''')

    def test_map_walk_reports_errors_and_bounds_concurrent_restarts(self):
        self.run_source(("traffic_flow_key_compare", "traffic_unique_flows",
                         "traffic_collect_flow_sample"), r'''
struct traffic_row *rows=calloc(TRAFFIC_MAX_FLOWS,sizeof(*rows));
assert(rows); bool incomplete=false;
/* A failed first key lookup is different from an empty map. */
mode=1;
assert(traffic_collect_flow_sample(0,rows,&incomplete)==0 && incomplete);
/* A deleting/reinserting producer cannot keep this snapshot looping forever. */
mode=2; calls=0; incomplete=false;
assert(traffic_collect_flow_sample(0,rows,&incomplete)==0 && incomplete);
assert(calls<=TRAFFIC_MAX_FLOWS*2+1);
/* Repeated keys are coalesced, not counted as multiple flow rows. */
mode=3; calls=0; incomplete=false;
assert(traffic_collect_flow_sample(0,rows,&incomplete)==1 && incomplete);
assert(calls<=TRAFFIC_MAX_FLOWS+1);
free(rows);
''', extra=r'''
static int mode,calls;
static int bpf_map_get_next_key(int fd,const void *key,void *next) {
    (void)fd; (void)key; calls++;
    if (mode==1) { errno=EIO; return -1; }
    memset(next,0,sizeof(traffic_flow_key_t));
    ((traffic_flow_key_t *)next)->tgid=42;
    return 0;
}
static int bpf_map_lookup_elem(int fd,const void *key,void *value) {
    (void)fd; (void)key;
    if (mode==2) { errno=ENOENT; return -1; }
    *(traffic_flow_value_t *)value=(traffic_flow_value_t){.rx_bytes=123,.last_seen_ns=1};
    return 0;
}
''')

    def test_global_read_failure_keeps_its_own_elapsed_baseline(self):
        source = (ROOT / "src/traffic.c").read_text()
        start = source.index("struct traffic_session {")
        session = source[start:source.index("\n};", start) + 4]
        display_source = (ROOT / "src/traffic_display.c").read_text()
        extra = r'''
typedef struct { int unused; } trace_args_t;
struct traffic { struct { int traffic_flows,traffic_processes,traffic_totals,traffic_stats; } maps; };
#define TRAFFIC_MAX_LINKS 15
#define TIME_MODE_DATE 1
static int ts_print_ts(char *text, u64 now, int mode) {
    (void)now; (void)mode; return sprintf(text, "[2026-10-12 00:05:07.000000] ");
}
static u64 total_rx;
static bool fail_totals;
static int bpf_map__fd(int map) { return map; }
static int bpf_map_get_next_key(int map,const void *key,void *next) {
    (void)map; (void)key; (void)next; errno=ENOENT; return -1;
}
static int bpf_map_lookup_elem(int map,const void *key,void *value) {
    (void)key;
    if (map==3) {
        if (fail_totals) { errno=EIO; return -1; }
        *(traffic_flow_value_t *)value=(traffic_flow_value_t){.rx_bytes=total_rx};
    } else *(u64 *)value=0;
    return 0;
}
void traffic_display_render(struct traffic_display *display,
                           const struct traffic_display_snapshot *snapshot) {
    (void)display; (void)snapshot;
}
''' + session + function(display_source, "traffic_bytes_per_second")
        self.run_source(("traffic_flow_key_compare", "traffic_process_key_compare",
                         "traffic_unique_flows", "traffic_unique_processes",
                         "traffic_sample_deltas", "traffic_display_row_compare",
                         "traffic_collect_flow_sample", "traffic_collect_process_sample",
                         "traffic_protocol_name", "traffic_format_endpoint",
                         "traffic_render_cached", "traffic_format_timestamp", "traffic_display_counters",
                         "traffic_sample_warning", "traffic_sample_display"), r'''
struct traffic skel={.maps={1,2,3,4}};
struct traffic_session session={.skel=&skel,.start_ns=100,.last_report_ns=100,
    .totals_sample_ns=100};
session.rows=calloc(TRAFFIC_MAX_FLOWS,sizeof(*session.rows));
session.previous_rows=calloc(TRAFFIC_MAX_FLOWS,sizeof(*session.rows));
session.process_rows=calloc(TRAFFIC_MAX_PROCESSES,sizeof(*session.process_rows));
session.previous_process_rows=calloc(TRAFFIC_MAX_PROCESSES,sizeof(*session.process_rows));
session.flow_display_rows=calloc(TRAFFIC_MAX_FLOWS,sizeof(*session.flow_display_rows));
session.process_display_rows=calloc(TRAFFIC_MAX_PROCESSES,sizeof(*session.process_display_rows));
session.process_flow_counts=calloc(TRAFFIC_MAX_PROCESSES,sizeof(*session.process_flow_counts));
total_rx=2048;
traffic_sample_display(&session,1000000100ULL);
assert(session.snapshot.rx_bytes==2048 && session.snapshot.rx_rate==2048.0);
session.last_report_ns=1000000100ULL;
fail_totals=true; total_rx=4096;
traffic_sample_display(&session,2000000100ULL);
assert(session.snapshot.rx_bytes==2048 && session.snapshot.rx_rate==0);
assert(strstr(session.warning,"map read incomplete"));
session.last_report_ns=2000000100ULL;
fail_totals=false; total_rx=6144;
traffic_sample_display(&session,3000000100ULL);
/* The recovered delta covers two seconds, not just the last display refresh. */
assert(session.snapshot.rx_bytes==6144 && session.snapshot.rx_rate==2048.0);
assert(!session.warning[0]);
free(session.rows); free(session.previous_rows);
free(session.process_rows); free(session.previous_process_rows);
free(session.flow_display_rows); free(session.process_display_rows);
free(session.process_flow_counts);
''', extra=extra)


if __name__ == "__main__":
    unittest.main()
