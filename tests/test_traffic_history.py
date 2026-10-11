"""Exercise retained traffic identities, totals and bounded timed samples."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TrafficHistoryTests(unittest.TestCase):
    def run_case(self, body):
        source = '''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "traffic_history.h"
int main(void) {
    struct traffic_history history = {0};
    struct traffic_display_row row = {.pid=1234,.tid=5678,.rx_bytes=100,.rx_delta=100,
        .sample_valid=true,.rx_rate=100,.first_seen_ns=1,.last_seen_ns=1000000000};
    unsigned long long key=11;
    strcpy(row.comm,"worker"); strcpy(row.local,"127.0.0.1:12345");
    strcpy(row.remote,"127.0.0.1:54321"); strcpy(row.last_seen,"2026-10-12 00:00:01");
''' + body + '\ntraffic_history_close(&history); return 0; }\n'
        with tempfile.TemporaryDirectory(prefix="anettrace-history-") as tmp:
            cfile, binary = Path(tmp)/"test.c", Path(tmp)/"test"
            cfile.write_text(source)
            build = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    "-I", str(ROOT/"src"), str(cfile),
                                    str(ROOT/"src/traffic_history.c"), "-o", str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([binary], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_idle_and_missing_kernel_record_keep_identity_and_totals(self):
        self.run_case('''
assert(traffic_history_open(&history,4,sizeof(key)));
traffic_history_begin(&history,"2026-10-12 00:00:01",1000000000,1000000000);
struct traffic_history_record *record=traffic_history_update(&history,&key,&row);
assert(record && record->row.rx_bytes==100);
traffic_history_begin(&history,"2026-10-12 00:05:09",309000000000ULL,308000000000ULL);
assert(history.count==1 && record->row.archived);
assert(record->row.rx_bytes==100 && record->row.rx_rate==0);
assert(record->row.idle_seconds==308);
assert(!record->samples[1].available);
assert(!strcmp(record->row.comm,"worker") && !strcmp(record->row.remote,"127.0.0.1:54321"));
row.rx_delta=0; row.rx_rate=0;
assert(traffic_history_update(&history,&key,&row)==record);
assert(!record->row.archived && record->samples[1].available && record->samples[1].rx_bytes==0);
''')

    def test_rebuilt_generation_adds_totals_without_recounting(self):
        self.run_case('''
assert(traffic_history_open(&history,4,sizeof(key)));
traffic_history_begin(&history,"2026-10-12 00:00:01",1000000000,1000000000);
struct traffic_history_record *record=traffic_history_update(&history,&key,&row);
traffic_history_begin(&history,"2026-10-12 00:00:02",2000000000,1000000000);
row.first_seen_ns=1500000000; row.last_seen_ns=2000000000; row.rx_bytes=row.rx_delta=40;
traffic_history_update(&history,&key,&row);
assert(record->row.rx_bytes==140 && history.count==1);
traffic_history_begin(&history,"2026-10-12 00:00:03",3000000000,1000000000);
row.rx_bytes=50; row.rx_delta=10;
traffic_history_update(&history,&key,&row);
assert(record->row.rx_bytes==150 && record->samples[2].rx_bytes==10);
row.rx_delta=0; traffic_history_update(&history,&key,&row);
assert(record->row.rx_bytes==150);
''')

    def test_capacity_and_reused_process_identity_do_not_replace_old_records(self):
        self.run_case('''
assert(traffic_history_open(&history,2,sizeof(key)));
traffic_history_begin(&history,"2026-10-12 00:00:01",1000000000,1000000000);
struct traffic_history_record *first=traffic_history_update(&history,&key,&row);
key=22; struct traffic_history_record *second=traffic_history_update(&history,&key,&row);
assert(first && second && first!=second && history.count==2);
key=33; assert(!traffic_history_update(&history,&key,&row));
assert(history.full && first->row.rx_bytes==100 && second->row.rx_bytes==100);
''')

    def test_ring_rollover_and_sample_gap_stay_distinct_from_zero(self):
        self.run_case('''
assert(traffic_history_open(&history,2,sizeof(key)));
struct traffic_history_record *record=NULL;
for (unsigned i=1;i<=65;i++) {
    traffic_history_begin(&history,"2026-10-12 00:00:01",(unsigned long long)i*1000000000,1000000000);
    row.rx_bytes=i*100; row.rx_delta=100;
    row.sample_valid=i!=65;
    record=traffic_history_update(&history,&key,&row);
}
assert(history.sequence==65 && history.frames[0].sequence==61);
assert(history.frames[4].sequence==65 && !record->samples[4].available);
assert(record->samples[3].available && record->samples[3].rx_bytes==100);
assert(record->row.rx_bytes==6500);
''')

    def test_many_identities_stay_distinct_and_record_addresses_stay_stable(self):
        self.run_case('''
assert(traffic_history_open(&history,1000,sizeof(key)));
traffic_history_begin(&history,"2026-10-12 00:00:01",1000000000,1000000000);
struct traffic_history_record *first=NULL;
for (unsigned i=0;i<1000;i++) {
    key=1000003ULL*i+11; row.pid=i+1;
    struct traffic_history_record *record=traffic_history_update(&history,&key,&row);
    assert(record && record->row.pid==i+1);
    if (!i) first=record;
}
assert(history.count==1000 && first->row.pid==1);
for (unsigned i=0;i<1000;i++) {
    key=1000003ULL*i+11; row.pid=i+1;
    struct traffic_history_record *record=traffic_history_update(&history,&key,&row);
    assert(record && record->row.pid==i+1 && record->row.rx_bytes==100);
    if (!i) assert(record==first);
}
assert(history.count==1000 && !history.full);
''')

    def test_old_generation_cannot_recount_a_rebuilt_record(self):
        self.run_case('''
assert(traffic_history_open(&history,2,sizeof(key)));
traffic_history_begin(&history,"2026-10-12 00:00:01",1000000000,1000000000);
struct traffic_history_record *record=traffic_history_update(&history,&key,&row);
traffic_history_begin(&history,"2026-10-12 00:00:02",2000000000,1000000000);
row.first_seen_ns=1500000000; row.rx_bytes=row.rx_delta=40;
traffic_history_update(&history,&key,&row);
traffic_history_begin(&history,"2026-10-12 00:00:03",3000000000,1000000000);
row.first_seen_ns=1; row.rx_bytes=100;
traffic_history_update(&history,&key,&row);
assert(record->row.rx_bytes==140 && !record->samples[2].available);
''')

    def test_counter_decrease_does_not_decrease_retained_total(self):
        self.run_case('''
assert(traffic_history_open(&history,2,sizeof(key)));
traffic_history_begin(&history,"2026-10-12 00:00:01",1000000000,1000000000);
struct traffic_history_record *record=traffic_history_update(&history,&key,&row);
traffic_history_begin(&history,"2026-10-12 00:00:02",2000000000,1000000000);
row.rx_bytes=20; row.rx_delta=0; row.sample_valid=false;
traffic_history_update(&history,&key,&row);
assert(record->row.rx_bytes==100 && !record->samples[1].available);
''')


if __name__ == "__main__":
    unittest.main()
