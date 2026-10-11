"""Decode real native exporter helpers; no BPF or Android build is required."""
from pathlib import Path
import json
import re
import struct
import subprocess
import tempfile
import unittest

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import TrackEvent

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r"^(?:static )?[^\n]*\b" + name + r"\([^;]*?\n\{", source, re.M)
    if not match:
        raise AssertionError("Missing source function: " + name)
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def declaration(source, name):
    start = source.index(name + " {")
    return source[start:source.index("\n};", start) + 3] + "\n"


class NativeGraphTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "src/perfetto_export.c").read_text()
        cls.tmp = tempfile.TemporaryDirectory(prefix="anettrace-native-graph-")
        base = Path(cls.tmp.name)
        prelude = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef long long s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint64_t __u64;
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define PERFETTO_SCHEMA "anettrace.perfetto.v1"
#define TRACE_CFREE 1
#define TRACE_HAS_ANALYZER(t, a) 0
#include "src/progs/shared.h"
typedef struct { const char *name; unsigned status; } trace_t;
static FILE *native_file, *export_file;
static u64 export_salt = 123;
static struct { struct { bool trace_detail, connect_diagnostics; } args; } trace_ctx;
'''
        structures = "".join(declaration(source, name) for name in (
            "enum native_track_kind", "struct native_track", "struct proto_buffer",
            "struct pending_io", "struct flow_state"))
        protos = source[source.index("static void proto_free("):
                        source.index("static void native_packet_queue_free(")]
        primitives = "".join(function(source, name) for name in (
            "hash_bytes", "object_id", "native_uuid", "socket_instance_id",
            "packet_id", "direction_name", "json_escape", "ipv6_is_v4_mapped",
            "packet_addresses", "socket_addresses", "native_event_start",
            "native_event_flow", "native_event_correlation"))
        annotations = source[source.index("static void native_annotation_string("):
                             source.index("static void native_event_write(")]
        stubs = r'''
static struct native_track thread_track = {.uuid=100};
static struct native_track socket_track = {.uuid=200};
static struct flow_state flow = {.id=500, .active=true, .protocol=IPPROTO_TCP,
    .display_index=1, .owner_tid=7, .owner_tgid=6};
static struct pending_io pending_ios[1];
static size_t pending_io_count;
static struct { network_syscall_event_t event; u64 flow_id; bool active; }
    pending_syscalls[1];
static size_t pending_syscall_count;
static trace_t receive = {.name="tcp_recvmsg"};
static struct native_track *native_thread_track(u32 p,u32 t,const char *s) { return &thread_track; }
static struct native_track *native_socket_track(u64 id,u32 p,const char *s) { return &socket_track; }
static struct flow_state *flow_find_any(u64 id) { return id == flow.id ? &flow : NULL; }
static struct flow_state *flow_find(u64 id) { return flow_find_any(id); }
static struct flow_state *flow_find_by_socket(u64 id,u8 p) { return id == flow.socket_id ? &flow : NULL; }
static u64 detail_flow_id(const detail_event_t *d,bool s) {
    return d->pkt.proto_l4 == IPPROTO_ICMP || d->pkt.proto_l4 == IPPROTO_ICMPV6 ? 0 : flow.id;
}
static const char *trace_event_name(const trace_t *t,const void *e) { return t->name; }
static trace_t *get_trace(u16 index) { return &receive; }
static void native_event_write(u64 ts, struct proto_buffer *e) {
    u32 size = (u32)e->size;
    fwrite(&size, sizeof(size), 1, native_file);
    fwrite(&ts, sizeof(ts), 1, native_file);
    fwrite(e->data, e->size, 1, native_file);
}
/* This harness isolates packet/link formatting; bounded overview buffering
 * and its real TracePacket output are exercised in test_socket_overview_native. */
static void native_packet_overview_observe(const detail_event_t *detail) {}
static void native_packet_overview_queue(const detail_event_t *detail, u64 flow_id,
    u64 thread_uuid, const char *name, struct proto_buffer *event,
    size_t annotation_offset, size_t annotation_size) {
    native_event_write(detail->pkt.ts, event);
}
'''
        helpers = "".join(function(source, name) for name in (
            "packet_is_icmp", "packet_is_icmp_echo",
            "flow_label_prefix", "format_flow_label", "format_known_flow_label",
            "format_packet_flow_label", "flow_protocol_name", "packet_submission_ids",
            "flow_packet_anchor", "packet_trace_terminal", "flow_link_socket", "pending_io_emit_start",
            "pending_io_finish", "export_packet_io_link", "native_export_packet_event",
            "export_packet_event", "export_rx_handoff"))
        body = r'''
int main(int argc, char **argv) {
    native_file=fopen(argv[1],"wb"); export_file=fopen(argv[2],"w");
    if (!native_file || !export_file) return 1;
    detail_event_t packet = {.key=99,.key_generation=1,.tid=7,.tgid=6,
        .owner_socket_key=90,.owner_socket_generation=1,
        .io_role=1,.io_tid=7,.io_tgid=6,.io_start_ts=100,.syscall_start_ts=90,
        .direction=PACKET_DIRECTION_TX};
    packet.pkt.proto_l3=ETH_P_IP; packet.pkt.proto_l4=IPPROTO_TCP;
    packet.pkt.ts=110; packet.pkt.l4.min.sport=htons(45000); packet.pkt.l4.min.dport=htons(443);
    flow.socket_id=socket_instance_id(90,1);
    flow_link_socket(&flow,95);
    flow_link_socket(&flow,96); /* Repeated association is not another edge. */
    struct pending_io io = {.active=true,.tx=true,.tid=7,.tgid=6,.protocol=IPPROTO_TCP,
        .start_ts=100,.syscall_start_ts=90,.socket_id=flow.socket_id,.flow_id=500,
        .io_id=native_uuid("io-call",((u64)6<<32)|7,100),.native_track_uuid=100};
    /* Early submission has no usable tuple. It must not poison the later
     * real packet association, while two real destinations remain ambiguous. */
    FILE *saved_native=native_file, *saved_json=export_file;
    native_file=NULL; export_file=NULL;
    pending_ios[0]=io; pending_ios[0].flow_id=0; pending_io_count=1;
    export_packet_io_link(&packet,NULL);
    export_packet_io_link(&packet,&flow);
    assert(pending_ios[0].flow_id==flow.id && !pending_ios[0].flow_ambiguous);
    struct flow_state second=flow; second.id=501;
    export_packet_io_link(&packet,&second);
    assert(!pending_ios[0].flow_id && pending_ios[0].flow_ambiguous);
    pending_io_count=0; native_file=saved_native; export_file=saved_json;
    trace_t send = {.name="tcp_sendmsg"}, stage = {.name="ip_output"};
    pending_io_emit_start(&io,&send,&flow);
    export_packet_io_link(&packet,&flow);
    native_export_packet_event(&packet,&stage,0); export_packet_event(&packet,&stage,0);
    pending_io_finish(&io,120,64,false);
    /* The original call has returned. BPF carries only observed submission
     * provenance for the same skb generation; no second call link is emitted. */
    packet.io_role=4; packet.tid=77; packet.tgid=77; packet.pkt.ts=150;
    stage.name="dev_hard_start_xmit";
    export_packet_io_link(&packet,&flow);
    native_export_packet_event(&packet,&stage,0); export_packet_event(&packet,&stage,0);
    /* A different skb in the same connection must not share packet arrows. */
    packet.key=100; packet.io_role=0; packet.io_start_ts=0; packet.syscall_start_ts=0;
    packet.io_multiple=1; packet.pkt.ts=160;
    native_export_packet_event(&packet,&stage,0); export_packet_event(&packet,&stage,0);
    rx_handoff_event_t ready={.kind=RX_HANDOFF_READY,.ts=170,.socket_key=90,
        .socket_generation=1,.tid=77,.tgid=77};
    export_rx_handoff(&ready,0);
    /* ICMP packets carry header metadata and skb identity without a transport flow. */
    for (int v6=0; v6<2; v6++) {
        detail_event_t icmp = {.key=200+v6*10,.key_generation=1,.tid=77,.tgid=77,
            .direction=PACKET_DIRECTION_TX};
        icmp.pkt.proto_l3=v6 ? ETH_P_IPV6 : ETH_P_IP;
        icmp.pkt.proto_l4=v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
        icmp.pkt.ts=200+v6*100;
        icmp.pkt.l4.icmp.type=v6 ? 128 : 8;
        icmp.pkt.l4.icmp.id=htons(1234); icmp.pkt.l4.icmp.seq=htons(7);
        stage.name=v6 ? "ip6_output" : "ip_output";
        native_export_packet_event(&icmp,&stage,0); export_packet_event(&icmp,&stage,0);
        icmp.pkt.ts++; stage.name="dev_hard_start_xmit";
        native_export_packet_event(&icmp,&stage,0); export_packet_event(&icmp,&stage,0);
        icmp.key++; icmp.pkt.ts++; icmp.direction=PACKET_DIRECTION_RX;
        icmp.pkt.l4.icmp.type=v6 ? 129 : 0;
        stage.name=v6 ? "icmpv6_rcv" : "icmp_rcv";
        native_export_packet_event(&icmp,&stage,0); export_packet_event(&icmp,&stage,0);
        /* Error headers reuse the bytes that echo uses for id/sequence. */
        icmp.key++; icmp.pkt.ts++; icmp.pkt.l4.icmp.type=v6 ? 1 : 3;
        icmp.pkt.l4.icmp.code=1;
        native_export_packet_event(&icmp,&stage,0); export_packet_event(&icmp,&stage,0);
    }
    fclose(native_file); fclose(export_file);
    return 0;
}
'''
        cfile, binary = base / "graph.c", base / "graph"
        cfile.write_text(prelude + structures + protos + primitives + annotations + stubs + helpers + body)
        result = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Werror",
                                 "-Wno-unused-function", "-Wno-unused-variable",
                                 "-I", str(ROOT), str(cfile), "-o", str(binary)],
                                text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        native, jsonl = base / "native.bin", base / "events.jsonl"
        subprocess.run([str(binary), str(native), str(jsonl)], check=True)
        cls.records = [json.loads(line) for line in jsonl.read_text().splitlines()]
        raw = native.read_bytes()
        cls.events = []
        while raw:
            length, timestamp = struct.unpack_from("=IQ", raw)
            event = TrackEvent()
            event.ParseFromString(raw[12:12 + length])
            cls.events.append((timestamp, event))
            raw = raw[12 + length:]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def args(event):
        return {a.name: a.string_value for a in event.debug_annotations}

    def events_in(self, category, protocol=None):
        return [(ts, event) for ts, event in self.events if category in event.categories
                and (protocol is None or self.args(event).get("proto_l4") == str(protocol))]

    def test_packet_chains_have_stage_names_and_never_join_different_skbs(self):
        packets = self.events_in("anettrace.packet", protocol=6)
        self.assertEqual(len(packets), 3)
        first, later, other = [event for _, event in packets]
        self.assertEqual(first.name, "tcp-1 · ip_output")
        self.assertEqual(later.name, "tcp-1 · dev_hard_start_xmit")
        self.assertEqual(list(first.flow_ids), list(later.flow_ids))
        self.assertNotEqual(list(first.flow_ids), list(other.flow_ids))
        for _, event in packets:
            args = self.args(event)
            self.assertEqual(event.correlation_id, 500)
            self.assertNotIn(500, event.flow_ids)
            self.assertEqual(args["flow_tag"], "tcp-1")
            self.assertIn("socket_id", args)

    def test_async_transmit_keeps_observed_call_without_reopening_io_flow(self):
        packets = [self.args(e) for _, e in self.events_in("anettrace.packet", protocol=6)]
        self.assertEqual(packets[0]["io_id"], packets[1]["io_id"])
        self.assertEqual(packets[0]["call_id"], packets[1]["call_id"])
        self.assertNotEqual(packets[1]["call_id"], "0000000000000000")
        self.assertEqual(packets[1]["io_evidence"], "stored_submission_context")
        self.assertEqual(len(self.events_in("anettrace.io.link")), 1)
        self.assertEqual(packets[2]["io_id"], "0000000000000000")
        self.assertEqual(packets[2]["submission_association"], "multiple_calls")

    def test_socket_io_and_completion_ids_are_explicit(self):
        self.assertEqual(len(self.events_in("anettrace.socket.flow")), 1)
        bridge = self.events_in("anettrace.socket.io")[0][1]
        complete = self.events_in("anettrace.io.complete")[0][1]
        args = self.args(complete)
        self.assertEqual(args["flow_tag"], "tcp-1")
        self.assertEqual(args["bytes"], "64")
        self.assertIn(int(args["io_id"], 16), bridge.flow_ids)
        self.assertEqual(list(complete.terminating_flow_ids), [int(args["io_id"], 16)])
        ends = [e for _, e in self.events if e.type == TrackEvent.TYPE_SLICE_END]
        self.assertTrue(all(not e.flow_ids and not e.terminating_flow_ids for e in ends))

    def test_readiness_does_not_claim_a_packet_or_wake_target(self):
        ready = self.events_in("anettrace.rx.handoff")[0][1]
        args = self.args(ready)
        self.assertEqual(args["packet_id"], "0000000000000000")
        self.assertEqual(args["evidence"], "socket_readable_callback")
        self.assertEqual(args["packet_association"], "unassociated")
        self.assertNotIn("wake_tid", args)
        self.assertEqual(list(ready.flow_ids), [int(args["socket_id"], 16)])

    def test_native_json_identity_and_final_association_agree(self):
        json_packets = [r for r in self.records if r["type"] == "packet_event"]
        native_packets = [self.args(e) for _, e in self.events_in("anettrace.packet")]
        for record, args in zip(json_packets, native_packets):
            for key in ("packet_id", "flow_id", "flow_tag", "socket_id", "io_id", "call_id"):
                self.assertEqual(record[key], args[key])
        record = next(r for r in self.records if r["type"] == "io_complete")
        args = self.args(self.events_in("anettrace.io.complete")[0][1])
        for key in ("flow_id", "socket_id", "io_id", "call_id", "flow_tag", "association"):
            self.assertEqual(record[key], args[key])

    def test_icmp_native_and_json_metadata_do_not_invent_ports_or_connections(self):
        for protocol, label, request, reply, error in (
                (1, "icmp", 8, 0, 3), (58, "icmpv6", 128, 129, 1)):
            with self.subTest(protocol=protocol):
                native = self.events_in("anettrace.packet", protocol=protocol)
                records = [r for r in self.records if r.get("proto_l4") == protocol]
                self.assertEqual(len(native), 4)
                self.assertEqual(len(records), 4)
                for (_, event), record, kind in zip(native, records, (request, request, reply, error)):
                    args = self.args(event)
                    self.assertEqual(args["flow_tag"], label)
                    self.assertTrue(event.name.startswith(label + " · "))
                    self.assertFalse(event.correlation_id)
                    self.assertEqual(record["flow_id"], "0000000000000000")
                    self.assertFalse(record["flow_anchor"])
                    self.assertEqual(args["owner_valid"], "false")
                    for key in ("sport", "dport", "tcp_seq", "tcp_flags", "dns_transaction_id"):
                        self.assertNotIn(key, args)
                        self.assertNotIn(key, record)
                    self.assertEqual(record["icmp_type"], kind)
                    self.assertEqual(record["icmp_code"], 1 if kind == error else 0)
                    for key in ("icmp_type", "icmp_code", "direction"):
                        self.assertEqual(args[key], str(record[key]))
                    if kind == error:
                        self.assertNotIn("icmp_id", args)
                        self.assertNotIn("icmp_seq", args)
                        self.assertNotIn("icmp_id", record)
                        self.assertNotIn("icmp_seq", record)
                    else:
                        self.assertEqual(record["icmp_id"], 1234)
                        self.assertEqual(record["icmp_seq"], 7)
                        self.assertEqual(args["icmp_id"], "1234")
                        self.assertEqual(args["icmp_seq"], "7")
                self.assertEqual(list(native[0][1].flow_ids), list(native[1][1].flow_ids))
                self.assertNotEqual(list(native[0][1].flow_ids), list(native[2][1].flow_ids))


if __name__ == "__main__":
    unittest.main()
