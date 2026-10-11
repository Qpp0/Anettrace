#!/usr/bin/env python3
"""Root/BTF regression: ICMP echo TX/RX in compact and detailed traces.

Run on Linux with a built anettrace binary. Raw loopback sockets supply known
echo IDs and sequences without a ping dependency. Stage one deliberately uses
no PID/UID filter: packet visibility does not imply ping socket ownership.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


PROTOCOLS = {
    'icmp': (socket.AF_INET, socket.IPPROTO_ICMP, '127.0.0.1', 8, 0,
             'ICMP', 'ip_output', 'icmp_rcv', 'ip_rcv'),
    'icmpv6': (socket.AF_INET6, socket.IPPROTO_ICMPV6, '::1', 128, 129,
               'ICMPv6', 'ip6_output', 'icmpv6_rcv', 'ipv6_rcv'),
}
SEQUENCES = (1, 2, 3)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ping_loopback(protocol, identifier):
    family, number, address, request_type, reply_type, *_ = PROTOCOLS[protocol]
    with socket.socket(family, socket.SOCK_RAW, number) as client:
        client.bind((address, 0))
        for sequence in SEQUENCES:
            payload = b'anettrace-icmp-regression' + struct.pack('!H', sequence)
            header = struct.pack('!BBHHH', request_type, 0, 0, identifier, sequence)
            # Linux computes the ICMPv6 checksum, including its pseudoheader.
            if family == socket.AF_INET:
                header = struct.pack('!BBHHH', request_type, 0,
                                     checksum(header + payload), identifier, sequence)
            client.sendto(header + payload, (address, 0))
            deadline = time.monotonic() + 3
            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, (protocol, identifier, sequence, 'no echo reply')
                client.settimeout(remaining)
                packet, peer = client.recvfrom(65535)
                # Linux IPv4 raw sockets include the IP header; IPv6 sockets
                # return the ICMPv6 message directly.
                offset = (packet[0] & 0xf) * 4 if family == socket.AF_INET else 0
                if len(packet) < offset + 8:
                    continue
                kind, code, _, echo_id, echo_seq = struct.unpack_from('!BBHHH', packet, offset)
                if (kind, code, echo_id, echo_seq) == (reply_type, 0, identifier, sequence):
                    assert peer[0] == address, peer
                    assert packet[offset + 8:] == payload, packet
                    break


def validate(records, protocol, identifier, detailed):
    _, number, address, request_type, reply_type, label, output, receive, ingress = PROTOCOLS[protocol]
    packets = [record for record in records
               if record['type'] == 'packet_event'
               and record.get('proto_l4') == number
               and record.get('icmp_id') == identifier]
    assert packets, (protocol, 'no matching ICMP packets', records)
    for record in packets:
        assert record['icmp_type'] in (request_type, reply_type), record
        assert record['icmp_code'] == 0, record
        assert record['icmp_seq'] in SEQUENCES, record
        assert record['saddr'] == address and record['daddr'] == address, record
        assert {'sport', 'dport'}.isdisjoint(record), record
        assert int(record['packet_id'], 16) != 0, record
        assert int(record.get('flow_id') or '0', 16) == 0, record
        assert not record.get('flow_anchor'), record
        assert not record.get('flow_tag', '').startswith(('tcp-', 'udp-')), record

    # Loopback observes both the request and the kernel-generated reply on
    # transmit and receive paths. Check every exchange, not one stray packet.
    for sequence in SEQUENCES:
        for kind in (request_type, reply_type):
            for direction, stage in (('tx', output), ('rx', receive)):
                if not detailed:
                    stage = f'{label} packet {"send" if direction == "tx" else "receive"}'
                matching = [record for record in packets
                            if record['icmp_seq'] == sequence and record['icmp_type'] == kind
                            and record['direction'] == direction and record['stage'] == stage]
                assert matching, (protocol, detailed, sequence, kind, direction, stage, packets)

    packet_ids = {record['packet_id'] for record in packets}
    assert len(packet_ids) >= len(SEQUENCES), packets
    assert not any(record['type'] in ('flow_start', 'socket_flow_link') for record in records), records
    links = [record for record in records if record['type'] == 'packet_io_link'
             and record['packet_id'] in packet_ids]
    assert not links, links
    if detailed:
        assert any(record['stage'] == ingress for record in packets), packets
        assert any(len({record['stage'] for record in packets if record['packet_id'] == packet_id}) > 1
                   for packet_id in packet_ids), packets
    else:
        assert not any(record['stage'] == ingress for record in packets), packets
    return len(packets), len(packet_ids)


def exercise(binary, protocol, group=False, detailed=False):
    identifier = (os.getpid() ^ time.monotonic_ns()) & 0xffff or 1
    with tempfile.TemporaryDirectory(prefix='anettrace-icmp-') as tmp:
        events = Path(tmp) / 'events.jsonl'
        log = Path(tmp) / 'capture.log'
        command = [str(binary), '--perfetto-events', str(events), '--proto', protocol]
        if group:
            command += ['--trace', 'icmp']
        if detailed:
            command += ['--trace-detail']
        with log.open('w') as output:
            tracer = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 180
                while 'begin trace...' not in log.read_text():
                    if tracer.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(log.read_text())
                    time.sleep(0.1)
                time.sleep(0.2)  # readiness is set immediately after the banner
                ping_loopback(protocol, identifier)
                time.sleep(0.3)
            finally:
                if tracer.poll() is None:
                    tracer.send_signal(signal.SIGINT)
                try:
                    tracer.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    tracer.kill()
                    tracer.wait()
        assert tracer.returncode == 0, log.read_text()
        records = [json.loads(line) for line in events.read_text().splitlines()]
        try:
            stages, identities = validate(records, protocol, identifier, detailed)
        except AssertionError:
            print(log.read_text(), file=sys.stderr)
            raise
        print(f'{protocol} group={group} detailed={detailed}: '
              f'{stages} packet stages, {identities} skb instances, echo TX/RX PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('requires Linux and root for BPF tracing and raw ICMP sockets')
    binary = args.binary.resolve()
    for protocol in PROTOCOLS:
        exercise(binary, protocol)
        exercise(binary, protocol, group=True)
        exercise(binary, protocol, detailed=True)
