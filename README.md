# ICMP Exfil

Data exfiltration over ICMP Echo Request, implemented as a sender in x86-64 NASM and a receiver in Python.

The sender reads a file from disk, splits it into fixed-size chunks and transmits each chunk as the data field of an ICMP Echo Request packet. The receiver captures those packets, indexes them by Sequence Number and reassembles the original file.

Part of the [RAZOR](https://0x574r.github.io/) blog series. Full writeup.

## Build

```bash
nasm -f elf64 ping.asm -o ping.o
ld ping.o -o ping
```

## Configuration

Edit `ping.asm` before assembling:

| Field | Default | Description |
|---|---|---|
| `pathname` | `/etc/services` | File to exfiltrate |
| `size_block` | `2` | Chunk size in bytes (max 1472) |
| `sockaddr_in.sin_addr` | `0.0.0.0` | Receiver IP (little-endian) |
| `req.tv_nsec` | `10000000` | Delay between packets in ns (10 ms) |

The sender uses `SOCK_DGRAM` with `IPPROTO_ICMP`, so it does not require `CAP_NET_RAW`. The kernel computes the ICMP checksum and writes the Identifier field automatically. Authorization depends on `net.ipv4.ping_group_range`.

## Receiver

```bash
sudo python3 icmp_receiver.py -o output.bin
```

| Flag | Description |
|---|---|
| `-o`, `--output` | Output file path (default: `exfil.bin`) |
| `-s`, `--source` | Filter by sender IP |
| `-t`, `--timeout` | Inactivity timeout in seconds (default: 3) |
| `--keep-nulls` | Preserve trailing null bytes (for binaries) |

The receiver requires `CAP_NET_RAW` (root). It stays listening across multiple transmission rounds, filling gaps in the hash map with each run. `Ctrl+C` triggers reassembly.

## Example

```
# Terminal 1 (receiver)
sudo python3 icmp_receiver.py -o /tmp/services

# Terminal 2 (sender)
./ping

# Verify
diff /etc/services /tmp/services
```

## Disclaimer

For authorized testing and educational purposes only.
