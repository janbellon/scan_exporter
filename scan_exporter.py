#!/usr/bin/env python3
import os
import re
import time
import threading
import subprocess
from prometheus_client import Counter, Gauge, start_http_server

LISTEN_PORT = int(os.getenv("UFW_EXPORTER_PORT", "9192"))
IP_TTL_SECONDS = int(os.getenv("UFW_EXPORTER_IP_TTL_SECONDS", "3600"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("UFW_EXPORTER_CLEANUP_INTERVAL_SECONDS", "60"))

UFW_RE = re.compile(r"\[UFW BLOCK\].*")
FIELD_RE = re.compile(r"\b([A-Z0-9]+)=([^ ]+)")

ufw_blocks_total = Counter(
    "ufw_blocks_total",
    "Total number of UFW blocked packets",
)

ufw_recent_blocks_by_src = Gauge(
    "ufw_recent_blocks_by_src",
    "Recent UFW blocked packets by source IP",
    ["src"],
)

ufw_recent_blocks_by_proto = Gauge(
    "ufw_recent_blocks_by_proto",
    "Recent UFW blocked packets by protocol",
    ["proto"],
)

ufw_recent_blocks_by_dst_port = Gauge(
    "ufw_recent_blocks_by_dst_port",
    "Recent UFW blocked packets by destination port",
    ["proto", "dpt"],
)

sources = {}
protocols = {}
dst_ports = {}

lock = threading.Lock()


def parse_ufw_line(line: str) -> dict | None:
    if not UFW_RE.search(line):
        return None

    fields = dict(FIELD_RE.findall(line))

    src = fields.get("SRC")
    if not src:
        return None

    return {
        "src": src,
        "dst": fields.get("DST", ""),
        "proto": fields.get("PROTO", "unknown").lower(),
        "spt": fields.get("SPT", ""),
        "dpt": fields.get("DPT", ""),
    }


def increment_stat(store: dict, key):
    now = time.time()

    if key not in store:
        store[key] = {
            "count": 0,
            "last_seen": now,
        }

    store[key]["count"] += 1
    store[key]["last_seen"] = now


def handle_ufw_event(event: dict):
    src = event["src"]
    proto = event["proto"]
    dpt = event["dpt"]

    with lock:
        ufw_blocks_total.inc()

        increment_stat(sources, src)
        ufw_recent_blocks_by_src.labels(src=src).set(sources[src]["count"])

        increment_stat(protocols, proto)
        ufw_recent_blocks_by_proto.labels(proto=proto).set(protocols[proto]["count"])

        if dpt:
            key = (proto, dpt)
            increment_stat(dst_ports, key)
            ufw_recent_blocks_by_dst_port.labels(proto=proto, dpt=dpt).set(
                dst_ports[key]["count"]
            )


def cleanup_loop():
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        now = time.time()

        with lock:
            for src, data in list(sources.items()):
                if now - data["last_seen"] > IP_TTL_SECONDS:
                    del sources[src]
                    ufw_recent_blocks_by_src.remove(src)

            for proto, data in list(protocols.items()):
                if now - data["last_seen"] > IP_TTL_SECONDS:
                    del protocols[proto]
                    ufw_recent_blocks_by_proto.remove(proto)

            for key, data in list(dst_ports.items()):
                if now - data["last_seen"] > IP_TTL_SECONDS:
                    proto, dpt = key
                    del dst_ports[key]
                    ufw_recent_blocks_by_dst_port.remove(proto, dpt)


def follow_journald():
    cmd = [
        "journalctl",
        "-k",
        "-f",
        "-n",
        "0",
        "-o",
        "cat",
    ]

    while True:
        try:
            with subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            ) as proc:
                for line in proc.stdout:
                    event = parse_ufw_line(line)
                    if event:
                        handle_ufw_event(event)

        except Exception as e:
            print(f"journalctl error: {e}")
            time.sleep(5)


def main():
    start_http_server(LISTEN_PORT)

    print(f"UFW exporter listening on :{LISTEN_PORT}/metrics")
    print(f"IP TTL: {IP_TTL_SECONDS}s")

    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()

    follow_journald()


if __name__ == "__main__":
    main()
