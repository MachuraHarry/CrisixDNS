#!/usr/bin/env python3
"""
Crisix DNS Tunnel Server
=======================
Läuft als Docker-Container auf Render.com.
Ermöglicht DNS-Tunneling für den Crisix-Messenger.

Protokoll:
----------
Senden (Client → Server):
  DNS-Query: [base32-nachricht].[empfänger-id].crisix.[server-domain] TXT
  Server extrahiert Nachricht + Empfänger, speichert in Queue

Empfangen (Client ← Server):
  DNS-Query: poll.[empfänger-id].crisix.[server-domain] TXT
  Server antwortet mit TXT-Record: "msg:[base32-nachricht]" oder "empty"

Bestätigung (Client → Server):
  DNS-Query: ack.[msg-hash].crisix.[server-domain] TXT
  Server markiert Nachricht als gelesen

Ports:
  - 8053: DNS over UDP (für echte DNS-Queries)
  - 8080: HTTP-API (für DNS-over-HTTPS / Debug)
"""

import asyncio
import base64
import hashlib
import json
import os
import struct
import time
from collections import defaultdict
from typing import Optional

from aiohttp import web

# ─── Konfiguration ───────────────────────────────────────────────────────────

SERVER_DOMAIN = os.environ.get("SERVER_DOMAIN", "crisix-dns.onrender.com")
DNS_PORT = int(os.environ.get("DNS_PORT", "8053"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
MAX_MSG_LENGTH = 200  # Max Zeichen Klartext
CLEANUP_INTERVAL = 300  # Alte Nachrichten alle 5min löschen
MSG_TTL = 3600  # Nachrichten 1h aufbewahren

# ─── In-Memory Nachrichten-Queue ─────────────────────────────────────────────

# Format: { receiver_id: { msg_hash: { "data": bytes, "sender": str, "timestamp": float } } }
message_queue: dict = defaultdict(dict)

# ─── Base32 Kodierung (DNS-safe: nur a-z, 0-9, -) ────────────────────────────

def base32_encode(data: bytes) -> str:
    """Kodiert Bytes in DNS-sicheres Base32 (keine Großbuchstaben, kein Padding)."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()

def base32_decode(s: str) -> bytes:
    """Dekodiert DNS-sicheres Base32 zurück zu Bytes."""
    # Padding auffüllen
    padding = 8 - (len(s) % 8)
    if padding != 8:
        s += "=" * padding
    return base64.b32decode(s.upper())

# ─── DNS-Protokoll (UDP) ─────────────────────────────────────────────────────

def parse_dns_query(data: bytes) -> Optional[dict]:
    """Parst eine eingehende DNS-Query und extrahiert den Query-Namen."""
    try:
        # DNS-Header: 12 Bytes
        # Transaction ID: 2 Bytes
        # Flags: 2 Bytes
        # Questions: 2 Bytes
        # Answer RRs: 2 Bytes
        # Authority RRs: 2 Bytes
        # Additional RRs: 2 Bytes
        header = data[:12]
        transaction_id = struct.unpack("!H", header[0:2])[0]
        flags = struct.unpack("!H", header[2:4])[0]
        questions = struct.unpack("!H", header[4:6])[0]

        if questions == 0:
            return None

        # Query-Namen parsen (Labels)
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:  # Kompression (Pointer)
                offset += 2
                break
            offset += 1
            label = data[offset:offset + length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

        # Query-Typ (2 Bytes) und Klasse (2 Bytes)
        qtype = struct.unpack("!H", data[offset:offset + 2])[0] if offset + 2 <= len(data) else 0
        qclass = struct.unpack("!H", data[offset + 2:offset + 4])[0] if offset + 4 <= len(data) else 0

        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "domain": ".".join(labels),
            "qtype": qtype,
            "qclass": qclass,
            "labels": labels,
        }
    except Exception as e:
        print(f"[DNS] Parse error: {e}")
        return None


def build_dns_response(query: dict, txt_records: list[str]) -> bytes:
    """Baut eine DNS-Response mit TXT-Records."""
    transaction_id = query["transaction_id"]
    domain = query["domain"]

    # DNS-Header
    # Flags: Standard-Response, no error
    flags = 0x8180  # QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
    questions = 1
    answer_rrs = len(txt_records)
    authority_rrs = 0
    additional_rrs = 0

    header = struct.pack("!HHHHHH",
        transaction_id, flags, questions,
        answer_rrs, authority_rrs, additional_rrs
    )

    # Question-Section (den Query-Namen wiederholen)
    question_parts = []
    for label in query["labels"]:
        question_parts.append(struct.pack("B", len(label)) + label.encode())
    question_parts.append(b"\x00")  # Root-Label
    question = b"".join(question_parts) + struct.pack("!HH", query["qtype"], query["qclass"])

    # Answer-Section (TXT-Records)
    answer_parts = []
    for txt in txt_records:
        # Name (Pointer auf Query-Namen)
        name = struct.pack("!H", 0xC000 | 12)  # Pointer auf Offset 12
        rtype = 16  # TXT
        rclass = 1  # IN
        ttl = 60    # 60 Sekunden TTL
        txt_data = txt.encode("utf-8")
        rdlength = 1 + len(txt_data)  # 1 Byte Länge + Daten
        rdata = struct.pack("B", len(txt_data)) + txt_data

        answer_parts.append(name + struct.pack("!HHIH", rtype, rclass, ttl, rdlength) + rdata)

    return header + question + b"".join(answer_parts)


def build_dns_nxdomain_response(query: dict) -> bytes:
    """Baut eine DNS-Response mit NXDOMAIN (Name nicht gefunden)."""
    transaction_id = query["transaction_id"]
    domain = query["domain"]

    # Flags: NXDOMAIN (RCODE=3)
    flags = 0x8183  # QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=3
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    header = struct.pack("!HHHHHH",
        transaction_id, flags, questions,
        answer_rrs, authority_rrs, additional_rrs
    )

    # Question-Section
    question_parts = []
    for label in query["labels"]:
        question_parts.append(struct.pack("B", len(label)) + label.encode())
    question_parts.append(b"\x00")
    question = b"".join(question_parts) + struct.pack("!HH", query["qtype"], query["qclass"])

    return header + question


# ─── Nachrichten-Logik ───────────────────────────────────────────────────────

def process_incoming_message(sender_id: str, receiver_id: str, raw_data: bytes):
    """Verarbeitet eine eingehende Nachricht und speichert sie in der Queue."""
    msg_hash = hashlib.sha256(raw_data).hexdigest()[:16]

    # Prüfen ob bereits empfangen (Duplikat)
    if msg_hash in message_queue[receiver_id]:
        return False

    message_queue[receiver_id][msg_hash] = {
        "data": raw_data,
        "sender": sender_id,
        "timestamp": time.time(),
    }
    print(f"[MSG] Neue Nachricht für {receiver_id} von {sender_id}: {len(raw_data)} Bytes")
    return True


def get_pending_messages(receiver_id: str) -> list[dict]:
    """Holt alle ausstehenden Nachrichten für einen Empfänger."""
    now = time.time()
    messages = []
    to_delete = []

    for msg_hash, msg in message_queue[receiver_id].items():
        if now - msg["timestamp"] > MSG_TTL:
            to_delete.append(msg_hash)
            continue
        messages.append({
            "hash": msg_hash,
            "data": msg["data"],
            "sender": msg["sender"],
        })

    # Alte Nachrichten löschen
    for h in to_delete:
        del message_queue[receiver_id][h]

    return messages


def acknowledge_message(receiver_id: str, msg_hash: str) -> bool:
    """Bestätigt den Empfang einer Nachricht und löscht sie."""
    if msg_hash in message_queue[receiver_id]:
        del message_queue[receiver_id][msg_hash]
        print(f"[ACK] Nachricht {msg_hash} für {receiver_id} bestätigt und gelöscht")
        return True
    return False


def parse_dns_domain(domain: str) -> Optional[dict]:
    """Parst eine DNS-Domain im Format: [aktion].[daten].[server-domain]"""
    domain = domain.lower().rstrip(".")

    # Server-Domain entfernen
    if SERVER_DOMAIN in domain:
        prefix = domain[:domain.index(SERVER_DOMAIN)].rstrip(".")
    else:
        # Fallback: letzte 2 Labels als Domain
        parts = domain.split(".")
        if len(parts) < 3:
            return None
        prefix = ".".join(parts[:-2])

    parts = prefix.split(".")
    if len(parts) < 2:
        return None

    action = parts[0]
    data = ".".join(parts[1:])

    return {"action": action, "data": data}


# ─── DNS-Request-Handler (UDP) ───────────────────────────────────────────────

async def handle_dns_request(data: bytes, addr: tuple, transport):
    """Verarbeitet eine eingehende DNS-Anfrage."""
    query = parse_dns_query(data)
    if not query:
        return

    domain = query["domain"]
    print(f"[DNS] Query von {addr}: {domain}")

    parsed = parse_dns_domain(domain)
    if not parsed:
        # Unbekanntes Format → NXDOMAIN
        response = build_dns_nxdomain_response(query)
        transport.sendto(response, addr)
        return

    action = parsed["action"]
    payload = parsed["data"]

    if action == "send":
        # Format: send.[base32-nachricht].[empfänger-id]
        parts = payload.split(".")
        if len(parts) < 2:
            response = build_dns_nxdomain_response(query)
            transport.sendto(response, addr)
            return

        receiver_id = parts[-1]
        b32_data = ".".join(parts[:-1])

        try:
            raw_data = base32_decode(b32_data)
            sender_id = f"peer-{addr[0]}:{addr[1]}"

            if len(raw_data) > MAX_MSG_LENGTH * 2:  # Base32 ist ~1.6x größer
                response = build_dns_response(query, ["error:too-large"])
            else:
                process_incoming_message(sender_id, receiver_id, raw_data)
                response = build_dns_response(query, ["ok"])
        except Exception as e:
            print(f"[DNS] Decode error: {e}")
            response = build_dns_nxdomain_response(query)

        transport.sendto(response, addr)

    elif action == "poll":
        # Format: poll.[empfänger-id]
        receiver_id = payload
        messages = get_pending_messages(receiver_id)

        if not messages:
            response = build_dns_response(query, ["empty"])
        else:
            txt_records = []
            for msg in messages[:5]:  # Max 5 Nachrichten pro Poll
                b32_data = base32_encode(msg["data"])
                txt = f"msg:{msg['hash']}:{msg['sender']}:{b32_data}"
                txt_records.append(txt)
            response = build_dns_response(query, txt_records)

        transport.sendto(response, addr)

    elif action == "ack":
        # Format: ack.[msg-hash].[empfänger-id]
        parts = payload.split(".")
        if len(parts) >= 2:
            msg_hash = parts[0]
            receiver_id = ".".join(parts[1:])
            acknowledge_message(receiver_id, msg_hash)
            response = build_dns_response(query, ["ack"])
        else:
            response = build_dns_nxdomain_response(query)
        transport.sendto(response, addr)

    else:
        response = build_dns_nxdomain_response(query)
        transport.sendto(response, addr)


# ─── UDP-Server ──────────────────────────────────────────────────────────────

class DnsUdpServer:
    """Asynchroner UDP-DNS-Server."""

    def __init__(self, port: int):
        self.port = port

    async def start(self):
        loop = asyncio.get_event_loop()
        print(f"[DNS] UDP-Server gestartet auf Port {self.port}")

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DnsUdpProtocol(),
            local_addr=("0.0.0.0", self.port),
        )

        # Am Leben erhalten
        while True:
            await asyncio.sleep(60)


class DnsUdpProtocol(asyncio.DatagramProtocol):
    """UDP-Protokoll-Handler für DNS-Anfragen."""

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.create_task(handle_dns_request(data, addr, self.transport))

    def error_received(self, exc):
        print(f"[DNS] UDP Error: {exc}")


# ─── HTTP-API (für DNS-over-HTTPS / Debug) ───────────────────────────────────

async def handle_http_dns(request: web.Request) -> web.Response:
    """HTTP-Endpoint für DNS-over-HTTPS (GET/POST)."""
    if request.method == "GET":
        domain = request.query.get("domain", "")
        action = request.query.get("action", "")
        data = request.query.get("data", "")
    else:
        body = await request.json()
        domain = body.get("domain", "")
        action = body.get("action", "")
        data = body.get("data", "")

    if not domain and action:
        domain = f"{action}.{data}.{SERVER_DOMAIN}"

    parsed = parse_dns_domain(domain)
    if not parsed:
        return web.json_response({"error": "invalid domain"}, status=400)

    action = parsed["action"]
    payload = parsed["data"]

    if action == "send":
        parts = payload.split(".")
        if len(parts) < 2:
            return web.json_response({"error": "invalid format"}, status=400)

        receiver_id = parts[-1]
        b32_data = ".".join(parts[:-1])

        try:
            raw_data = base32_decode(b32_data)
            sender_id = f"http-{request.remote}"

            if len(raw_data) > MAX_MSG_LENGTH * 2:
                return web.json_response({"error": "too large"}, status=400)

            process_incoming_message(sender_id, receiver_id, raw_data)
            return web.json_response({"status": "ok"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    elif action == "poll":
        receiver_id = payload
        messages = get_pending_messages(receiver_id)
        return web.json_response({
            "messages": [
                {
                    "hash": m["hash"],
                    "sender": m["sender"],
                    "data": base64.b64encode(m["data"]).decode(),
                }
                for m in messages
            ]
        })

    elif action == "ack":
        parts = payload.split(".")
        if len(parts) >= 2:
            msg_hash = parts[0]
            receiver_id = ".".join(parts[1:])
            acknowledge_message(receiver_id, msg_hash)
            return web.json_response({"status": "ack"})
        return web.json_response({"error": "invalid format"}, status=400)

    return web.json_response({"error": "unknown action"}, status=400)


async def handle_health(request: web.Request) -> web.Response:
    """Health-Check-Endpoint für Render.com."""
    return web.json_response({
        "status": "ok",
        "server": "Crisix DNS Tunnel",
        "domain": SERVER_DOMAIN,
        "queue_size": sum(len(msgs) for msgs in message_queue.values()),
        "uptime": time.time(),
    })


async def handle_debug(request: web.Request) -> web.Response:
    """Debug-Endpoint – zeigt Queue-Status."""
    return web.json_response({
        "queue": {
            receiver: {
                msg_hash: {
                    "sender": msg["sender"],
                    "size": len(msg["data"]),
                    "age": int(time.time() - msg["timestamp"]),
                }
                for msg_hash, msg in msgs.items()
            }
            for receiver, msgs in message_queue.items()
        },
        "total_messages": sum(len(msgs) for msgs in message_queue.values()),
    })


# ─── Cleanup-Task ────────────────────────────────────────────────────────────

async def cleanup_old_messages():
    """Löscht regelmäßig alte Nachrichten."""
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL)
        now = time.time()
        total_deleted = 0

        for receiver_id in list(message_queue.keys()):
            to_delete = []
            for msg_hash, msg in message_queue[receiver_id].items():
                if now - msg["timestamp"] > MSG_TTL:
                    to_delete.append(msg_hash)

            for h in to_delete:
                del message_queue[receiver_id][h]
                total_deleted += 1

            if not message_queue[receiver_id]:
                del message_queue[receiver_id]

        if total_deleted > 0:
            print(f"[CLEANUP] {total_deleted} alte Nachrichten gelöscht")


# ─── Hauptprogramm ───────────────────────────────────────────────────────────

async def main():
    print("=" * 50)
    print("🚀 Crisix DNS Tunnel Server")
    print(f"📡 Domain: {SERVER_DOMAIN}")
    print(f"🔌 DNS-Port: {DNS_PORT} (UDP)")
    print(f"🌐 HTTP-Port: {HTTP_PORT}")
    print("=" * 50)

    # HTTP-App
    app = web.Application()
    app.router.add_get("/dns-query", handle_http_dns)
    app.router.add_post("/dns-query", handle_http_dns)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/debug", handle_debug)
    app.router.add_get("/", handle_health)

    # Cleanup-Task starten
    asyncio.create_task(cleanup_old_messages())

    # UDP-DNS-Server starten
    dns_server = DnsUdpServer(DNS_PORT)
    asyncio.create_task(dns_server.start())

    # HTTP-Server starten
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    print(f"[HTTP] Server gestartet auf Port {HTTP_PORT}")

    # Am Leben erhalten
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
