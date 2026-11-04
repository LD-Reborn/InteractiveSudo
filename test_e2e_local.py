#!/usr/bin/env python3
"""test_e2e_local.py — offline end-to-end test of relay + channel + E2EE.

Starts approve_server on 127.0.0.1:8099 (plain ws), connects a real
ApproveChannel, and walks the page's API calls exactly like the browser
does — but encrypting via Node's WebCrypto (test_page_parity.mjs) to prove
browser parity, falling back to python cryptography when Node is missing.

Run:  python3 test_e2e_local.py
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import approve_server  # noqa: E402
from approve_client import (ApproveChannel, ChannelError,  # noqa: E402
                            generate_request_key, open_payload, seal_payload)

PSK = "test-psk-1234567890"
PORT = 8099
BASE = f"http://127.0.0.1:{PORT}"
WSS = f"ws://127.0.0.1:{PORT}/ws/v1/client"
FAILED = []


def check(name: str, cond: bool, extra: str = "") -> None:
    print(f"  {'ok' if cond else 'FAIL'}  {name} {extra}")
    if not cond:
        FAILED.append(name)


def api(path, token=None, method="GET", body=None):
    req = urllib.request.Request(BASE + path, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def page_encrypt(pubkey_b64: str, blob: dict) -> dict:
    """Encrypt exactly like the browser page: via Node's WebCrypto when
    available (proves real browser API parity), else python cryptography."""
    import shutil
    mjs = os.path.join(HERE, "test_page_parity.mjs")
    if shutil.which("node"):
        blob_b64 = b64u(json.dumps(blob, ensure_ascii=False).encode())
        node = subprocess.run(["node", mjs, pubkey_b64, blob_b64],
                              capture_output=True, text=True, timeout=30)
        if node.returncode == 0 and node.stdout.strip():
            return json.loads(node.stdout)
        raise RuntimeError(f"node page-parity failed: {node.stderr}")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    import secrets as _s
    pub = load_der_public_key(
        base64.urlsafe_b64decode(blob_pubkey_pad(pubkey_b64)))
    key = AESGCM.generate_key(bit_length=256)
    iv = _s.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(blob).encode(), None)
    ek = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))
    return {"ek": b64u(ek), "iv": b64u(iv), "ct": b64u(ct)}


def blob_pubkey_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def main() -> int:
    approve_server.REGISTRY = approve_server.Registry(
        dict(approve_server.DEFAULTS, psk=PSK, ttl_s=300,
             page_title="test"))
    threading.Thread(target=approve_server.reaper, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), approve_server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)

    print("== 1. page + api basics ==")
    req = urllib.request.Request(BASE + "/")
    with urllib.request.urlopen(req, timeout=5) as r:
        html = r.read().decode()
    check("page served", "sudo-Freigabe" in html)
    st, _ = api("/api/v1/request", "0" * 47)
    check("unknown token -> 404", st == 404)
    st, _ = api("/api/v1/request")
    check("no bearer -> 404", st == 404)

    print("== 2. wrong PSK rejected ==")
    bad = ApproveChannel(WSS, "wrong-psk", log=lambda m: None)
    bad.start()
    time.sleep(0.5)
    try:
        bad.register("x-1", "true", "", [], 60)
        check("bad psk rejected", False, "(registered anyway!)")
    except ChannelError as e:
        check("bad psk rejected", True, f"({str(e)[:40]}…)")
    bad._stop.set()

    print("== 3. register -> page view -> approve -> decrypt ==")
    ch = ApproveChannel(WSS, PSK, client_label="test@pc", log=lambda m: None)
    ch.start()
    deadline = time.time() + 5
    while not ch.connected and time.time() < deadline:
        time.sleep(0.1)
    check("channel connected", ch.connected)

    url, key = ch.register("s-e2e-1", "systemctl restart foo",
                           "unit reloaded", ["GIT_TOKEN"], 300)
    token = url.split("/r/")[1]
    check("url is fragment form", url.startswith(BASE + "/#/r/")
          and len(token) > 40)

    st, meta = api("/api/v1/request", token)
    check("meta 200", st == 200)
    check("meta command", meta.get("command") == "systemctl restart foo")
    check("meta secrets", meta.get("secrets") == ["GIT_TOKEN"])
    check("meta has pubkey", bool(meta.get("pubkey")))

    payload = page_encrypt(meta["pubkey"], {
        "v": 1, "id": "s-e2e-1", "password": "hunter2 testgeheim",
        "secrets": {"GIT_TOKEN": "tok-with-$pecial välu"},
        "scope": "once", "ts": int(time.time())})
    st, r = api("/api/v1/request/decision", token, "POST",
                {"decision": "approve", "scope": "once", "payload": payload})
    check("approve POST accepted", st == 200 and r.get("ok"))

    ev = ch.wait("s-e2e-1", 5)
    check("decision on channel", ev and ev.get("decision") == "approve")
    blob = open_payload(key, ev["payload"]["ek"], ev["payload"]["iv"],
                        ev["payload"]["ct"])
    check("decrypted password", blob.get("password") == "hunter2 testgeheim")
    check("decrypted secret",
          blob.get("secrets", {}).get("GIT_TOKEN") == "tok-with-$pecial välu")
    check("bound to request id", blob.get("id") == "s-e2e-1")
    check("via node WebCrypto" if shutil_node() else "via python fallback",
          True)

    ch.report("s-e2e-1", "done")
    st, r = api("/api/v1/request/status", token)
    check("status ok after done", st == 200 and r.get("state") == "ok")
    st, _ = api("/api/v1/request/decision", token, "POST",
                {"decision": "approve", "payload": payload})
    check("token single-use", st == 404)

    print("== 4. wrong password -> auth_failed retry allowed ==")
    url2, key2 = ch.register("s-e2e-2", "id", "retry test", [], 300)
    tok2 = url2.split("/r/")[1]
    st, meta2 = api("/api/v1/request", tok2)
    badpl = page_encrypt(meta2["pubkey"], {
        "v": 1, "id": "s-e2e-2", "password": "totally-wrong",
        "secrets": {}, "scope": "once", "ts": int(time.time())})
    st, _ = api("/api/v1/request/decision", tok2, "POST",
                {"decision": "approve", "scope": "once", "payload": badpl})
    check("first attempt accepted", st == 200)
    ev = ch.wait("s-e2e-2", 5)
    check("decision received", ev and ev.get("op") == "decision")
    ch.report("s-e2e-2", "auth_failed")
    st, r = api("/api/v1/request/status", tok2)
    check("state auth_failed (page may retry)",
          st == 200 and r.get("state") == "auth_failed")

    print("== 5. page deny ==")
    url3, _ = ch.register("s-e2e-3", "rm -f /tmp/x", "deny test", [], 300)
    tok3 = url3.split("/r/")[1]
    st, _ = api("/api/v1/request/decision", tok3, "POST",
                {"decision": "deny"})
    check("deny 200", st == 200)
    ev = ch.wait("s-e2e-3", 5)
    check("deny on channel", ev and ev.get("decision") == "deny")

    print("== 5b. sealed result channel (exit code + output) ==")
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    urlr, _ = ch.register("s-e2e-r", "true", "result test", [], 300)
    tokr = urlr.split("/r/")[1]
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = b64u(rk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    summary = {"status": "done", "command": "true", "exit_code": 0,
               "stdout": "hello ergebnis", "stderr": ""}
    sealed = seal_payload(spki, summary)
    ch.report("s-e2e-r", "executing")     # exec-hold extends the TTL …
    time.sleep(0.3)
    st, r = api("/api/v1/request/status", tokr)
    check("executing extends hold",
          st == 200 and r.get("expires_in", 0) > 600)
    ch.report("s-e2e-r", "done", payload=sealed)
    st, r = api("/api/v1/request/status", tokr)
    check("status ok + has_result",
          st == 200 and r.get("state") == "ok" and r.get("has_result"))
    st, r = api("/api/v1/request/result", tokr)
    check("result endpoint serves sealed blob", st == 200 and bool(r.get("ct")))
    aes = rk.decrypt(
        base64.urlsafe_b64decode(blob_pubkey_pad(r["ek"])),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    d = json.loads(AESGCM(aes).decrypt(
        base64.urlsafe_b64decode(blob_pubkey_pad(r["iv"])),
        base64.urlsafe_b64decode(blob_pubkey_pad(r["ct"])), None))
    check("result roundtrip (exit+stdout)",
          d.get("exit_code") == 0 and "hello ergebnis" in d.get("stdout", ""))

    # browser parity: exactly the showResult()/approve() WebCrypto calls
    if shutil_node():
        gen = subprocess.run(["node", os.path.join(HERE, "test_result_parity.mjs"),
                              "gen"], capture_output=True, text=True, timeout=30)
        check("result parity: gen", gen.returncode == 0, gen.stderr[:120])
        pair = json.loads(gen.stdout)
        sealed2 = seal_payload(pair["spki"], summary)
        op = subprocess.run(
            ["node", os.path.join(HERE, "test_result_parity.mjs"), "open",
             json.dumps(pair["jwk"]), json.dumps(sealed2)],
            capture_output=True, text=True, timeout=30)
        try:
            d2 = json.loads(op.stdout)
        except Exception:
            d2 = {}
        check("browser decrypts sealed result (node WebCrypto)",
              op.returncode == 0 and d2 == summary, op.stderr[:120])

    print("== 6. expiry ==")
    url4, _ = ch.register("s-e2e-4", "sleep 999", "expiry test", [], 300)
    tok4 = url4.split("/r/")[1]
    e = approve_server.REGISTRY.by_rid["s-e2e-4"]
    e.expires = time.time() - 1  # fast-forward

    time.sleep(3.5)
    ev = ch.wait("s-e2e-4", 2)
    check("expired on channel", ev and ev.get("op") == "expired",
          f"(got {ev})")
    st, _ = api("/api/v1/request", tok4)
    check("expired token -> 404", st == 404)

    print("== 7. revoke by client (Matrix 👎) ==")
    url5, _ = ch.register("s-e2e-5", "echo hi", "revoke test", [], 300)
    tok5 = url5.split("/r/")[1]
    ch.revoke("s-e2e-5")
    time.sleep(0.5)
    st, _ = api("/api/v1/request", tok5)
    check("revoked token -> 404", st == 404)

    ch._stop.set()
    srv.shutdown()
    print()
    if FAILED:
        print(f"FAILED: {FAILED}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


def shutil_node() -> bool:
    import shutil
    return shutil.which("node") is not None


if __name__ == "__main__":
    sys.exit(main())
