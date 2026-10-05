#!/usr/bin/env -S uv run --quiet --script
# /// script
# dependencies = ["cryptography"]
# ///
"""Writes vectors/store/ and vectors/vectors.json, deterministically (fixed key and nonces)."""
import base64, json, shutil
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

here = Path(__file__).parent
store = here / "store"
shutil.rmtree(store, ignore_errors=True)
store.mkdir()
(store / ".salt").write_bytes(bytes(range(16)))
key = bytes(range(32, 64))
n = 0

def put(address, plain, *, aad=None, magic=b"SEC2"):
    global n
    n += 1
    nonce = bytes([n]) * 12
    blob = AESGCM(key).encrypt(nonce, plain, (aad or address).encode())
    *dirs, last = address.split(":")
    p = store.joinpath(*dirs) / f"{last}.enc"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(magic + nonce + blob)
    return p

def text(a, v): put(a, b"T" + v.encode())
def plain(a, v):
    p = store.joinpath(*a.split(":")[:-1]) / f"{a.split(':')[-1]}.plain"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(v.encode())
def file(a, name, data): put(a, b"F" + bytes([len(name.encode())]) + name.encode() + data)

cases = []
def t(a, v, why): text(a, v); cases.append({"address": a, "kind": "text", "value": v, "why": why})
def f(a, name, data, why):
    file(a, name, data)
    cases.append({"address": a, "kind": "file", "filename": name, "data_b64": base64.b64encode(data).decode(), "why": why})

t("REVENUECAT:KEY:COMICSCANNER", "sk_test_comicscanner", "a plain value")
t("REVENUECAT:KEY:UNICODE", "sk_ünï_✓", "non-ASCII text")
t("REVENUECAT:KEY:MULTILINE", "line1\nline2", "a newline inside a value")
t("APPLE:KEYID:ME@ICLOUD.COM", "69GG3NAX8V", "an e-mail scope")
plain("TELEGRAM:CHATID:ESTIFIE", "123456789")
cases.append({"address": "TELEGRAM:CHATID:ESTIFIE", "kind": "text", "value": "123456789", "plain": True, "why": "a plain entry needs no key"})
plain("TELEGRAM:CHATID:UNICODE", "chat ✓")
cases.append({"address": "TELEGRAM:CHATID:UNICODE", "kind": "text", "value": "chat ✓", "plain": True, "why": "plain, non-ASCII"})
t("TELEGRAM:BOT:ESTIFIE:MYBOT", "bot-token", "a four-segment address, one folder deeper")
t("TELEGRAM:TOKEN:BOTH", "the-encrypted-one", "an encrypted secret beats a stale plain twin")
plain("TELEGRAM:TOKEN:BOTH", "the-stale-plain-one")
f("APPLE:P8:ME@ICLOUD.COM", "AuthKey_69GG3NAX8V.p8",
  b"-----BEGIN PRIVATE KEY-----\nMIGTFAKE\n-----END PRIVATE KEY-----\n", "a file keeps its own name")
f("APPLE:P8:BINARY", "blob.bin", bytes(range(256)), "arbitrary bytes")

errors = []
good = store / "REVENUECAT/KEY/COMICSCANNER.enc"
tam = store / "REVENUECAT/KEY/TAMPERED.enc"
raw = bytearray(good.read_bytes()); raw[-1] ^= 0xFF
# tamper a copy that is *at the right address*: re-seal then flip a byte
put("REVENUECAT:KEY:TAMPERED", b"Tsk_x")
raw = bytearray(tam.read_bytes()); raw[-1] ^= 0xFF; tam.write_bytes(bytes(raw))
errors.append({"address": "REVENUECAT:KEY:TAMPERED", "why": "a flipped byte"})
(store / "REVENUECAT/KEY/MOVED.enc").write_bytes(good.read_bytes())
errors.append({"address": "REVENUECAT:KEY:MOVED", "why": "a file copied from another address"})
put("REVENUECAT:KEY:BADMAGIC", b"Tsk_x", magic=b"NOPE")
errors.append({"address": "REVENUECAT:KEY:BADMAGIC", "why": "another magic"})
(store / "REVENUECAT/KEY/SHORT.enc").write_bytes(b"SEC2")
errors.append({"address": "REVENUECAT:KEY:SHORT", "why": "shorter than a header"})
put("APPLE:P8:BADLAYOUT", b"F")
errors.append({"address": "APPLE:P8:BADLAYOUT", "why": "opens, but the file layout is cut off"})

(here / "vectors.json").write_text(json.dumps({
    "key_b64": base64.b64encode(key).decode(),
    "store": "store",
    "cases": cases,
    "absent": ["REVENUECAT:KEY:NOPE", "OTHER:KIND:SCOPE", "revenuecat:key:nope"],
    "lowercase_finds": {"input": "revenuecat:key:comicscanner", "value": "sk_test_comicscanner"},
    "errors": errors,
    "bad_addresses": ["REVENUECAT:KEY:../../X", "REVENUECAT:KEY:a/b", "ONE", "", "REVENUECAT:KEY:"],
    "addresses_under_telegram": ["TELEGRAM:BOT:ESTIFIE:MYBOT", "TELEGRAM:CHATID:ESTIFIE", "TELEGRAM:CHATID:UNICODE", "TELEGRAM:TOKEN:BOTH"],
    "addresses_under_apple": ["APPLE:KEYID:ME@ICLOUD.COM", "APPLE:P8:BADLAYOUT", "APPLE:P8:BINARY", "APPLE:P8:ME@ICLOUD.COM"],
}, indent=2, ensure_ascii=False) + "\n")
print("wrote", len(cases), "cases,", len(errors), "error cases")
