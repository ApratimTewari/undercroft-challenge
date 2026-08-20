import os
import time
from collections import defaultdict

from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

VISIBLE_KEY = "cutelilpibble"

MAX_INPUT_LEN = 500

# Simple per-IP rate limit: (max requests, per how many seconds).
# This is a courtesy limit so one player can't hammer the server —
# it is NOT meant to be your brute-force defense. Design the algorithm
# itself to make brute force infeasible; don't rely on rate limiting
# for that (it's trivial to defeat with multiple IPs/players).
RATE_LIMIT = (20, 10)  # 20 requests per 10 seconds per IP

def encrypt(plaintext: str) -> str:
    key = VISIBLE_KEY
    out = []
    for k, ch in enumerate(plaintext):
        A = ord(ch) - 32          # normalize into 0-94 before any math
        key_val = ord(key[k % len(key)]) - 32
        shifted = (A + key_val + 2 * k + 1) % 95
        out.append(chr(32 + shifted))
    return "".join(out)

def decrypt(ciphertext: str, key: str = VISIBLE_KEY) -> str:
    out = []
    for k, ch in enumerate(ciphertext):
        C = ord(ch) - 32
        key_val = ord(key[k % len(key)]) - 32
        orig = (C - key_val - 2 * k - 1) % 95
        out.append(chr(32 + orig))
    return "".join(out)


# ─────────────────────────────────────────────────────────────────────────
# Rate limiting (in-memory, fine for a single small instance)
# ─────────────────────────────────────────────────────────────────────────

_request_log = defaultdict(list)


def _is_rate_limited(ip: str) -> bool:
    max_reqs, window = RATE_LIMIT
    now = time.time()
    log = _request_log[ip]
    log[:] = [t for t in log if now - t < window]
    if len(log) >= max_reqs:
        return True
    log.append(now)
    return False


@app.route("/")
def index():
    return render_template(
        "index.html", visible_key=VISIBLE_KEY
    )


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if _is_rate_limited(ip):
        return jsonify({"error": "Too many requests, slow down."}), 429

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not isinstance(text, str) or text == "":
        return jsonify({"error": "Send JSON like {\"text\": \"...\"}"}), 400
    if len(text) > MAX_INPUT_LEN:
        return jsonify({"error": f"Max {MAX_INPUT_LEN} characters."}), 400
    if not all(32 <= ord(c) <= 126 for c in text):
        return jsonify({"error": "Printable ASCII only (32-126)."}), 400

    result = encrypt(text)
    return jsonify({"result": result})


""" if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
"""
