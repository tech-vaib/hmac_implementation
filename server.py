from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import hmac
import hashlib
import json
import time
from pathlib import Path

app = FastAPI()

# Example key store (replace with Azure Key Vault)
HMAC_KEYS = {
    "event-broadcaster-1": b"testHmacSecret"
}

OUTPUT_FILE = Path("events.log")


def canonicalize_json(data: dict) -> str:
    """
    Canonical JSON representation (RFC 8785–style)
    """
    return json.dumps(
        data,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_hmac(headers: dict, body: dict) -> None:
    """
    Raises HTTPException if verification fails
    """

    key_id = headers.get("key-id")
    timestamp = headers.get("timestamp")
    received_signature = headers.get("signature")

    if not key_id or not timestamp or not received_signature:
        raise HTTPException(status_code=401, detail="Missing HMAC headers")

    secret = HMAC_KEYS.get(key_id)
    if not secret:
        raise HTTPException(status_code=401, detail="Invalid key-id")

    # ⏱ Timestamp freshness check (5 minutes)
    now_ms = int(time.time() * 1000)
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    if abs(now_ms - ts) > 5 * 60 * 1000:
        raise HTTPException(status_code=401, detail="Timestamp expired")

    # Canonicalize body
    canonical_body = canonicalize_json(body)

    # Body hash
    body_hash = sha256_hex(canonical_body.encode("utf-8"))

    # Canonical string
    canonical_string = f"{timestamp}{body_hash}"

    # Compute expected signature
    expected_signature = hmac.new(
        secret,
        canonical_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison
    if not hmac.compare_digest(expected_signature, received_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


@app.post("/events")
async def receive_event(request: Request):
    # Read JSON body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Verify HMAC (raises 401 if invalid)
    verify_hmac(request.headers, body)

    # ✅ HMAC is valid — process body
    # Example: write body to file
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(body) + "\n")

    # Return success
    return JSONResponse(
        status_code=200,
        content={"status": "ok"}
    )
