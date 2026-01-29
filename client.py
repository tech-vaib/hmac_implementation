import json
import hmac
import hashlib
import time
import uuid
import requests

SECRET = b"testHmacSecret"
KEY_ID = "event-broadcaster-1"
URL = "https://<your-apim-endpoint>/events"

body = {
    "event": "UNREGISTER_SA",
    "guid": "testGuid01"
}

# Canonicalize
canonical_body = json.dumps(body, separators=(",", ":"), sort_keys=True)

# Timestamp (ms)
timestamp = str(int(time.time() * 1000))

# Body hash
body_hash = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()

# Canonical string
canonical_string = f"{timestamp}{body_hash}"

# Signature
signature = hmac.new(
    SECRET,
    canonical_string.encode("utf-8"),
    hashlib.sha256
).hexdigest()

headers = {
    "Content-Type": "application/json",
    "key-id": KEY_ID,
    "timestamp": timestamp,
    "signature": signature,
    "request-id": str(uuid.uuid4())
}

response = requests.post(URL, json=body, headers=headers)
print(response.status_code, response.text)
