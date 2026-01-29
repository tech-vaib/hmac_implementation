# hmac_implementation
Azure APIM – how to implement verification
Option A (Recommended): Verify in backend service

APIM only forwards headers + body.
✔ Easier
✔ More secure key handling
✔ Easier rotation

APIM changes

Pass headers unchanged
No cryptography in APIM
<inbound>
    <base />
    <!-- Optional: validate headers exist -->
    <check-header name="signature" failed-check-httpcode="401" />
    <check-header name="timestamp" failed-check-httpcode="401" />
    <check-header name="key-id" failed-check-httpcode="401" />
</inbound>

**All HMAC crypto checks happen in your Python backend.**

HMAC secret management (Azure best practice)
🔐 Where to store secrets

✅ Azure Key Vault

Each key-id → separate secret

Rotate without downtime

**Rotation strategy**

Add new secret version

Accept both old + new temporarily

Remove old after clients update


**Azure APIM**

APIM acts as:

Gateway / reverse proxy

Header presence validator (optional)

Throttling / IP filtering / auth (optional)

🚫 APIM does NOT

Compute SHA256

Compute HMAC

Compare signatures

Store secrets

APIM just forwards:

Request body

key-id

timestamp

signature

request-id

**Python Backend (authoritative security)**

Your Python service:

Reads raw JSON body

Canonicalizes JSON

Computes SHA256(body)

Builds canonical string

Computes HMAC-SHA256

Compares signatures

Enforces timestamp freshness

Enforces replay protection

Retrieves secrets securely
