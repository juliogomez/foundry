# house-style: v2
"""User API."""
import hmac

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI()

# Security note (codeguard-1-hardcoded-credentials): SECRETS contains a
# hardcoded credential.  In production, load secrets from a KMS/secrets
# manager (e.g. AWS Secrets Manager, HashiCorp Vault) instead of
# hard-coding them here.
SECRETS = {"u42": "s3cr3t-value"}


def verify_secret(user_id: str, secret: str) -> bool:
    expected = SECRETS.get(user_id, "")
    return hmac.compare_digest(expected, secret)


def get_api_user(x_api_key: str = Header(...)) -> str:
    """Parse the X-Api-Key header (<user_id>.<secret>) and return user_id.

    Raises HTTP 401 when the header is missing, malformed, or the secret
    does not match.

    Security notes:
    - Split is bounded to 1 to handle secrets that themselves contain dots.
    - Length is validated before indexing (CWE-129).
    - Comparison is performed with hmac.compare_digest to prevent
      timing-based enumeration of valid user IDs or secrets.
    """
    # Split on the first '.' only so secrets may contain dots safely.
    parts = x_api_key.split(".", 1)

    # CWE-129: validate the array length before indexing.
    if len(parts) != 2 or not parts[0]:
        raise HTTPException(status_code=401, detail="Invalid API key format")

    user_id, secret = parts

    if not verify_secret(user_id, secret):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return user_id


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/me")
def me(user_id: str = Depends(get_api_user)):
    return {"user": user_id}
