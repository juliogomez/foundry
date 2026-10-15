# house-style: v2
"""User API."""
from fastapi import FastAPI, Header, HTTPException, Depends

app = FastAPI()

SECRETS = {"u42": "s3cr3t-value"}


def verify_secret(user_id: str, secret: str) -> bool:
    import hmac
    expected = SECRETS.get(user_id, "")
    return hmac.compare_digest(expected, secret)


def get_api_user(x_api_key: str = Header(...)) -> str:
    """Parse X-Api-Key header (<user_id>.<secret>) and authenticate the caller."""
    if "." not in x_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key format")
    user_id, secret = x_api_key.split(".", 1)
    if not verify_secret(user_id, secret):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user_id


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/me")
def me(user_id: str = Depends(get_api_user)):
    return {"user": user_id}
