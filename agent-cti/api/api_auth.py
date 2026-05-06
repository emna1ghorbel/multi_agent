from fastapi import Header, HTTPException

VALID_API_KEYS = {"cti-key-analyst-001", "cti-key-admin-001"}

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key
