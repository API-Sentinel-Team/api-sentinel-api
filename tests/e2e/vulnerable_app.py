from fastapi import FastAPI, Depends, HTTPException, Query
import uvicorn

target = FastAPI(title="Deliberately Vulnerable Target")

@target.get("/api/users/{user_id}/data")
async def get_user_data(user_id: str, token: str = Query(None)):
    # DELIBERATELY vulnerable — no auth check actually performed on the user_id matching the token
    # This is a classic BOLA/IDOR vulnerability
    return {
        "user_id": user_id,
        "data": f"Sensitive data for user {user_id}",
        "secret_flag": "FLAG{BOLA_DETECTED}"
    }

@target.get("/api/products")
async def list_products():
    # Secure public endpoint — no sensitivity
    return [{"id": 1, "name": "Standard Widget"}]

if __name__ == "__main__":
    uvicorn.run(target, host="127.0.0.1", port=9999)
