from fastapi import FastAPI, File, UploadFile

app = FastAPI()


@app.post("/auth/login")
def login() -> dict[str, str]:
    return {"token": "fixture-token"}


@app.get("/admin/users")
def list_admin_users() -> list[dict[str, str]]:
    # Deliberate product defect: authenticated admin-role authorization is absent.
    return [{"id": "fixture-user"}]


@app.post("/upload")
async def upload(file: UploadFile = File(...)) -> dict[str, str]:
    return {"filename": file.filename or "unnamed"}


@app.post("/mcp")
def mcp_endpoint() -> dict[str, str]:
    return {"jsonrpc": "2.0"}
