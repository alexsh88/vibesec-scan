import pickle

import requests
import yaml
from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/config/import")
async def import_config(request: Request):
    body = await request.body()
    config = yaml.load(body, Loader=yaml.Loader)
    return {"config": config}


@app.post("/session/restore")
async def restore_session(request: Request):
    body = await request.body()
    session = pickle.loads(body)
    return {"ok": True, "user": session.get("user")}


@app.get("/fetch")
async def fetch_url(url: str):
    response = requests.get(url)
    return {"status": response.status_code, "body": response.text[:2000]}
