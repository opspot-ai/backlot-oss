import asyncio
import base64
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Backlot desktop agent", docs_url=None, redoc_url=None)
DISPLAY_ENV = {**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":99")}
KEY_RE = re.compile(r"^[A-Za-z0-9_+\-]+(?:\+[A-Za-z0-9_+\-]+)*$")


def verified(metadata: str | None) -> None:
    if not metadata:
        raise HTTPException(401, "Modal Connect Token required")
    try:
        data = json.loads(metadata)
    except json.JSONDecodeError as exc:
        raise HTTPException(401, "Invalid verified metadata") from exc
    if data.get("purpose") != "agent" or not data.get("computer_id"):
        raise HTTPException(403, "Wrong Connect Token scope")


def run(argv: list[str], timeout: float = 30, stdin: str | None = None) -> dict:
    try:
        result = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=DISPLAY_ENV,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(408, f"Command timed out after {timeout}s") from exc
    return {
        "success": result.returncode == 0,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


class Click(BaseModel):
    x: int
    y: int
    button: str = "left"
    double: bool = False


class Drag(BaseModel):
    start_x: int
    start_y: int
    end_x: int
    end_y: int
    duration: float = Field(default=0.5, ge=0, le=60)


class TypeText(BaseModel):
    text: str


class Key(BaseModel):
    key: str


class Scroll(BaseModel):
    direction: str
    amount: int = Field(default=3, ge=0, le=100)


class Wait(BaseModel):
    seconds: float = Field(ge=0, le=60)


class Bash(BaseModel):
    command: str
    timeout: float = Field(default=30, gt=0, le=300)


class Exec(BaseModel):
    code: str
    timeout: float = Field(default=30, gt=0, le=300)


class Process(BaseModel):
    argv: list[Annotated[str, Field(min_length=1, max_length=4096)]] = Field(
        min_length=1, max_length=64
    )
    stdin: str = Field(default="", max_length=1_000_000)
    timeout: float = Field(default=30, gt=0, le=300)


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/screenshot")
def screenshot(x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    with tempfile.NamedTemporaryFile(suffix=".png") as target:
        result = run(["scrot", "-o", target.name])
        if not result["success"]:
            raise HTTPException(500, result["stderr"] or "Screenshot failed")
        return {"screenshot": base64.b64encode(Path(target.name).read_bytes()).decode()}


@app.post("/click")
def click(body: Click, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    buttons = {"left": "1", "middle": "2", "right": "3"}
    if body.button not in buttons:
        raise HTTPException(422, "button must be left, middle, or right")
    argv = ["xdotool", "mousemove", "--sync", str(body.x), str(body.y), "click"]
    if body.double:
        argv += ["--repeat", "2", "--delay", "120"]
    argv.append(buttons[body.button])
    return run(argv)


@app.post("/drag")
def drag(body: Drag, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    moved = run(["xdotool", "mousemove", "--sync", str(body.start_x), str(body.start_y)])
    if not moved["success"]:
        return moved
    pressed = run(["xdotool", "mousedown", "1"])
    if not pressed["success"]:
        return pressed
    try:
        time.sleep(body.duration)
        moved = run(["xdotool", "mousemove", "--sync", str(body.end_x), str(body.end_y)])
    finally:
        released = run(["xdotool", "mouseup", "1"])
    return moved if not moved["success"] else released


@app.post("/type")
def type_text(body: TypeText, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    return run(["xdotool", "type", "--clearmodifiers", "--delay", "1", "--", body.text])


@app.post("/key")
def key(body: Key, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    if not KEY_RE.fullmatch(body.key):
        raise HTTPException(422, "Invalid key chord")
    return run(["xdotool", "key", "--clearmodifiers", body.key])


@app.post("/scroll")
def scroll(body: Scroll, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    buttons = {"up": "4", "down": "5", "left": "6", "right": "7"}
    if body.direction not in buttons:
        raise HTTPException(422, "direction must be up, down, left, or right")
    if body.amount == 0:
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
    return run(["xdotool", "click", "--repeat", str(body.amount), buttons[body.direction]])


@app.post("/wait")
async def wait(body: Wait, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    await asyncio.sleep(body.seconds)
    return {"success": True}


@app.post("/bash")
def bash(body: Bash, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    return run(["bash", "-lc", body.command], body.timeout)


@app.post("/exec")
def execute(body: Exec, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    return run(["python3", "-c", body.code], body.timeout)


@app.post("/process")
def process(body: Process, x_verified_user_data: str | None = Header(default=None)) -> dict:
    verified(x_verified_user_data)
    return run(body.argv, body.timeout, body.stdin)
