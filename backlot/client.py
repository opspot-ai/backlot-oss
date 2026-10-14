from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
from typing import Any

import httpx
import yaml


class Backlot:
    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or os.environ.get("BACKLOT_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("BACKLOT_API_KEY", "")
        if not self.base_url or not self.api_key:
            raise ValueError("BACKLOT_BASE_URL and BACKLOT_API_KEY are required")

    def request(self, method: str, path: str, **kwargs) -> Any:
        response = httpx.request(
            method,
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=kwargs.pop("timeout", 330),
            follow_redirects=True,
            **kwargs,
        )
        response.raise_for_status()
        return response.json()

    def workspace(self, name: str = "default") -> dict[str, Any]:
        workspaces = self.request("GET", "/workspaces")
        return workspaces[0] if workspaces else self.request(
            "POST", "/workspaces", json={"name": name}
        )

    def computers(self) -> list[dict[str, Any]]:
        return self.request("GET", "/computers")


class Computer:
    def __init__(
        self,
        computer_id: str | None = None,
        *,
        ram: int = 4,
        cpu: int = 1,
        name: str = "Backlot computer",
        workspace_id: str | None = None,
        resolution: str = "1280x720x24",
        idle_timeout_minutes: int = 30,
        template_ref: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ):
        self.client = Backlot(base_url, api_key)
        if computer_id:
            self.data = self.client.request("GET", f"/computers/{computer_id}")
        else:
            workspace_id = workspace_id or self.client.workspace()["id"]
            self.data = self.client.request(
                "POST",
                "/computers",
                json={
                    "workspace_id": workspace_id,
                    "name": name,
                    "ram": ram,
                    "cpu": cpu,
                    "resolution": resolution,
                    "idle_timeout_minutes": idle_timeout_minutes,
                    "template_ref": template_ref,
                },
            )

    @property
    def id(self) -> str:
        return self.data["id"]

    def refresh(self) -> dict[str, Any]:
        self.data = self.client.request("GET", f"/computers/{self.id}")
        return self.data

    def start(self) -> dict[str, Any]:
        self.data = self.client.request("POST", f"/computers/{self.id}/start")
        return self.data

    def stop(self) -> dict[str, Any]:
        self.data = self.client.request("POST", f"/computers/{self.id}/stop")
        return self.data

    def restart(self) -> dict[str, Any]:
        self.data = self.client.request("POST", f"/computers/{self.id}/restart")
        return self.data

    def delete(self) -> dict[str, Any]:
        return self.client.request("DELETE", f"/computers/{self.id}")

    def screenshot(self) -> str:
        return self.client.request("GET", f"/computers/{self.id}/screenshot")["screenshot"]

    def save_screenshot(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(self.screenshot()))
        return target

    def click(
        self, x: int, y: int, button: str = "left", double: bool = False
    ) -> dict[str, Any]:
        return self.client.request(
            "POST",
            f"/computers/{self.id}/click",
            json={"x": x, "y": y, "button": button, "double": double},
        )

    def drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration: float = 0.5,
    ) -> dict[str, Any]:
        return self.client.request(
            "POST",
            f"/computers/{self.id}/drag",
            json={
                "start_x": start_x,
                "start_y": start_y,
                "end_x": end_x,
                "end_y": end_y,
                "duration": duration,
            },
        )

    def type(self, text: str) -> dict[str, Any]:
        return self.client.request(
            "POST", f"/computers/{self.id}/type", json={"text": text}
        )

    def key(self, key: str) -> dict[str, Any]:
        return self.client.request(
            "POST", f"/computers/{self.id}/key", json={"key": key}
        )

    def scroll(self, direction: str, amount: int = 3) -> dict[str, Any]:
        return self.client.request(
            "POST",
            f"/computers/{self.id}/scroll",
            json={"direction": direction, "amount": amount},
        )

    def wait(self, seconds: float) -> dict[str, Any]:
        return self.client.request(
            "POST", f"/computers/{self.id}/wait", json={"seconds": seconds}
        )

    def bash(self, command: str, timeout: float = 30) -> dict[str, Any]:
        return self.client.request(
            "POST",
            f"/computers/{self.id}/bash",
            json={"command": command, "timeout": timeout},
        )

    def exec(self, code: str, timeout: float = 30) -> dict[str, Any]:
        return self.client.request(
            "POST",
            f"/computers/{self.id}/exec",
            json={"code": code, "timeout": timeout},
        )

    def process(
        self, argv: list[str], stdin: str = "", timeout: float = 30
    ) -> dict[str, Any]:
        return self.client.request(
            "POST",
            f"/computers/{self.id}/process",
            json={"argv": argv, "stdin": stdin, "timeout": timeout},
        )

    def vnc_url(self) -> str:
        return self.client.request("GET", f"/computers/{self.id}/vnc-password")["url"]

    def app_url(self, port: int) -> str:
        """A browser-reachable URL for a web app inside the machine. Never cache it."""
        return self.client.request(
            "GET", f"/computers/{self.id}/app-url", params={"port": port}
        )["url"]


def emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="backlot")
    sub = root.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--name", default="Backlot computer")
    create.add_argument("--ram", type=int, default=4, choices=[4, 8, 16, 32, 64])
    create.add_argument("--cpu", type=int, default=1, choices=[1, 2, 4, 8, 16])
    create.add_argument("--resolution", default="1280x720x24")
    create.add_argument("--workspace-id")
    sub.add_parser("ls")
    for command in ("start", "stop", "vnc-url", "rm"):
        item = sub.add_parser(command)
        item.add_argument("computer_id")
    app = sub.add_parser("app-url")
    app.add_argument("computer_id")
    app.add_argument("--port", type=int, required=True)
    key = sub.add_parser("key-create")
    key.add_argument("name")
    key.add_argument("--workspace-id", required=True)
    revoke = sub.add_parser("key-revoke")
    revoke.add_argument("key_id")
    template = sub.add_parser("template-build")
    template.add_argument("path")
    return root


def main() -> None:
    args = parser().parse_args()
    client = Backlot()
    if args.command == "create":
        emit(
            Computer(
                ram=args.ram,
                cpu=args.cpu,
                name=args.name,
                resolution=args.resolution,
                workspace_id=args.workspace_id,
            ).data
        )
    elif args.command == "ls":
        emit(client.computers())
    elif args.command == "template-build":
        spec = yaml.safe_load(Path(args.path).read_text())
        emit(client.request("POST", "/templates/build", json=spec, timeout=900))
    elif args.command == "key-create":
        emit(
            client.request(
                "POST",
                "/api-keys",
                json={"name": args.name, "workspace_id": args.workspace_id},
            )
        )
    elif args.command == "key-revoke":
        emit(client.request("DELETE", f"/api-keys/{args.key_id}"))
    else:
        computer = Computer(args.computer_id)
        if args.command == "start":
            emit(computer.start())
        elif args.command == "stop":
            emit(computer.stop())
        elif args.command == "vnc-url":
            print(computer.vnc_url())
        elif args.command == "app-url":
            print(computer.app_url(args.port))
        elif args.command == "rm":
            emit(computer.delete())
