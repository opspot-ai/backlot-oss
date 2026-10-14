# Synthetic API-contract tests using local fixtures only.
from __future__ import annotations

import base64
import hashlib
import importlib.util
import inspect
import json
import re
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import backlot.agent as desktop_agent
from backlot.client import Computer
from fastapi import HTTPException
from fastapi.testclient import TestClient
from modal.exception import ConnectionError as ModalConnectionError
from modal.exception import ConflictError, NotFoundError

REPO = Path(__file__).resolve().parents[1]

BOOTSTRAP = "backlot_test_bootstrap_key"
AUTH = {"Authorization": f"Bearer {BOOTSTRAP}"}
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n").decode()
ACTIONS = [
    ("GET", "screenshot", None),
    ("POST", "click", {"x": 10, "y": 20, "button": "left", "double": False}),
    (
        "POST",
        "drag",
        {"start_x": 0, "start_y": 0, "end_x": 5, "end_y": 5, "duration": 0.1},
    ),
    ("POST", "type", {"text": "hi"}),
    ("POST", "key", {"key": "Return"}),
    ("POST", "scroll", {"direction": "down", "amount": 3}),
    ("POST", "wait", {"seconds": 0}),
    ("POST", "bash", {"command": "true", "timeout": 30}),
    ("POST", "exec", {"code": "print(1)", "timeout": 30}),
    ("POST", "process", {"argv": ["printf", "%s"], "stdin": "private", "timeout": 30}),
]


@pytest.fixture
def control(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKLOT_DB_PATH", str(tmp_path / "backlot.db"))
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    import backlot.server as server

    def fake_start(computer_id: str, *, implicit: bool = True):
        # Mirrors the real signature, including the keyword-only `implicit`
        # flag, so a call site that forgets to mark itself explicit fails here
        # the same way it would in production instead of passing silently.
        # Recorded so a test can assert HOW a boot was reached, not just that
        # one happened.
        fake_start.calls.append({"computer_id": computer_id, "implicit": implicit})
        timestamp = server.now()
        server.execute(
            """
            UPDATE computers SET status = 'running', sandbox_id = 'sb_test',
                agent_url = 'http://example.invalid', agent_token = 'agent-token',
                vnc_url = 'http://example.invalid', vnc_token = 'vnc-token',
                vnc_password = 'password', started_at = ?, last_active_at = ?,
                expires_at = ? WHERE id = ?
            """,
            (timestamp, timestamp, timestamp + 3600, computer_id),
        )
        return server.get_computer(computer_id)

    def fake_stop(computer_id: str):
        server.execute(
            """
            UPDATE computers SET status = 'stopped', snapshot_image_id = 'im_snapshot',
                sandbox_id = NULL, agent_url = NULL, agent_token = NULL,
                vnc_url = NULL, vnc_token = NULL, vnc_password = NULL
            WHERE id = ?
            """,
            (computer_id,),
        )
        return server.get_computer(computer_id)

    def fake_agent(_computer_id, action, body=None, method="POST", *, computer=None):
        if action == "screenshot":
            return {"screenshot": PNG}
        return {"success": True, "action": action, "body": body, "method": method}

    fake_start.calls = []
    monkeypatch.setattr(server, "start_runtime", fake_start)
    monkeypatch.setattr(server, "stop_runtime", fake_stop)
    monkeypatch.setattr(server, "agent_request", fake_agent)
    monkeypatch.setattr(server, "terminate_runtime", lambda _: None)
    monkeypatch.setattr(server, "clone_snapshot", lambda _: "im_clone")
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: SimpleNamespace(returncode=None),
    )
    with TestClient(server.make_api()) as client:
        yield server, client


def workspace(client: TestClient, name: str = "test") -> dict:
    response = client.post("/workspaces", headers=AUTH, json={"name": name})
    assert response.status_code == 200, response.text
    return response.json()


def computer(client: TestClient, workspace_id: str | None = None) -> dict:
    workspace_id = workspace_id or workspace(client)["id"]
    response = client.post(
        "/computers",
        headers=AUTH,
        json={"workspace_id": workspace_id, "name": "test", "ram": 4, "cpu": 1},
    )
    assert response.status_code == 200, response.text
    return response.json()


def template_registration_body() -> dict:
    return {
        "ref": "probe/existing-image@1.0.0",
        "image_id": "im_existing",
        "name": "Existing image",
        "purpose": "An already-built operator image.",
        "hardware": {
            "cpu": 1,
            "ram": 4,
            "resolution": "1280x720x24",
            "idle_timeout_minutes": 30,
        },
    }


def stopped_computer(control, name: str = "binding"):
    _, client = control
    ws = workspace(client, name)
    machine = computer(client, ws["id"])
    stopped = client.post(f"/computers/{machine['id']}/stop", headers=AUTH)
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["status"] == "stopped"
    assert stopped.json()["sandbox_id"] is None
    return ws, stopped.json()


def binding_body(server, machine: dict, **changes) -> dict:
    body = {
        "template_ref": server.CURATED_TEMPLATE_REF,
        "expected_workspace_id": machine["workspace_id"],
        "expected_template_ref": machine.get("template_ref"),
        "expected_snapshot_image_id": machine.get("snapshot_image_id"),
    }
    body.update(changes)
    return body


def test_bearer_is_required(control):
    _, client = control
    assert client.get("/computers").status_code == 401


def test_workspace_crud(control):
    _, client = control
    created = workspace(client)
    assert client.get("/workspaces", headers=AUTH).json()[0]["id"] == created["id"]
    assert client.get(f"/projects/{created['id']}", headers=AUTH).status_code == 200
    assert client.delete(f"/workspaces/{created['id']}", headers=AUTH).json()["deleted"]


def test_computer_create_list_get(control):
    _, client = control
    created = computer(client)
    assert created["status"] == "running"
    assert created["computer_id"] == created["id"]
    assert client.get("/computers", headers=AUTH).json()[0]["id"] == created["id"]
    assert client.get(f"/computers/{created['id']}", headers=AUTH).status_code == 200


@pytest.mark.parametrize(("method", "action", "body"), ACTIONS)
def test_all_action_shapes(control, method, action, body):
    _, client = control
    machine = computer(client)
    response = client.request(
        method,
        f"/computers/{machine['id']}/{action}",
        headers=AUTH,
        json=body,
    )
    assert response.status_code == 200, response.text


def test_process_passes_private_input_on_stdin_without_a_shell(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(desktop_agent.subprocess, "run", fake_run)
    client = TestClient(desktop_agent.app)
    response = client.post(
        "/process",
        headers={
            "x-verified-user-data": json.dumps(
                {"purpose": "agent", "computer_id": "computer_test"}
            )
        },
        json={
            "argv": ["sample agent runtime", "agent", "--message-file", "/dev/stdin"],
            "stdin": "test-contact-01@example.invalid",
            "timeout": 30,
        },
    )

    assert response.status_code == 200, response.text
    assert captured["argv"] == ["sample agent runtime", "agent", "--message-file", "/dev/stdin"]
    assert captured["kwargs"]["input"] == "test-contact-01@example.invalid"
    assert captured["kwargs"].get("shell") is None


def test_wait_rejects_out_of_range(control):
    _, client = control
    machine = computer(client)
    response = client.post(
        f"/computers/{machine['id']}/wait",
        headers=AUTH,
        json={"seconds": 61},
    )
    assert response.status_code == 422


def test_workspace_scoped_keys_are_symmetric(control):
    """Two workspace keys see only own resources; cross-scope ops are 403."""
    server, client = control
    assert (
        client.post("/api-keys", headers=AUTH, json={"name": "missing-ws"}).status_code
        == 422
    )
    bootstrap = server.one(
        "SELECT id FROM api_keys WHERE workspace_id IS NULL LIMIT 1"
    )
    assert bootstrap is not None
    assert client.delete(f"/api-keys/{bootstrap['id']}", headers=AUTH).status_code == 404

    left_ws = workspace(client, "left")
    right_ws = workspace(client, "right")
    left_pc = computer(client, left_ws["id"])
    right_pc = computer(client, right_ws["id"])
    for machine in (left_pc, right_pc):
        stopped = client.post(f"/computers/{machine['id']}/stop", headers=AUTH)
        assert stopped.status_code == 200, stopped.text
        assert stopped.json().get("snapshot_image_id")

    left_key = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "left", "workspace_id": left_ws["id"]},
    ).json()
    right_key = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "right", "workspace_id": right_ws["id"]},
    ).json()
    left_auth = {"Authorization": f"Bearer {left_key['key']}"}
    right_auth = {"Authorization": f"Bearer {right_key['key']}"}

    def ids(path: str, headers: dict) -> list[str]:
        return [row["id"] for row in client.get(path, headers=headers).json()]

    assert ids("/workspaces", left_auth) == [left_ws["id"]]
    assert ids("/workspaces", right_auth) == [right_ws["id"]]
    assert ids("/computers", left_auth) == [left_pc["id"]]
    assert ids("/computers", right_auth) == [right_pc["id"]]

    def forbid(headers: dict, method: str, path: str, body: dict | None = None) -> None:
        response = client.request(method, path, headers=headers, json=body)
        assert response.status_code == 403, response.text
        assert response.json()["detail"]["code"] == "workspace_scope_mismatch"

    sides = (
        (left_auth, right_ws, right_pc, right_key),
        (right_auth, left_ws, left_pc, left_key),
    )
    for auth, other_ws, other_pc, other_key in sides:
        forbid(auth, "GET", f"/workspaces/{other_ws['id']}")
        forbid(auth, "GET", f"/computers/{other_pc['id']}")
        forbid(auth, "DELETE", f"/computers/{other_pc['id']}")
        forbid(auth, "POST", "/clone", {"computer_id": other_pc["id"], "name": "x"})
        forbid(
            auth,
            "POST",
            "/api-keys",
            {"name": "nope", "workspace_id": other_ws["id"]},
        )
        forbid(auth, "DELETE", f"/api-keys/{other_key['id']}")

    for key in (left_key, right_key):
        revoked = client.delete(f"/api-keys/{key['id']}", headers=AUTH)
        assert revoked.status_code == 200, revoked.text
    for auth in (left_auth, right_auth):
        assert client.get("/computers", headers=auth).status_code == 401


def test_clone_resize_and_move(control):
    _, client = control
    first = workspace(client, "first")
    second = workspace(client, "second")
    machine = computer(client, first["id"])
    clone = client.post(
        "/clone",
        headers=AUTH,
        json={"computer_id": machine["id"], "name": "clone"},
    )
    assert clone.status_code == 200
    resized = client.patch(
        f"/computers/{machine['id']}/resize",
        headers=AUTH,
        json={"ram": 8},
    )
    assert resized.json()["ram"] == 8
    moved = client.patch(
        f"/computers/{machine['id']}/move",
        headers=AUTH,
        json={"workspace_id": second["id"]},
    )
    assert moved.json()["workspace_id"] == second["id"]


def completion() -> dict:
    return {
        "id": "chatcmpl_test",
        "object": "chat.completion",
        "created": 1,
        "model": "claude-sonnet-5",
        "thread_id": "thread_test",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "done"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


@pytest.mark.parametrize("stream", [False, True])
def test_openai_chat_envelope(control, monkeypatch, stream):
    server, client = control
    machine = computer(client)
    monkeypatch.setattr(server, "run_chat", lambda _: completion())
    response = client.post(
        "/v1/chat/completions",
        headers=AUTH,
        json={
            "model": "claude-sonnet-5",
            "messages": [{"role": "user", "content": "test"}],
            "computer_id": machine["id"],
            "stream": stream,
        },
    )
    assert response.status_code == 200
    if stream:
        assert "chat.completion.chunk" in response.text
        assert "data: [DONE]" in response.text
    else:
        assert response.json()["object"] == "chat.completion"


def test_template_schema_is_public(control):
    _, client = control
    response = client.get("/template-schema")
    assert response.status_code == 200
    assert response.json()["supported"] == [
        "hardware",
        "env",
        "secrets",
        "build.run",
        "files",
    ]


def test_no_orgo_reference_survives_on_any_public_surface():
    """the legacy provider is parked and Backlot replaced it. A dangling legacy-provider.invalid string on a public
    response is what makes the next reader believe the legacy provider is still wired in and
    reintroduce the assumption, which is how a sibling repo shipped a dead the legacy provider image
    reference on its money path.
    """
    source = (REPO / "backlot" / "server.py").read_text()
    # Prose explaining the replacement is fine; a live value returned to a caller is not.
    offenders = [
        line.strip()
        for line in source.splitlines()
        if "legacy-provider.invalid" in line.lower() and not line.strip().startswith("#")
    ]
    assert offenders == [], f"legacy-provider.invalid reachable in a response: {offenders}"


def test_snapshot_has_bounded_ttl_and_terminates(control, monkeypatch):
    """Snapshots must expire. modal 1.5.2 exposes no image delete, so ttl is the only
    reclamation lever and ttl=None would bill an abandoned workspace forever."""
    server, client = control
    machine = computer(client)
    row = server.get_computer(machine["id"])
    sandbox = SimpleNamespace()
    calls = {}

    def snapshot_filesystem(*, timeout, ttl):
        calls["timeout"] = timeout
        calls["ttl"] = ttl
        return SimpleNamespace(object_id="im_persistent")

    sandbox.snapshot_filesystem = snapshot_filesystem
    sandbox.terminate = lambda *, wait: calls.update(terminated=wait)
    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: sandbox)
    assert server.snapshot_running(row) == "im_persistent"
    assert calls == {"timeout": 120, "ttl": 2_592_000, "terminated": True}
    assert calls["ttl"] is not None

    monkeypatch.setenv("BACKLOT_SNAPSHOT_TTL_SECONDS", "7200")
    assert server.snapshot_ttl() == 7200
    monkeypatch.setenv("BACKLOT_SNAPSHOT_TTL_SECONDS", "5")
    assert server.snapshot_ttl() == 3_600, "a floor keeps a typo from wiping live disks"


def test_save_screenshot_creates_parent(tmp_path):
    machine = object.__new__(Computer)
    machine.screenshot = lambda: PNG
    target = tmp_path / "receipts" / "proof.png"
    assert machine.save_screenshot(target) == target
    assert target.read_bytes().startswith(b"\x89PNG")


def test_package_exports_are_lazy():
    import backlot

    assert backlot.Computer is Computer


def test_drag_always_releases_mouse(monkeypatch):
    import backlot.agent as agent

    calls = []
    monkeypatch.setattr(
        agent,
        "run",
        lambda argv, timeout=30: calls.append(argv)
        or {"success": True, "exit_code": 0, "stdout": "", "stderr": ""},
    )
    monkeypatch.setattr(agent.time, "sleep", lambda _: None)
    result = agent.drag(
        agent.Drag(start_x=1, start_y=2, end_x=3, end_y=4),
        '{"purpose":"agent","computer_id":"test"}',
    )
    assert result["success"]
    assert calls[-1] == ["xdotool", "mouseup", "1"]


def test_openrouter_tool_loop_and_max_steps(control, monkeypatch):
    server, client = control
    machine = computer(client)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")

    tool = {
        "id": "call_test",
        "type": "function",
        "function": {
            "name": "computer",
            "arguments": '{"action":"wait","duration":0}',
        },
    }

    class Response:
        def __init__(self, message):
            self.message = message
            self.text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [{"message": self.message}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }

    responses = iter(
        [
            Response({"role": "assistant", "content": "", "tool_calls": [tool]}),
            Response({"role": "assistant", "content": "done"}),
        ]
    )
    monkeypatch.setattr(server.httpx, "post", lambda *args, **kwargs: next(responses))
    completed = server.run_chat(
        server.ChatCompletion(
            computer_id=machine["id"],
            messages=[{"role": "user", "content": "wait, then finish"}],
            max_steps=2,
        )
    )
    assert completed["choices"][0]["finish_reason"] == "stop"
    assert completed["choices"][0]["message"]["content"] == "done"
    assert completed["model"] == "openai/gpt-4.1-mini"
    assert completed["requested_model"] == "claude-sonnet-5"
    assert completed["provider_model"] == "openai/gpt-4.1-mini"

    monkeypatch.setattr(
        server.httpx,
        "post",
        lambda *args, **kwargs: Response(
            {"role": "assistant", "content": "", "tool_calls": [tool]}
        ),
    )
    capped = server.run_chat(
        server.ChatCompletion(
            computer_id=machine["id"],
            messages=[{"role": "user", "content": "keep working"}],
            max_steps=1,
        )
    )
    assert capped["choices"][0]["finish_reason"] == "length"


def test_chat_refreshes_runtime_after_its_opening_frame(control, monkeypatch):
    """A long tool loop does not reuse one row across a reap or rollover."""
    server, client = control
    machine = computer(client)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    screenshots = []
    actions = []

    def fake_desktop(computer_id, *, computer=None):
        screenshots.append(computer)
        return {"role": "user", "content": f"desktop:{computer_id}"}

    def fake_action(computer_id, arguments, *, computer=None):
        actions.append(computer)
        return {"success": True, "computer_id": computer_id, "arguments": arguments}

    tool = {
        "id": "call_refresh",
        "type": "function",
        "function": {"name": "computer", "arguments": '{"action":"wait"}'},
    }

    class Response:
        text = ""

        def __init__(self, message):
            self.message = message

        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": self.message}], "usage": {}}

    responses = iter(
        [
            Response({"role": "assistant", "content": "", "tool_calls": [tool]}),
            Response({"role": "assistant", "content": "done"}),
        ]
    )
    monkeypatch.setattr(server, "desktop_message", fake_desktop)
    monkeypatch.setattr(server, "computer_action", fake_action)
    monkeypatch.setattr(server.httpx, "post", lambda *args, **kwargs: next(responses))

    server.run_chat(
        server.ChatCompletion(
            computer_id=machine["id"],
            messages=[{"role": "user", "content": "work"}],
            max_steps=2,
        )
    )

    assert screenshots[0] is not None, "the opening liveness check feeds its first frame"
    assert screenshots[1:] == [None], "later frames must re-read the current runtime"
    assert actions == [None], "tool actions must re-read after model think time"


def test_desktop_image_includes_yaml_and_pinned_gitleaks():
    """Desktop image must ship python3-yaml and pinned Gitleaks v8.30.1."""
    source = (REPO / "backlot" / "server.py").read_text()
    block = source.split("desktop_image = (", 1)[1].split("runtime_lock", 1)[0]
    assert '"python3-yaml"' in block
    # A staff installer clones its own source, so a missing git aborts the install at
    # its last step with everything before it already done. Measured absent on a live
    # machine; nothing else in the probe was missing.
    assert '"git"' in block
    assert (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/"
        "gitleaks_8.30.1_linux_x64.tar.gz"
    ) in block
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in block


def test_desktop_image_includes_pinned_openclaw_for_employee_runtimes():
    source = (REPO / "backlot" / "server.py").read_text()
    block = source.split("desktop_image = (", 1)[1].split("runtime_lock", 1)[0]
    assert "https://example.invalid/install.sh" in block
    assert "0034898bce1ff687b25812e9807d89d34080d5569bbdacfae8816d115ccb9b89" in block
    assert "--version 2026.7.1-2" in block
    assert "--verify" in block
    assert "--node-version" not in block
    assert "--no-prompt --no-onboard" in block


def test_desktop_sh_clears_stale_x_lock_before_xvfb():
    """Restarted sandboxes leave /tmp/.X99-lock; desktop must clear it before Xvfb."""
    script = (REPO / "backlot" / "desktop.sh").read_text()
    match = re.search(
        r"rm\s+-f\s+/tmp/\.X99-lock\s+/tmp/\.X11-unix/X99",
        script,
    )
    assert match, "desktop.sh must remove stale Xvfb lock and socket"
    assert match.start() < script.index("Xvfb :99")


def test_u2_desktop_image_uses_minimal_xfce_components():
    source = (REPO / "backlot" / "server.py").read_text()
    block = source.split("desktop_image = (", 1)[1].split("runtime_lock", 1)[0]
    for package in ("xfwm4", "xfdesktop4", "xfce4-terminal", "thunar", "mousepad", "libglib2.0-bin"):
        assert f'"{package}"' in block
    for excluded in ("openbox", "pulseaudio", "alsa-utils", "nvidia", "cuda"):
        assert f'"{excluded}"' not in block


def test_u2_desktop_launchers_and_startup_contract():
    script = (REPO / "backlot" / "desktop.sh").read_text()
    for target in ("xfce4-terminal", "thunar /", "chromium", "mousepad"):
        assert target in script
    assert script.count('launcher "') == 4
    assert 'metadata::trusted true' in script
    assert "metadata::xfce-exe-checksum" in script
    assert "--no-first-run" in script
    assert "--disable-gpu" in script
    assert "about:blank" not in script
    assert script.index("Xvfb :99") < script.index("xfwm4 >")
    assert "xfdesktop --disable-wm-check" in script
    assert script.index("xfwm4 >") < script.index("xfdesktop --disable-wm-check")
    assert script.index("xfdesktop") < script.index("x11vnc -storepasswd")
    assert script.index("websockify") < script.index("uvicorn backlot.agent:app")


def _load_swap_test():
    path = REPO / "scripts" / "swap_test.py"
    spec = importlib.util.spec_from_file_location("backlot_swap_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_swap_proof_html_mirrors_save_into_document_title():
    """Save must update document.title so xdotool getwindowname can prove the UI."""
    module = _load_swap_test()
    assert "document.title=result.textContent" in module.HTML
    assert "Saved: '+proof.value" in module.HTML
    assert module.PROOF_TEXT == "BACKLOT-SWAP-PASS"


def test_swap_test_visible_title_proof_and_sanitized_receipt():
    """Swap proof asserts window titles; receipt records flags, not VNC secrets."""
    module = _load_swap_test()
    source = inspect.getsource(module.main)
    assert source.count("xdotool getactivewindow getwindowname") >= 2
    assert 'nine_actions_visible' in source
    assert "model_task_visible" in source
    assert "Saved: M2-ACTIONS-PASS" in source
    assert "Saved: {PROOF_TEXT}" in source
    assert 'vnc_connect_token_issued' in source
    # VNC URL may be held for handoff, but must not land in the JSON receipt.
    assert not re.search(
        r"""receipt\s*\[\s*['\"](?:vnc_url|api_key|vnc_password|vnc_token|agent_token)['\"]\s*\]""",
        source,
    )
    assert "json.dumps(receipt" in source


def _load_m3_proof():
    path = REPO / "scripts" / "m3_proof.py"
    spec = importlib.util.spec_from_file_location("backlot_m3_proof", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_m3_proof_deadline_cleanup_and_sanitized_receipt():
    """M3 proof must enforce deadline, nested stop-then-delete cleanup, no secrets."""
    module = _load_m3_proof()
    assert module.DEADLINE_SECONDS == 240
    source = inspect.getsource(module.main)
    assert 'choices=("idle", "rollover")' in source
    finally_blocks = [m.start() for m in re.finditer(r"\bfinally\s*:", source)]
    assert len(finally_blocks) >= 2, "nested finally required for stop then delete"
    stop_at = source.index("computer.stop()")
    delete_at = source.index("computer.delete()")
    assert finally_blocks[0] < stop_at < finally_blocks[1] < delete_at
    assert "DEADLINE_SECONDS" in source
    assert "BACKLOT_M3_RECEIPT" in inspect.getsource(module)
    assert not re.search(
        r"""receipt\s*\[\s*['\"](?:vnc_url|api_key|vnc_password|vnc_token|agent_token|agent_url)['\"]\s*\]""",
        source,
    )


def test_principal_and_supervise_reload_registry_before_db_reads():
    """Cross-container SQLite must reload the Modal Volume before authenticated/supervisor reads."""
    import backlot.server as server

    # Auth path: every Depends(principal) request reloads before api_keys lookup.
    principal_src = inspect.getsource(server.principal)
    assert "reload_registry()" in principal_src
    assert principal_src.index("reload_registry()") < principal_src.index("one(")

    # Supervisor path: EVERY tick reloads before scanning, not just the first.
    # The registry is one sqlite file on a Modal Volume, where last write wins and there
    # is no distributed locking, so the supervisor committing from a stale copy erases
    # whatever the web container wrote in between. Reloading once per supervise() left
    # that window open for the whole resident period.
    once_src = inspect.getsource(server.supervise_once)
    assert "reload_registry()" in once_src, "each tick must refresh before it reads"
    assert once_src.index("reload_registry()") < once_src.index("many(")
    supervise_src = inspect.getsource(server.supervise.get_raw_f())
    assert "reload_registry()" not in supervise_src, (
        "a single reload at the top is the stale window this test exists to prevent"
    )

    # reload_registry must actually hit the Volume when the DB lives on /data.
    reload_src = inspect.getsource(server.reload_registry)
    assert "registry_volume.reload()" in reload_src
    assert 'startswith("/data/")' in reload_src

    # Every registry connect() site must close the handle; bare `with connect()` leaves
    # SQLite files open and breaks Modal Volume reload across containers.
    for helper in (server.init_db, server.one, server.many, server.execute):
        src = inspect.getsource(helper)
        assert "closing(connect())" in src
        assert "with connect()" not in src


def test_action_route_awaits_agent_request_in_thread():
    """POST /computers/{id}/{action} must offload agent_request so the event loop stays free."""
    source = (REPO / "backlot" / "server.py").read_text()
    match = re.search(
        r"@api\.post\(\"/computers/\{computer_id\}/\{action\}\"\)\s*"
        r"async def action\([\s\S]*?return await asyncio\.to_thread\(\s*"
        r"agent_request, computer_id, action, body\.model_dump\(\)\s*\)",
        source,
    )
    assert match, "action route must await asyncio.to_thread(agent_request, ...)"


def test_yard_html_escapes_machine_name_via_dom_nodes():
    """YARD_HTML must assign machine names through safe DOM properties."""
    source = (REPO / "backlot" / "server.py").read_text()
    yard = source.split("YARD_HTML = ", 1)[1]
    assert "heading.textContent = machine.name" in yard
    assert "document.querySelector('#desktopName').textContent = machine.name" in yard
    assert "machinesRoot.replaceChildren()" in yard
    assert not re.search(r"machines(?:Root)?\.innerHTML\s*=", yard)


def test_yard_html_u1_dashboard_contract():
    """U1 exposes fleet creation/lifecycle without the parked chat surface."""
    source = (REPO / "backlot" / "server.py").read_text()
    yard = source.split("YARD_HTML = ", 1)[1]
    assert 'id="workspace"' in yard
    assert "document.querySelector('#workspace')" in yard
    assert "api('/workspaces')" in yard
    assert "Create and start" in yard
    assert "api('/computers', {method: 'POST'" in yard
    assert "lifecycle(machine, 'stop')" in yard
    assert "lifecycle(machine, 'start')" in yard
    assert "api(`/computers/${machine.id}/${action}`, {method: 'POST'})" in yard
    assert "api(`/computers/${machine.id}/screenshot`)" in yard
    assert "sessionStorage" not in yard
    assert "key.value = ''" in yard
    for banned in ("chat", "model", "agent"):
        assert not re.search(rf"\b{banned}\b", yard, re.I), banned


def test_yard_html_u2_desktop_canvas_contract():
    source = (REPO / "backlot" / "server.py").read_text()
    yard = source.split("YARD_HTML = ", 1)[1]
    assert '@api.get("/computer/{computer_id}"' in source
    assert '@api.get("/computer/{computer_id}/desktop"' in source
    assert 'id="commandForm"' in yard
    assert "api(`/computers/${machine.id}/bash`" in yard
    assert "screen.requestFullscreen()" in yard
    assert "classList.toggle('standalone'" in yard
    assert "@novnc/novnc@1.5.0/+esm" in yard
    assert "clipboardPasteFrom" in yard
    assert "_modal_connect_token" in yard
    assert "WebSocket" not in yard


def test_bootstrap_list_api_keys_metadata_only_and_revoke(control):
    """GET /api-keys is admin-only metadata for scoped keys; revoke drops the row."""
    _, client = control
    ws = workspace(client, "keys")
    created = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "scoped", "workspace_id": ws["id"]},
    )
    assert created.status_code == 200, created.text
    raw = created.json()["key"]
    key_id = created.json()["id"]

    listed = client.get("/api-keys", headers=AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    row = rows[0]
    assert row == {
        "id": key_id,
        "name": "scoped",
        "workspace_id": ws["id"],
        "created_at": row["created_at"],
    }
    payload = listed.text
    assert "key_hash" not in payload
    assert raw not in payload
    assert "key" not in row

    scoped_auth = {"Authorization": f"Bearer {raw}"}
    forbidden = client.get("/api-keys", headers=scoped_auth)
    assert forbidden.status_code == 403, forbidden.text
    assert forbidden.json()["detail"]["code"] == "workspace_scope_mismatch"

    revoked = client.delete(f"/api-keys/{key_id}", headers=AUTH)
    assert revoked.status_code == 200, revoked.text
    assert client.get("/api-keys", headers=AUTH).json() == []


def test_slow_lifecycle_work_does_not_block_unrelated_reads():
    """One global lock did two unrelated jobs and the slow one starved the fast one.

    stop_runtime holds its lock across a Modal snapshot, ~30s. one/many/execute take a
    lock for the milliseconds a statement runs. Sharing one lock meant a stop on machine
    B blocked a read on machine A for the whole snapshot: an `echo x` was measured at 46
    seconds behind an unrelated stop, logged here as a clean 200 while the caller saw a
    timeout.
    """
    import backlot.server as server

    assert "with lifecycle_lock_for(computer_id):" in inspect.getsource(server.stop_runtime)
    assert "with lifecycle_lock_for(computer_id):" in inspect.getsource(server.start_runtime)
    for reader in (server.one, server.many, server.execute):
        assert "with runtime_lock:" in inspect.getsource(reader), reader.__name__
        assert "lifecycle_lock_for" not in inspect.getsource(reader), (
            f"{reader.__name__} must not wait on slow lifecycle work"
        )

    # Different machines must get different locks; the same machine must share one, or
    # two concurrent stops of one computer could both snapshot it.
    a, b = server.lifecycle_lock_for("computer_a"), server.lifecycle_lock_for("computer_b")
    assert a is not b
    assert server.lifecycle_lock_for("computer_a") is a

    holder_started = threading.Event()
    release = threading.Event()

    def hold_machine_a():
        with server.lifecycle_lock_for("computer_a"):
            holder_started.set()
            release.wait(5)

    thread = threading.Thread(target=hold_machine_a, daemon=True)
    thread.start()
    assert holder_started.wait(2)
    try:
        # While machine A's lifecycle lock is held, machine B must be reachable at once.
        got_b = threading.Event()

        def touch_machine_b():
            with server.lifecycle_lock_for("computer_b"):
                got_b.set()

        other = threading.Thread(target=touch_machine_b, daemon=True)
        other.start()
        assert got_b.wait(2), "a stop on one machine must not block another machine"
    finally:
        release.set()
        thread.join(timeout=5)


def test_web_serves_concurrently_while_staying_one_writer():
    """Concurrency comes from more inputs per container, never more containers.

    max_containers=1 is what keeps the registry single-writer: one process, one mount.
    Raising containers instead would reintroduce the last-write-wins race that ate a
    template.
    """
    source = (REPO / "backlot" / "server.py").read_text()
    web_block = source[source.index("def web():") - 700 : source.index("def web():")]
    assert "max_containers=1" in web_block, "still exactly one writer"
    assert "@modal.concurrent(" in web_block, "one container must serve many requests"
    assert "volumes={\"/data\": registry_volume}" in web_block, "the writer holds the mount"


def test_supervisor_cannot_write_the_registry():
    """The registry is one sqlite file on a last-write-wins volume with no distributed
    locking. Two writers erased a successfully built template. The supervisor must not
    mount the volume at all, so the guarantee is structural rather than a convention
    someone can undo by adding one DB call.
    """
    import backlot.server as server

    source = (REPO / "backlot" / "server.py").read_text()
    supervise_decorator = source[
        source.index("@app.function(\n    image=control_image,\n    secrets=[backlot_secret],\n    schedule="):
        source.index("def supervise():")
    ]
    assert "volumes=" not in supervise_decorator, (
        "the supervisor must not mount the registry volume"
    )
    assert "max_containers=1" in source, "the web endpoint stays the single writer"

    body = inspect.getsource(server.supervise.get_raw_f())
    for writer in ("execute(", "supervise_once(", "init_db(", "stop_runtime(", "start_runtime("):
        assert writer not in body, f"supervisor must not call {writer} directly"
    assert "supervisor_tick(" in body, "it drives the endpoint instead"


def test_supervisor_drives_the_endpoint_and_stops_when_unreachable(monkeypatch):
    """It must not spin against a control plane it cannot reach: that burns a resident
    container and hides the outage."""
    import backlot.server as server

    calls = []

    def ok(url, headers, timeout):
        calls.append(url)
        return SimpleNamespace(
            raise_for_status=lambda: None, json=lambda: {"running": 0, "checked_at": 1}
        )

    monkeypatch.setattr(server.httpx, "post", ok)
    assert server.supervisor_tick("https://example.invalid/", "k") == 0
    assert calls == ["https://example.invalid/supervise"], "no double slash, right path"

    def boom(*_a, **_k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(server.httpx, "post", boom)
    monkeypatch.setenv("BACKLOT_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    slept: list[float] = []
    clock = {"t": 1_000_000}
    monkeypatch.setattr(server, "now", lambda: clock["t"])
    # Advance a fake clock. A stub that freezes time makes a spinning mutant hang
    # forever instead of failing, which is the bug hiding rather than the test catching
    # it. Third time this exact trap has appeared tonight.
    monkeypatch.setattr(
        server.time, "sleep",
        lambda s: (slept.append(s), clock.__setitem__("t", clock["t"] + s)),
    )
    server.supervise.get_raw_f()()
    assert slept == [], "an unreachable control plane must return, not spin"


def test_supervise_endpoint_is_admin_only(control):
    """It performs privileged lifecycle writes for every workspace."""
    server, client = control
    ws = workspace(client, "sup-auth")
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "s", "workspace_id": ws["id"]}
    ).json()

    assert client.post("/supervise").status_code == 401
    forbidden = client.post(
        "/supervise", headers={"Authorization": f"Bearer {scoped['key']}"}
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["code"] == "workspace_scope_mismatch"

    ok = client.post("/supervise", headers=AUTH)
    assert ok.status_code == 200, ok.text
    assert ok.json()["running"] == 0
    computer(client, ws["id"])
    assert client.post("/supervise", headers=AUTH).json()["running"] == 1


def test_supervisor_returns_immediately_when_the_fleet_is_empty(monkeypatch):
    """Waking every minute cost $0.05/hour with nothing running, about $36/month.

    There is nothing to reap when the fleet is empty, so no reap latency is traded away
    by sleeping. With a machine running it stays resident and keeps ticking, so
    customer-facing latency is unchanged.
    """
    import backlot.server as server

    monkeypatch.setenv("BACKLOT_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    clock = {"t": 1_000_000}
    slept: list[float] = []
    monkeypatch.setattr(server, "now", lambda: clock["t"])
    # A stubbed sleep that does not advance time would spin forever, hiding the bug
    # instead of failing on it. Advance a fake clock so the loop can terminate.
    monkeypatch.setattr(
        server.time, "sleep",
        lambda s: (slept.append(s), clock.__setitem__("t", clock["t"] + s)),
    )

    running = {"n": 0}
    monkeypatch.setattr(
        server.httpx, "post",
        lambda url, headers, timeout: SimpleNamespace(
            raise_for_status=lambda: None, json=lambda: {"running": running["n"]}
        ),
    )

    server.supervise.get_raw_f()()
    assert slept == [], "an empty fleet must not hold the container open"

    running["n"] = 1
    server.supervise.get_raw_f()()
    assert slept, "a running machine must keep the supervisor resident and ticking"
    assert set(slept) == {server.SUPERVISOR_TICK_SECONDS}
    assert sum(slept) <= server.SUPERVISOR_WAKE_MINUTES * 60, "must not overrun its window"
    assert server.SUPERVISOR_TICK_SECONDS == 60, "reap granularity unchanged when busy"
    assert server.SUPERVISOR_WAKE_MINUTES > 1, "empty-fleet wake is backed off"


def test_build_returns_logs_on_success_not_only_on_failure(tmp_path, monkeypatch):
    """Build output was reachable only through the error detail, so measuring anything
    about the build environment meant deliberately breaking the build."""
    server = isolated_server(tmp_path, monkeypatch)

    class FakeSandbox:
        def wait_until_ready(self, timeout):
            return None

        def exec(self, *_argv, timeout=None):
            return SimpleNamespace(
                stdout=SimpleNamespace(read=lambda: "MEM_MB=8192"),
                stderr=SimpleNamespace(read=lambda: ""),
                wait=lambda: 0,
            )

        def snapshot_filesystem(self, timeout, ttl):
            return SimpleNamespace(object_id="im_ok")

        def terminate(self, wait):
            return None

    monkeypatch.setattr(server.modal.Sandbox, "create", lambda *a, **k: FakeSandbox())
    result = server.build_template(
        server.TemplateBuild(
            ref="acme/logs@1.0.0",
            hardware={"ram": 8},
            build={"run": ["free -m"]},
        )
    )
    assert result["image_id"] == "im_ok"
    assert result["logs"][0]["command"] == "free -m"
    assert result["logs"][0]["exit_code"] == 0
    assert "MEM_MB=8192" in result["logs"][0]["output_tail"]


def test_disk_size_gb_is_accepted_but_never_applied(control):
    """KNOWN GAP, pinned so nobody mistakes it for working.

    disk_size_gb is accepted, stored, and shown in the UI as "Disk: N GiB", but
    modal.Sandbox.create has no disk parameter, so it has never done anything. Real
    sandbox disk measured at 511 GB regardless of what is requested. Same accepted-then-
    ignored shape as hardware and the ?workspace_id= filter; not rejected outright only
    because a consumer is mid-integration sending it today.
    """
    import inspect as _inspect

    server, client = control
    assert not any(
        key in _inspect.signature(server.modal.Sandbox.create).parameters
        for key in ("disk_size_gb", "disk", "disk_size")
    ), "if Modal ever adds a disk parameter, honour disk_size_gb and delete this test"

    ws = workspace(client, "disk")
    created = client.post(
        "/computers",
        headers=AUTH,
        json={"workspace_id": ws["id"], "name": "d", "ram": 4, "cpu": 1, "disk_size_gb": 20},
    )
    assert created.status_code == 200
    assert created.json()["disk_size_gb"] == 20, "stored and echoed back"
    source = (REPO / "backlot" / "server.py").read_text()
    start = source.index("def start_runtime")
    assert "disk_size_gb" not in source[start : start + 3000], (
        "disk_size_gb reaches no sandbox call; it is a label, not a setting"
    )


def test_desktop_runs_the_tenant_boot_hook_without_blocking_boot():
    """Processes do not survive stop/start, so a tenant runtime is dead after every idle
    reap, rollover and action auto-start. Nothing on the consumer side covers those.

    The hook must be fire and forget: a tenant script that hangs or fails must not stop
    the desktop or the agent coming up.
    """
    script = (REPO / "backlot" / "desktop.sh").read_text()
    assert "/opt/backlot/on-boot.sh" in script
    hook_at = script.index("backlot_hook=/opt/backlot/on-boot.sh")
    uvicorn_at = script.index("uvicorn backlot.agent:app")
    assert hook_at < uvicorn_at, "the hook must fire before the agent blocks"

    block = script[hook_at:uvicorn_at]
    assert "setsid nohup" in block, "must be detached so it survives and never blocks"
    assert block.rstrip().endswith("fi"), "hook launch is guarded by the existence check"
    assert "&" in block, "backgrounded"
    assert "/var/log/backlot-on-boot.log" in block, "tenant needs somewhere to look"
    assert "if [ -f " in block, "absent hook is not an error"
    assert "exit" not in block, "a failing hook must never fail the boot"


def test_command_timeout_says_it_was_a_timeout_and_how_to_raise_it(tmp_path, monkeypatch):
    """A command outrunning the 30s default returns 502, which reads as an
    infrastructure fault. It cost another team hours: their install step legitimately
    took longer, the neighbouring calls ran in 1.2s so it did not look like a queue,
    and the raw message was an httpx URL dump with no mention of a timeout.
    """
    server = isolated_server(tmp_path, monkeypatch)
    machine_id = seed_stopped_computer(server, None)
    server.execute(
        """
        UPDATE computers SET status = 'running', agent_url = 'http://example.invalid',
            agent_token = 't' WHERE id = ?
        """,
        (machine_id,),
    )

    def timed_out(*_a, **_k):
        response = httpx.Response(408, request=httpx.Request("POST", "http://example.invalid"))
        raise httpx.HTTPStatusError("boom", request=response.request, response=response)

    monkeypatch.setattr(server.httpx, "request", timed_out)

    with pytest.raises(HTTPException) as omitted:
        server.agent_request(machine_id, "bash", {"command": "sleep 45"})
    d = omitted.value.detail
    assert d["code"] == "command_timeout"
    assert d["timeout_seconds"] == server.DEFAULT_ACTION_TIMEOUT
    assert "not a queue" in d["hint"], "rule out the thing they will suspect first"
    assert str(server.MAX_ACTION_TIMEOUT) in d["hint"]
    assert "is the default" in d["hint"], "the caller may never have chosen this limit"
    assert "timeout_was_default" not in d, (
        "the model fills its default before this code runs, so that flag could only lie"
    )

    with pytest.raises(HTTPException) as explicit:
        server.agent_request(machine_id, "bash", {"command": "x", "timeout": 90})
    assert explicit.value.detail["timeout_seconds"] == 90


def test_agent_failure_distinguishes_a_timeout_from_an_unreachable_desktop(
    tmp_path, monkeypatch
):
    """Both are 502. Telling them apart by grepping the message for 408 is a string
    match on an error string, which breaks silently on any provider change."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id = seed_stopped_computer(server, None)
    server.execute(
        """
        UPDATE computers SET status = 'running', agent_url = 'http://example.invalid',
            agent_token = 't' WHERE id = ?
        """,
        (machine_id,),
    )

    def raise_http(status):
        def _request(*_a, **_k):
            response = httpx.Response(status, request=httpx.Request("POST", "http://example.invalid"))
            raise httpx.HTTPStatusError("boom", request=response.request, response=response)

        return _request

    monkeypatch.setattr(server.httpx, "request", raise_http(408))
    with pytest.raises(HTTPException) as timeout:
        server.agent_request(machine_id, "bash", {"command": "sleep 999"})
    assert timeout.value.status_code == 502
    assert timeout.value.detail["code"] == "command_timeout"
    assert timeout.value.detail["agent_status"] == 408

    def unreachable(*_a, **_k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(server.httpx, "request", unreachable)
    with pytest.raises(HTTPException) as down:
        server.agent_request(machine_id, "bash", {"command": "true"})
    assert down.value.detail["code"] == "agent_unreachable"
    assert down.value.detail["agent_status"] is None


def test_build_hardware_accepts_ram_and_rejects_unknown_keys(control):
    """Silently ignoring an unknown hardware key ran four real builds at the 2 GiB
    default and OOM killed every one, with nothing in the error mentioning memory.

    ComputerCreate takes ram in GiB, so hardware takes it too. Anything unrecognised is
    now a loud 422 rather than a default nobody asked for.
    """
    server, _ = control
    assert server.build_resources({"ram": 16}) == (1.0, 16384)
    assert server.build_resources({"memory_mib": 4096}) == (1.0, 4096)
    assert server.build_resources({"ram": 8, "cpu": 2}) == (2.0, 8192)
    assert server.build_resources({"memory_mib": 4096, "ram": 99}) == (1.0, 4096)
    assert server.build_resources({})[1] == server.BUILD_MEMORY_DEFAULT_MIB
    assert server.BUILD_MEMORY_DEFAULT_MIB >= 8192, "a real build needs more than 2 GiB"

    with pytest.raises(HTTPException) as unknown:
        server.build_resources({"ram": 8, "memroy": 99})
    assert unknown.value.status_code == 422
    assert unknown.value.detail["code"] == "unknown_hardware_key"
    assert unknown.value.detail["unknown"] == ["memroy"]

    for bad in ({"memory_mib": 1}, {"ram": 999}):
        with pytest.raises(HTTPException) as exc:
            server.build_resources(bad)
        assert exc.value.detail["code"] == "memory_out_of_range"
    with pytest.raises(HTTPException) as cpu_exc:
        server.build_resources({"cpu": 99})
    assert cpu_exc.value.detail["code"] == "cpu_out_of_range"


@pytest.mark.parametrize(
    "exit_code, output, expected",
    [
        # Direct kill of the command itself.
        (137, "some noise", "build_out_of_memory"),
        (1, "bash: line 1: 2630 Killed  pnpm install", "build_out_of_memory"),
        # The case that actually matters: a parallel build whose WORKER was killed.
        # The build tool catches it and exits 1, so the parent code is not 137 and the
        # kill survives only as text. Matching the parent's exit code alone calls this a
        # compile error and sends someone hunting a bug that is a memory ceiling.
        (1, "worker exited 137", "build_out_of_memory"),
        (1, "Killed\nELIFECYCLE Command failed", "build_out_of_memory"),
        # Node aborts rather than being killed, and prints a heap message.
        (
            134,
            "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory",
            "build_out_of_memory",
        ),
        (1, "tsc: Cannot allocate memory", "build_out_of_memory"),
        # File descriptor exhaustion looks like a memory failure and is not.
        (1, "Error: EMFILE: too many open files, open '/opt/app/x.ts'", "build_file_descriptor_limit"),
        # A genuine compile error must stay a compile error.
        (1, "ERR_PNPM_NO_LOCKFILE", "build_command_failed"),
        (2, "TS2345: Argument of type string is not assignable", "build_command_failed"),
    ],
)
def test_build_failure_names_an_oom_instead_of_saying_killed(
    tmp_path, monkeypatch, exit_code, output, expected
):
    """A bare 'Killed' reads like a crash inside the tool. The cause must be in the error."""
    server = isolated_server(tmp_path, monkeypatch)

    class FakeSandbox:
        def wait_until_ready(self, timeout):
            return None

        def exec(self, *_argv, timeout=None):
            return SimpleNamespace(
                stdout=SimpleNamespace(read=lambda: output),
                stderr=SimpleNamespace(read=lambda: ""),
                wait=lambda: exit_code,
            )

        def terminate(self, wait):
            return None

    monkeypatch.setattr(server.modal.Sandbox, "create", lambda *a, **k: FakeSandbox())
    spec = server.TemplateBuild(
        ref="acme/oom@1.0.0",
        hardware={"ram": 4},
        build={"run": ["pnpm install"]},
    )
    with pytest.raises(HTTPException) as exc:
        server.build_template(spec)
    assert exc.value.status_code == 422
    assert exc.value.detail["code"] == expected
    if expected == "build_out_of_memory":
        assert exc.value.detail["memory_mib"] == 4096
        assert "Raise it" in exc.value.detail["hint"]
        assert "raising cpu raises the memory floor" in exc.value.detail["hint"], (
            "parallel workers multiply peak memory; the next caller will add cpu first"
        )
        assert exc.value.detail["matched"], "say what triggered the classification"
    if expected == "build_file_descriptor_limit":
        assert exc.value.detail["ulimit_nofile"] == 1024
        assert "ulimit -n" in exc.value.detail["hint"]


def test_build_error_keeps_the_tail_where_the_cause_is(control):
    """A noisy build streams hundreds of progress lines. Truncating from the front keeps
    the spinner and throws away the error."""
    server, _ = control
    noisy = "\n".join([f"progress line {i}" for i in range(500)] + ["FATAL: the cause"])
    tail = server.tail_for_error(noisy)
    assert "FATAL: the cause" in tail
    assert "progress line 0" not in tail
    assert len(tail) <= 4000


def test_template_delete_removes_litter_but_protects_what_matters(control):
    """Seven permanent templates existed after one night of iteration, four of them
    probes. Every failed attempt is otherwise unreclaimable litter."""
    server, client = control
    server.execute(
        "INSERT INTO templates(ref, image_id, spec_json, created_at) VALUES (?, ?, ?, ?)",
        ("probe/litter@0.0.1", "im_litter", "{}", server.now()),
    )
    assert client.delete("/templates/probe/litter@0.0.1", headers=AUTH).json() == {
        "deleted": True,
        "ref": "probe/litter@0.0.1",
        "image_retained": True,
    }
    assert client.delete("/templates/probe/litter@0.0.1", headers=AUTH).status_code == 404

    curated = client.delete(f"/templates/{server.CURATED_TEMPLATE_REF}", headers=AUTH)
    assert curated.status_code == 409
    assert curated.json()["detail"]["code"] == "curated_template_protected"

    ws = workspace(client, "tpl")
    server.execute(
        "INSERT INTO templates(ref, image_id, spec_json, created_at) VALUES (?, ?, ?, ?)",
        ("probe/used@0.0.1", "im_used", "{}", server.now()),
    )
    client.post(
        "/computers",
        headers=AUTH,
        json={
            "workspace_id": ws["id"],
            "name": "uses-template",
            "ram": 4,
            "cpu": 1,
            "template_ref": "probe/used@0.0.1",
        },
    )
    in_use = client.delete("/templates/probe/used@0.0.1", headers=AUTH)
    assert in_use.status_code == 409, "deleting would orphan a machine's disk"
    assert in_use.json()["detail"]["code"] == "template_in_use"

    scoped_ws = workspace(client, "scoped-tpl")
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "s", "workspace_id": scoped_ws["id"]}
    ).json()
    forbidden = client.delete(
        "/templates/probe/used@0.0.1",
        headers={"Authorization": f"Bearer {scoped['key']}"},
    )
    assert forbidden.status_code == 403, "template delete is admin only"


def test_template_build_waits_for_the_sandbox_before_touching_it(tmp_path, monkeypatch):
    """Filesystem and exec calls race sandbox startup.

    Without the wait the first mkdir raised FilesystemExecutionError and the endpoint
    500'd in under two seconds. It went unnoticed because the curated template is seeded
    at init rather than built, so this path had never successfully run.
    """
    server = isolated_server(tmp_path, monkeypatch)
    order = []
    scripts = []

    class FakeSandbox:
        def wait_until_ready(self, timeout):
            order.append("wait")

        def mkdir(self, _path, parents=False):
            order.append("mkdir")
            raise AssertionError(
                "Modal's filesystem API fails against vm_runtime sandboxes; "
                "files must be written through exec"
            )

        def open(self, _path, _mode):
            order.append("open")
            raise AssertionError("files must be written through exec, not sandbox.open")

        def exec(self, *argv, timeout=None):
            order.append("exec")
            scripts.append(argv[-1])
            return SimpleNamespace(
                stdout=SimpleNamespace(read=lambda: ""),
                stderr=SimpleNamespace(read=lambda: ""),
                wait=lambda: 0,
            )

        def snapshot_filesystem(self, timeout, ttl):
            order.append("snapshot")
            return SimpleNamespace(object_id="im_built")

        def terminate(self, wait):
            order.append("terminate")

    created = {}

    def fake_create(*_a, **kwargs):
        created.update(kwargs)
        return FakeSandbox()

    monkeypatch.setattr(server.modal.Sandbox, "create", fake_create)
    spec = server.TemplateBuild(
        ref="acme/thing@1.0.0",
        files={"/etc/acme/env": "X=1\n"},
        build={"run": ["true"]},
    )
    built = server.build_template(spec)
    assert built["ref"] == "acme/thing@1.0.0"
    assert built["image_id"] == "im_built"
    assert built["logs"], "build logs must come back on success, not only on failure"
    assert order[0] == "wait", f"must wait before touching the sandbox, got {order}"
    assert "mkdir" not in order and "open" not in order, (
        f"filesystem API must not be used against a vm_runtime sandbox, got {order}"
    )
    assert order.index("wait") < order.index("exec")
    written = [s for s in scripts if "base64 -d" in s]
    assert len(written) == 1, "the file must be written through exec"
    assert "/etc/acme" in written[0], "parent directory created in the same script"
    import base64 as _b64
    assert _b64.b64encode(b"X=1\n").decode() in written[0], "content is base64, not shell-quoted"
    assert created.get("readiness_probe") is not None, (
        "wait_until_ready raises ConflictError without a probe, so the wait is only "
        "real if the sandbox was created with one"
    )


@pytest.mark.parametrize(
    "path, body",
    [
        ("/workspaces", {"name": "w", "nmae": "typo"}),
        ("/computers", {"workspace_id": "ws_x", "name": "c", "ram": 4, "memroy": 8}),
        ("/api-keys", {"name": "k", "workspace_id": "ws_x", "scope": "admin"}),
        ("/clone", {"computer_id": "computer_x", "name": "c", "snapshot": "im_x"}),
    ],
)
def test_unknown_request_fields_are_rejected_not_dropped(control, path, body):
    """Four silent-ignore defects came from an input accepted and never applied.

    Every request model was extra=ignore, so a typo was dropped and the request
    succeeded with a default nobody asked for. hardware["ram"] cost another team four
    OOM-killed builds exactly this way. A misspelled field is now a 422 naming it.
    """
    _, client = control
    response = client.post(path, headers=AUTH, json=body)
    assert response.status_code == 422, response.text
    assert "extra" in response.text.lower() or "not permitted" in response.text.lower()


def test_openai_surface_still_accepts_arbitrary_provider_fields(control):
    """ChatCompletion stays extra=allow deliberately: it is the OpenAI-compatible
    surface and SDK callers pass provider params Backlot does not model."""
    server, _ = control
    assert server.ChatCompletion.model_config.get("extra") == "allow"
    for name in ("WorkspaceCreate", "ComputerCreate", "ApiKeyCreate", "TemplateBuild"):
        assert getattr(server, name).model_config.get("extra") == "forbid", name


def test_workspace_records_who_created_it_from_the_key(control):
    """A shared account with no recorded owner means a sweep can only guess from names.

    sample organization's reconciler came one run from deleting another session's workspace
    because "delete anything no customer owns" cannot be answered without this. The
    owner is taken from the authenticating key, so a caller can neither spoof it nor
    forget to supply it.
    """
    server, client = control
    created = client.post("/workspaces", headers=AUTH, json={"name": "owned"})
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["created_by"] == "bootstrap", "the admin key's name is the owner label"
    assert body["created_by_key"].startswith("key_"), "and the exact key for an audit trail"

    # A scoped key stamps its own name, which is the consumer label an admin chose.
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "sample organization", "workspace_id": body["id"]}
    ).json()
    scoped_auth = {"Authorization": f"Bearer {scoped['key']}"}
    assert client.post(
        "/workspaces", headers=scoped_auth, json={"name": "nope"}
    ).status_code == 403, "workspace creation stays admin only"

    stored = server.one("SELECT created_by, created_by_key FROM workspaces WHERE id = ?",
                        (body["id"],))
    assert stored["created_by"] == "bootstrap"
    assert stored["created_by_key"] == body["created_by_key"]


def test_owner_cannot_be_supplied_by_the_caller(control):
    """If the body could set it, the field would be a suggestion rather than a record."""
    _, client = control
    spoofed = client.post(
        "/workspaces",
        headers=AUTH,
        json={"name": "spoof", "created_by": "somebody-else"},
    )
    assert spoofed.status_code == 422, "an owner in the body is rejected outright"
    honest = client.post("/workspaces", headers=AUTH, json={"name": "honest"}).json()
    assert honest["created_by"] == "bootstrap"


def test_workspaces_can_be_filtered_by_creator(control):
    """The point of recording it: a reconciler asks whose, instead of matching names."""
    _, client = control
    mine = client.post("/workspaces", headers=AUTH, json={"name": "a"}).json()
    client.post("/workspaces", headers=AUTH, json={"name": "b"})

    listed = client.get("/workspaces?created_by=bootstrap", headers=AUTH)
    assert listed.status_code == 200
    assert {w["id"] for w in listed.json()} >= {mine["id"]}
    assert all(w["created_by"] == "bootstrap" for w in listed.json())

    assert client.get("/workspaces?created_by=nobody", headers=AUTH).json() == [], (
        "an unknown creator owns nothing, rather than everything"
    )


def test_creator_filter_cannot_be_used_to_escape_scope(control):
    """A new query parameter is a new way to ask for someone else's rows.

    The filter exists so a reconciler can find its own workspaces. If it ignored scope, a
    scoped key could enumerate every workspace a shared creator label ever made, which is
    a cross-tenant leak on the endpoint added to prevent cross-tenant mistakes.
    """
    _, client = control
    mine = client.post("/workspaces", headers=AUTH, json={"name": "mine"}).json()
    theirs = client.post("/workspaces", headers=AUTH, json={"name": "theirs"}).json()
    assert mine["created_by"] == theirs["created_by"] == "bootstrap", (
        "same creator on both, so only scope can separate them"
    )
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "scoped", "workspace_id": mine["id"]}
    ).json()
    scoped_auth = {"Authorization": f"Bearer {scoped['key']}"}

    visible = client.get("/workspaces?created_by=bootstrap", headers=scoped_auth)
    assert visible.status_code == 200, visible.text
    ids = {w["id"] for w in visible.json()}
    assert ids == {mine["id"]}, f"scoped key must see only its own workspace, saw {ids}"
    assert theirs["id"] not in ids, "the filter must not become a scope bypass"

    # And the unfiltered list must agree, so the two paths cannot disagree about scope.
    assert {w["id"] for w in client.get("/workspaces", headers=scoped_auth).json()} == {
        mine["id"]
    }


def test_legacy_workspaces_report_no_owner_rather_than_a_wrong_one(tmp_path, monkeypatch):
    """Rows created before this existed have no owner, and must say so.

    Backfilling them with the migrating key would invent provenance and is exactly how a
    sweep ends up confidently deleting somebody else's data.
    """
    db = tmp_path / "legacy.db"
    monkeypatch.setenv("BACKLOT_DB_PATH", str(db))
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    import sqlite3 as legacy_sqlite

    with legacy_sqlite.connect(db) as connection:
        connection.executescript(
            """
            CREATE TABLE workspaces (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL
            );
            INSERT INTO workspaces VALUES ('ws_old', 'from-before', 1);
            """
        )

    import backlot.server as server

    server.init_db()
    row = server.one("SELECT * FROM workspaces WHERE id = 'ws_old'")
    assert row["created_by"] is None, "unknown provenance must read as unknown"
    assert row["created_by_key"] is None


def test_computers_filter_denies_a_foreign_workspace(control):
    """A scoped key asking for another workspace must be denied, not quietly answered.

    Returning the caller's own rows for someone else's workspace_id makes a reconcile
    read "nothing here" and boot the duplicate the reconcile exists to prevent. sample organization
    found this at the wire: path routes gave 403 while this one gave 200.
    """
    _, client = control
    mine = workspace(client, "mine")
    theirs = workspace(client, "theirs")
    computer(client, mine["id"])
    computer(client, theirs["id"])
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "scoped", "workspace_id": mine["id"]}
    ).json()
    scoped_auth = {"Authorization": f"Bearer {scoped['key']}"}

    crossed = client.get(f"/computers?workspace_id={theirs['id']}", headers=scoped_auth)
    assert crossed.status_code == 403, crossed.text
    assert crossed.json()["detail"]["code"] == "workspace_scope_mismatch"

    own = client.get(f"/computers?workspace_id={mine['id']}", headers=scoped_auth)
    assert own.status_code == 200
    assert [c["workspace_id"] for c in own.json()] == [mine["id"]]

    unfiltered = client.get("/computers", headers=scoped_auth)
    assert [c["workspace_id"] for c in unfiltered.json()] == [mine["id"]]

    admin = client.get(f"/computers?workspace_id={theirs['id']}", headers=AUTH)
    assert admin.status_code == 200
    assert [c["workspace_id"] for c in admin.json()] == [theirs["id"]]
    assert len(client.get("/computers", headers=AUTH).json()) == 2


def test_create_accepts_per_machine_env_and_never_returns_it(control):
    """Per-customer identity at boot. Values are secrets, so they leave through no response."""
    server, client = control
    ws = workspace(client, "env")
    secret = "signing-key-value-not-a-real-credential"
    created = client.post(
        "/computers",
        headers=AUTH,
        json={
            "workspace_id": ws["id"],
            "name": "with-env",
            "ram": 4,
            "cpu": 1,
            "env": {"EXAMPLE_CUSTOMER_ID": "cus_123", "EXAMPLE_SIGNING_KEY": secret},
        },
    )
    assert created.status_code == 200, created.text
    machine_id = created.json()["computer_id"]

    assert secret not in created.text
    assert "env_json" not in created.text
    for path in (f"/computers/{machine_id}", "/computers"):
        body = client.get(path, headers=AUTH)
        assert secret not in body.text, f"{path} leaked env"
        assert "env_json" not in body.text
    assert secret not in client.get(f"/workspaces/{ws['id']}/health", headers=AUTH).text

    stored = json.loads(server.get_computer(machine_id)["env_json"])
    assert stored == {
        "EXAMPLE_CUSTOMER_ID": "cus_123",
        "EXAMPLE_SIGNING_KEY": secret,
    }


@pytest.mark.parametrize(
    "env, reason",
    [
        ({"BACKLOT_VNC_PASSWORD": "x"}, "reserved"),
        ({"BACKLOT_WIDTH": "1"}, "reserved"),
        ({"not-a-var": "x"}, "not a valid variable name"),
        ({"2LEADING": "x"}, "not a valid variable name"),
        ({f"K{i}": "x" for i in range(65)}, "at most"),
        ({"BIG": "x" * 4097}, "exceeds"),
    ],
)
def test_env_validation_rejects_unsafe_input(control, env, reason):
    """A caller must not be able to overwrite the desktop's own VNC password."""
    _, client = control
    ws = workspace(client, "env-bad")
    response = client.post(
        "/computers",
        headers=AUTH,
        json={"workspace_id": ws["id"], "name": "bad", "ram": 4, "cpu": 1, "env": env},
    )
    assert response.status_code == 422, response.text
    assert reason in json.dumps(response.json())
    assert client.get("/computers", headers=AUTH).json() == [], "no row on rejection"


def test_env_reaches_the_sandbox_with_reserved_vars_winning(tmp_path, monkeypatch):
    """The real start path must hand the machine its identity, and never let a caller
    weaken the reserved display and VNC variables."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id = seed_stopped_computer(server, None)
    server.execute(
        "UPDATE computers SET env_json = ? WHERE id = ?",
        (json.dumps({"CUSTOMER_ID": "cus_1", "SPEND_CAP": "500"}), machine_id),
    )
    captured = {}

    class FakeSandbox:
        object_id = "sb_fake"

        def wait_until_ready(self, timeout):
            return None

        def create_connect_token(self, _payload, port):
            return SimpleNamespace(url=f"http://fake:{port}", token="t")

        def detach(self):
            return None

    def fake_create(*_args, **kwargs):
        captured.update(kwargs.get("env", {}))
        return FakeSandbox()

    monkeypatch.setattr(server.modal.Sandbox, "create", fake_create)
    server.start_runtime(machine_id)

    assert captured["CUSTOMER_ID"] == "cus_1"
    assert captured["SPEND_CAP"] == "500"
    assert captured["BACKLOT_WIDTH"] == "1280"
    assert captured["BACKLOT_VNC_PASSWORD"], "reserved vars still set"


def test_clone_of_a_running_computer_bounds_its_snapshot(tmp_path, monkeypatch):
    """Every snapshot path must be bounded, not just stop. modal exposes no image delete,
    so a clone taken with ttl=None is an unreclaimable image per clone.

    Uses an isolated module because the control fixture stubs clone_snapshot itself.
    """
    server = isolated_server(tmp_path, monkeypatch)
    machine_id = seed_stopped_computer(server, None)
    server.execute(
        "UPDATE computers SET status = 'running', sandbox_id = 'sb_live' WHERE id = ?",
        (machine_id,),
    )
    calls = {}

    def snapshot_filesystem(*, timeout, ttl):
        calls.update(timeout=timeout, ttl=ttl)
        return SimpleNamespace(object_id="im_clone")

    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _: SimpleNamespace(snapshot_filesystem=snapshot_filesystem),
    )
    assert server.clone_snapshot(server.get_computer(machine_id)) == "im_clone"
    assert calls["ttl"] == 2_592_000
    assert calls["ttl"] is not None


def test_status_reads_are_guaranteed_non_waking(control, monkeypatch):
    """Consumers poll customer status on a schedule. A read that boots a machine would
    bill on every poll, so the non-waking guarantee is contractual, not incidental.

    Actions deliberately DO auto-start, so this guarantee has to be pinned by a test
    rather than left to whoever next edits a read path.
    """
    server, client = control
    ws = workspace(client, "nonwaking")
    machine = computer(client, ws["id"])
    client.post(f"/computers/{machine['computer_id']}/stop", headers=AUTH)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a status read must never start a machine")

    monkeypatch.setattr(server, "start_runtime", forbidden)

    read = client.get(f"/computers/{machine['computer_id']}", headers=AUTH)
    assert read.status_code == 200 and read.json()["status"] == "stopped"
    assert client.get("/computers", headers=AUTH).status_code == 200
    assert client.get(f"/workspaces/{ws['id']}/health", headers=AUTH).status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get(f"/projects/{ws['id']}/health", headers=AUTH).status_code == 200

    assert (
        server.get_computer(machine["computer_id"])["status"] == "stopped"
    ), "the machine must still be off after every read path"


@pytest.mark.parametrize("padding", ["\n", " ", "\r\n", "\t", "  \n"])
def test_whitespace_in_a_stored_key_does_not_break_auth(control, padding):
    """Secret stores and copy-paste add trailing newlines.

    Hashing one in makes a correct key fail forever with no way to diagnose it, because
    the stored value cannot be read back to spot the whitespace. Reported by sample organization
    as the bug class that broke their clone URL, so it is closed on both sides here.
    """
    _, client = control
    padded = {"Authorization": f"Bearer {BOOTSTRAP}{padding}"}
    assert client.get("/api-keys", headers=padded).status_code == 200
    leading = {"Authorization": f"Bearer {padding}{BOOTSTRAP}"}
    assert client.get("/api-keys", headers=leading).status_code == 200
    assert client.get(
        "/api-keys", headers={"Authorization": f"Bearer {BOOTSTRAP}x"}
    ).status_code == 401, "trimming must not make a wrong key pass"


def test_bootstrap_seed_trims_a_padded_secret(tmp_path, monkeypatch):
    """A newline in the Modal secret must still seed the key operators actually hold."""
    monkeypatch.setenv("BACKLOT_DB_PATH", str(tmp_path / "padded.db"))
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", f"  {BOOTSTRAP}\n")
    import backlot.server as server

    server.init_db()
    with TestClient(server.make_api()) as client:
        assert client.get("/api-keys", headers=AUTH).status_code == 200


def test_workspace_computer_ceiling_is_a_safety_valve(control, monkeypatch, capfd):
    """A runaway loop bills OpSpot until per-tenant pass-through metering exists.

    This is an infrastructure ceiling, not a plan limit. It is per workspace, so one
    agency hitting it cannot deny service to another.
    """
    server, client = control
    monkeypatch.setenv("BACKLOT_WORKSPACE_COMPUTER_CEILING", "2")
    mine = workspace(client, "capped")
    theirs = workspace(client, "uncapped")

    computer(client, mine["id"])
    computer(client, mine["id"])
    refused = client.post(
        "/computers",
        headers=AUTH,
        json={"workspace_id": mine["id"], "name": "third", "ram": 4, "cpu": 1},
    )
    assert refused.status_code == 429, refused.text
    assert refused.json()["detail"] == {
        "code": "workspace_computer_ceiling",
        "ceiling": 2,
        "computers": 2,
    }
    assert "BACKLOT_CEILING_HIT" in capfd.readouterr().out

    assert client.post(
        "/computers",
        headers=AUTH,
        json={"workspace_id": theirs["id"], "name": "other", "ram": 4, "cpu": 1},
    ).status_code == 200, "one agency's ceiling must not deny service to another"

    assert server.workspace_computer_ceiling() == 2
    monkeypatch.delenv("BACKLOT_WORKSPACE_COMPUTER_CEILING")
    assert server.workspace_computer_ceiling() == 50, "default stays generous"
    monkeypatch.setenv("BACKLOT_WORKSPACE_COMPUTER_CEILING", "0")
    assert server.workspace_computer_ceiling() == 1, "a zero must not brick creation"


def test_init_migrates_a_pre_existing_database(tmp_path, monkeypatch):
    """The deployed registry predates error_reason/status_changed_at and holds live rows.

    CREATE TABLE IF NOT EXISTS silently skips an existing table, so without an explicit
    ALTER the first query after deploy would fail on the real volume.
    """
    db = tmp_path / "legacy.db"
    monkeypatch.setenv("BACKLOT_DB_PATH", str(db))
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    import sqlite3 as legacy_sqlite

    with legacy_sqlite.connect(db) as connection:
        connection.executescript(
            """
            CREATE TABLE workspaces (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL
            );
            CREATE TABLE computers (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                name TEXT NOT NULL, ram INTEGER NOT NULL, cpu INTEGER NOT NULL,
                disk_size_gb INTEGER, resolution TEXT NOT NULL, template_ref TEXT,
                idle_timeout_minutes INTEGER NOT NULL, status TEXT NOT NULL,
                sandbox_id TEXT, snapshot_image_id TEXT, agent_url TEXT, agent_token TEXT,
                vnc_url TEXT, vnc_token TEXT, vnc_password TEXT,
                created_at INTEGER NOT NULL, started_at INTEGER, last_active_at INTEGER,
                expires_at INTEGER
            );
            INSERT INTO workspaces VALUES ('ws_legacy', 'default', 1);
            INSERT INTO computers (id, workspace_id, name, ram, cpu, resolution,
                idle_timeout_minutes, status, created_at)
            VALUES ('computer_legacy', 'ws_legacy', 'old', 4, 1, '1280x720x24', 30, 'stopped', 1);
            """
        )

    import backlot.server as server

    server.init_db()
    row = server.get_computer("computer_legacy")
    assert row["error_reason"] is None
    assert row["status_changed_at"] is None
    assert row["stranded_since"] is None
    assert server.runtime_health(row, server.now())["healthy"] is True
    server.execute(
        """
        UPDATE computers SET status = 'error', sandbox_id = 'sb_legacy',
            error_reason = 'runtime_supervision_failed', status_changed_at = 123,
            stranded_since = NULL
        WHERE id = 'computer_legacy'
        """
    )
    server.init_db()  # a second boot must not re-add the columns
    migrated = server.get_computer("computer_legacy")
    assert migrated["status"] == "error"
    assert migrated["sandbox_id"] == "sb_legacy", "migration must preserve billing rows"
    assert migrated["stranded_since"] == 123, "existing failures need a stable onset"


def test_health_proves_the_registry_is_readable(control):
    """A literal 200 proves only that a container answered, so /health reads the registry."""
    _, client = control
    body = client.get("/health").json()
    assert body["ok"] is True
    assert body["registry"] == "readable"
    assert body["workspaces"] == 0
    workspace(client, "counted")
    assert client.get("/health").json()["workspaces"] == 1


def test_workspace_health_is_scoped_and_leaks_no_tokens(control):
    """sample workspace asks one question per agency, and never receives a credential."""
    server, client = control
    mine = workspace(client, "mine")
    theirs = workspace(client, "theirs")
    machine = computer(client, mine["id"])
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "scoped", "workspace_id": mine["id"]}
    ).json()
    scoped_auth = {"Authorization": f"Bearer {scoped['key']}"}

    healthy = client.get(f"/workspaces/{mine['id']}/health", headers=scoped_auth)
    assert healthy.status_code == 200, healthy.text
    body = healthy.json()
    assert body["healthy"] is True
    assert body["reason"] is None
    assert body["counts"]["total"] == 1
    assert body["computers"][0]["computer_id"] == machine["id"]

    payload = healthy.text
    for leak in ("agent_token", "vnc_token", "vnc_password", "sandbox_id", "snapshot_image_id"):
        assert leak not in payload

    crossed = client.get(f"/workspaces/{theirs['id']}/health", headers=scoped_auth)
    assert crossed.status_code == 403, crossed.text
    assert crossed.json()["detail"]["code"] == "workspace_scope_mismatch"
    assert client.get(f"/workspaces/{mine['id']}/health").status_code == 401


def test_workspace_health_surfaces_a_dead_vm_instead_of_reporting_running(control):
    """A row claiming 'running' past its sandbox timeout describes a machine that is gone."""
    server, client = control
    ws = workspace(client, "stale")
    machine = computer(client, ws["id"])
    client.post(f"/computers/{machine['id']}/start", headers=AUTH)
    server.execute(
        "UPDATE computers SET expires_at = ? WHERE id = ?",
        (server.now() - 60, machine["id"]),
    )

    body = client.get(f"/workspaces/{ws['id']}/health", headers=AUTH).json()
    assert body["healthy"] is False
    assert body["reason"] == "runtime_expired"
    assert body["counts"]["stale"] == 1
    assert body["computers"][0]["status"] == "running"
    assert body["computers"][0]["stale"] is True


def test_workspace_health_flags_a_stalled_idle_reaper(control):
    """Idle reaping stopping is a money leak, so it surfaces before the bill does."""
    server, client = control
    ws = workspace(client, "idle")
    machine = computer(client, ws["id"])
    client.post(f"/computers/{machine['id']}/start", headers=AUTH)
    stalled = server.now() - (30 * 60) - server.STALE_GRACE_SECONDS - 60
    server.execute(
        "UPDATE computers SET last_active_at = ?, expires_at = ? WHERE id = ?",
        (stalled, server.now() + 3600, machine["id"]),
    )

    body = client.get(f"/workspaces/{ws['id']}/health", headers=AUTH).json()
    assert body["healthy"] is False
    assert body["reason"] == "idle_reaper_stalled"
    assert body["computers"][0]["stale"] is True


def isolated_server(tmp_path, monkeypatch):
    """A module instance whose start_runtime is the real one, not the control stub."""
    monkeypatch.setenv("BACKLOT_DB_PATH", str(tmp_path / "isolated.db"))
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    path = REPO / "backlot" / "server.py"
    spec = importlib.util.spec_from_file_location("backlot_server_isolated", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec, per the importlib docs. Pydantic resolves a model's
    # annotations through sys.modules[cls.__module__], so an unregistered module leaves
    # forward refs like `Any` unresolvable and any model needing a rebuild raises
    # PydanticUserError. Overwritten on each call, so instances stay isolated.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.init_db()
    return module


def seed_stopped_computer(server, snapshot_image_id: str | None) -> str:
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, snapshot_image_id, created_at
        ) VALUES (?, ?, 'iso', 4, 1, '1280x720x24', 30, 'stopped', ?, ?)
        """,
        (machine_id, ws_id, snapshot_image_id, server.now()),
    )
    return machine_id


def seed_running_computer_with_claims(server) -> tuple[str, str, str]:
    """A registry-live row whose provider task can be made deterministically absent."""
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    snapshot_id = "im_last_intact_customer_disk"
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'liveness', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, snapshot_image_id, agent_url, agent_token,
            vnc_url, vnc_token, vnc_password, created_at, started_at,
            last_active_at, expires_at, template_ref
        ) VALUES (?, ?, 'liveness', 4, 1, '1280x720x24', 30, 'running',
            'sb_provider_missing', ?, 'https://example.invalid',
            'dead-agent-secret', 'https://example.invalid', 'dead-vnc-secret',
            'dead-vnc-password', ?, ?, ?, ?, ?)
        """,
        (
            machine_id,
            ws_id,
            snapshot_id,
            server.now() - 900,
            server.now() - 900,
            server.now(),
            server.now() + 86_400,
            server.CURATED_TEMPLATE_REF,
        ),
    )
    return machine_id, ws_id, snapshot_id


def assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id):
    row = server.get_computer(machine_id)
    assert row["id"] == machine_id
    assert row["workspace_id"] == ws_id
    assert row["template_ref"] == server.CURATED_TEMPLATE_REF
    assert row["snapshot_image_id"] == snapshot_id
    assert row["status"] == "error"
    assert row["error_reason"] == "provider_task_missing"
    assert row["stranded_since"] is None
    for field in (
        "sandbox_id",
        "agent_url",
        "agent_token",
        "vnc_url",
        "vnc_token",
        "vnc_password",
        "started_at",
        "expires_at",
    ):
        assert row[field] is None, f"dead runtime field {field} stayed attached"


def test_single_read_reconciles_a_typed_missing_provider_task(
    tmp_path, monkeypatch, capsys
):
    """The authoritative single-row read heals before it can report `running`."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, snapshot_id = seed_running_computer_with_claims(server)
    stale_row = server.get_computer(machine_id)
    lookups = []

    def provider_missing(sandbox_id):
        lookups.append(sandbox_id)
        raise NotFoundError("vendor wording is deliberately irrelevant")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", provider_missing)
    monkeypatch.setattr(
        server,
        "start_runtime",
        lambda *_args, **_kwargs: pytest.fail("liveness reconciliation booted a VM"),
    )
    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        first = client.get(f"/computers/{machine_id}", headers=AUTH)
        second = client.get(f"/computers/{machine_id}", headers=AUTH)

    assert first.status_code == 200, first.text
    assert first.json()["status"] == "error"
    assert first.json()["error_reason"] == "provider_task_missing"
    assert second.json() == first.json(), "a repeated read must be idempotent"
    assert lookups == ["sb_provider_missing"], "the healed row must not be re-probed"
    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)
    server.clear_unrecoverable_runtime(
        stale_row,
        event="BACKLOT_DEAD_SANDBOX_DETACHED",
        reason=server.ERROR_PROVIDER_TASK_MISSING,
    )
    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)
    output = capsys.readouterr().out
    assert output.count("BACKLOT_DEAD_SANDBOX_DETACHED") == 1
    assert "BACKLOT_DEAD_SANDBOX_CLEANUP_SKIPPED" in output
    assert "exception_type=NotFoundError" in output


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "vnc-password", None),
        ("GET", "app-url?port=3100", None),
        ("GET", "screenshot", None),
        (
            "POST",
            "chat",
            {
                "model": "backlot",
                "messages": [{"role": "user", "content": "hello"}],
            },
        ),
    ],
)
def test_consumer_routes_return_a_typed_result_without_serving_dead_claims_or_booting(
    tmp_path, monkeypatch, method, path, body
):
    """All four runtime-claim consumers stop at one shared provider authority."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, snapshot_id = seed_running_computer_with_claims(server)
    lookups = []
    boots = []
    dead_route_calls = []

    def provider_missing(sandbox_id):
        lookups.append(sandbox_id)
        raise NotFoundError("changed vendor text")

    def unexpected_boot(*_args, **_kwargs):
        boots.append(True)
        raise RuntimeError("liveness reconciliation booted a VM")

    def dead_route(*_args, **_kwargs):
        dead_route_calls.append(True)
        raise RuntimeError("a dead runtime route was called")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", provider_missing)
    monkeypatch.setattr(server.modal.Sandbox, "create", unexpected_boot)
    monkeypatch.setattr(
        server,
        "httpx",
        SimpleNamespace(
            HTTPError=httpx.HTTPError,
            HTTPStatusError=httpx.HTTPStatusError,
            request=dead_route,
            post=dead_route,
        ),
    )
    url = (
        "/v1/chat/completions"
        if path == "chat"
        else f"/computers/{machine_id}/{path}"
    )
    if path == "chat":
        body = {**body, "computer_id": machine_id}

    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        first = client.request(method, url, headers=AUTH, json=body)
        second = client.request(method, url, headers=AUTH, json=body)

    for response in (first, second):
        assert response.status_code == 409, response.text
        detail = response.json()["detail"]
        assert detail["code"] == "provider_task_missing"
        assert detail["retryable"] is True
        assert detail["computer_id"] == machine_id
        assert "dead-agent" not in response.text
        assert "dead-vnc" not in response.text
    assert lookups == ["sb_provider_missing"], "the terminal row must not be re-probed"
    assert boots == []
    assert dead_route_calls == []
    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)


def test_supervisor_reconciles_a_missing_provider_before_idle_or_expiry(
    tmp_path, monkeypatch
):
    """A fresh registry timestamp cannot hide a provider task that is already gone."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, snapshot_id = seed_running_computer_with_claims(server)
    lookups = []

    def provider_missing(sandbox_id):
        lookups.append(sandbox_id)
        raise NotFoundError("provider task is absent")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", provider_missing)

    assert server.supervise_once() == 1
    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)
    assert server.supervise_once() == 0
    assert lookups == ["sb_provider_missing"]


def test_terminal_provider_result_is_reconciled_without_message_matching(
    tmp_path, monkeypatch
):
    """`from_id` can return a terminal handle instead of raising NotFound."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, snapshot_id = seed_running_computer_with_claims(server)
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: SimpleNamespace(returncode=137),
    )

    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        response = client.get(f"/computers/{machine_id}", headers=AUTH)

    assert response.status_code == 200, response.text
    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)


def test_non_not_found_provider_lookup_is_unknown_and_single_read_survives(
    tmp_path, monkeypatch, capsys
):
    """A registry read falls back without classifying provider silence as death."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, _, snapshot_id = seed_running_computer_with_claims(server)
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: (_ for _ in ()).throw(
            ConflictError("Container terminated due to user termination request")
        ),
    )

    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        response = client.get(f"/computers/{machine_id}", headers=AUTH)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "running"
    row = server.get_computer(machine_id)
    assert row["status"] == "running"
    assert row["error_reason"] is None
    assert row["stranded_since"] is None
    assert row["sandbox_id"] == "sb_provider_missing"
    assert row["snapshot_image_id"] == snapshot_id
    assert row["agent_url"] == "https://example.invalid"
    output = capsys.readouterr().out
    assert "BACKLOT_SINGLE_READ_LIVENESS_UNKNOWN" in output
    assert "exception_type=ConflictError" in output
    assert "action=registry_unchanged" in output


def test_consumer_provider_lookup_unknown_returns_typed_retryable_result(
    tmp_path, monkeypatch, capsys
):
    """A consumer gets no dead route or credential when the provider cannot answer."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, _, snapshot_id = seed_running_computer_with_claims(server)
    dead_route_calls = []
    boots = []

    def provider_unreachable(_sandbox_id):
        raise ModalConnectionError("transient control-plane blip")

    def dead_route(*_args, **_kwargs):
        dead_route_calls.append(True)
        raise RuntimeError("a dead runtime route was called")

    def unexpected_boot(*_args, **_kwargs):
        boots.append(True)
        raise RuntimeError("provider reconciliation booted a VM")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", provider_unreachable)
    monkeypatch.setattr(server.modal.Sandbox, "create", unexpected_boot)
    monkeypatch.setattr(server.httpx, "request", dead_route)

    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        response = client.get(f"/computers/{machine_id}/screenshot", headers=AUTH)

    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail == {
        "code": "provider_unreachable",
        "computer_id": machine_id,
        "retryable": True,
        "retry_after": "retry_request",
        "message": (
            "The provider did not answer the liveness lookup. No runtime claims "
            "were changed; retry the request."
        ),
    }
    assert "dead-agent" not in response.text
    assert "dead-vnc" not in response.text
    assert dead_route_calls == []
    assert boots == []
    row = server.get_computer(machine_id)
    assert row["status"] == "running"
    assert row["error_reason"] is None
    assert row["stranded_since"] is None
    assert row["sandbox_id"] == "sb_provider_missing"
    assert row["snapshot_image_id"] == snapshot_id
    output = capsys.readouterr().out
    assert "BACKLOT_AGENT_LIVENESS_UNKNOWN" in output
    assert "exception_type=ConnectionError" in output


def test_one_unknown_supervisor_probe_does_not_strand_or_stop_a_healthy_machine(
    tmp_path, monkeypatch, capsys
):
    """One provider blip leaves every registry and lifecycle field untouched."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, _, _ = seed_running_computer_with_claims(server)
    before = dict(server.get_computer(machine_id))
    stopped = []

    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: (_ for _ in ()).throw(
            ModalConnectionError("transient control-plane blip")
        ),
    )
    monkeypatch.setattr(server, "stop_runtime", lambda cid: stopped.append(cid))

    assert server.supervise_once() == 1

    assert dict(server.get_computer(machine_id)) == before
    assert stopped == []
    output = capsys.readouterr().out
    assert "BACKLOT_SUPERVISOR_LIVENESS_UNKNOWN" in output
    assert "BACKLOT_SUPERVISION_ERROR" not in output


def test_sustained_unknown_provider_liveness_never_starts_abandonment(
    tmp_path, monkeypatch
):
    """Provider silence beyond 900s cannot terminate a healthy unsnapshotted disk."""
    server = isolated_server(tmp_path, monkeypatch)
    clock = {"t": 2_000_000}
    monkeypatch.setattr(server, "now", lambda: clock["t"])
    machine_id, _, _ = seed_running_computer_with_claims(server)
    provider_down = {"value": True}
    stopped = []
    terminated = []

    class LiveSandbox:
        returncode = None

        def terminate(self, wait=False):
            terminated.append("sb_provider_missing")

    def provider_lookup(_sandbox_id):
        if provider_down["value"]:
            raise ModalConnectionError("sustained control-plane degradation")
        return LiveSandbox()

    monkeypatch.setattr(server.modal.Sandbox, "from_id", provider_lookup)
    monkeypatch.setattr(server, "stop_runtime", lambda cid: stopped.append(cid))

    ticks = 0
    while ticks * server.SUPERVISOR_TICK_SECONDS <= server.STRANDED_TERMINATE_SECONDS:
        assert server.supervise_once() == 1
        clock["t"] += server.SUPERVISOR_TICK_SECONDS
        ticks += 1

    during = server.get_computer(machine_id)
    assert during["status"] == "running"
    assert during["error_reason"] is None
    assert during["stranded_since"] is None
    assert during["sandbox_id"] == "sb_provider_missing"
    assert stopped == []
    assert terminated == []

    provider_down["value"] = False
    assert server.supervise_once() == 1
    after = server.get_computer(machine_id)
    assert after["status"] == "running"
    assert after["error_reason"] is None
    assert after["stranded_since"] is None
    assert after["sandbox_id"] == "sb_provider_missing"
    assert stopped == []
    assert terminated == []


def test_non_not_found_terminate_error_remains_attached_for_followup_card(
    tmp_path, monkeypatch
):
    """implementation milestone residual: ConnectionError is retryable and remains out of this lease."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, _, snapshot_id = seed_running_computer_with_claims(server)

    class UnreachableAtTerminate:
        returncode = None

        def terminate(self, wait=False):
            assert wait is True
            raise ModalConnectionError("terminate control-plane blip")

    monkeypatch.setattr(
        server.modal.Sandbox, "from_id", lambda _sandbox_id: UnreachableAtTerminate()
    )

    with pytest.raises(ModalConnectionError, match="terminate control-plane blip"):
        server.terminate_runtime(server.get_computer(machine_id))

    row = server.get_computer(machine_id)
    assert row["status"] == "running"
    assert row["sandbox_id"] == "sb_provider_missing"
    assert row["snapshot_image_id"] == snapshot_id


def test_liveness_paths_do_not_use_assert_for_production_control_flow():
    """`python -O` cannot erase runtime-handle validation in production paths."""
    import backlot.server as server

    for routine in (
        server.snapshot_running,
        server.terminate_runtime,
        server.abandon_stranded,
        server.app_payload,
        server.clone_snapshot,
    ):
        assert "assert " not in inspect.getsource(routine), routine.__name__


def test_provider_missing_extends_the_existing_workspace_health_vocabulary(
    tmp_path, monkeypatch
):
    """Health reports the healed provider drift through `runtime_health`, not a side API."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, _ = seed_running_computer_with_claims(server)
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: (_ for _ in ()).throw(NotFoundError("missing")),
    )

    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        assert client.get(f"/computers/{machine_id}", headers=AUTH).status_code == 200
        health = client.get(f"/workspaces/{ws_id}/health", headers=AUTH)

    assert health.status_code == 200, health.text
    body = health.json()
    assert body["healthy"] is False
    assert body["reason"] == "provider_task_missing"
    assert body["counts"]["error"] == 1
    assert body["counts"]["stale"] == 1
    assert body["computers"][0]["stale"] is True


@pytest.mark.parametrize("operation", ["snapshot", "abandon"])
def test_from_id_not_found_is_caught_at_each_lifecycle_lookup(
    tmp_path, monkeypatch, operation
):
    """The provider lookup itself is inside the typed boundary at both old seams."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, snapshot_id = seed_running_computer_with_claims(server)
    if operation == "abandon":
        server.execute(
            """
            UPDATE computers SET status = 'error', error_reason = ?,
                status_changed_at = ?, stranded_since = ? WHERE id = ?
            """,
            (
                server.ERROR_SUPERVISION_FAILED,
                server.now(),
                server.now() - server.STRANDED_TERMINATE_SECONDS,
                machine_id,
            ),
        )
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: (_ for _ in ()).throw(NotFoundError("missing at lookup")),
    )

    if operation == "snapshot":
        server.snapshot_running(server.get_computer(machine_id))
    else:
        server.abandon_stranded(server.get_computer(machine_id))

    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)


def test_computer_list_does_not_fan_out_provider_liveness(tmp_path, monkeypatch):
    """Fleet listing is registry-only; single reads and the supervisor are authoritative."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, _, _ = seed_running_computer_with_claims(server)
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda *_args, **_kwargs: pytest.fail("GET /computers fanned out to Modal"),
    )

    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        response = client.get("/computers", headers=AUTH)

    assert response.status_code == 200, response.text
    assert response.json()[0]["id"] == machine_id


def test_every_provider_handle_lookup_uses_the_one_liveness_authority():
    """A new direct lookup would bypass atomic cleanup and reopen stale claims."""
    source = (REPO / "backlot" / "server.py").read_text()
    assert source.count("modal.Sandbox.from_id(") == 1


def test_clone_reconciles_a_missing_source_and_uses_its_last_intact_snapshot(
    tmp_path, monkeypatch
):
    """A stale source heals without booting and still clones its retained disk."""
    server = isolated_server(tmp_path, monkeypatch)
    machine_id, ws_id, snapshot_id = seed_running_computer_with_claims(server)
    monkeypatch.setattr(
        server.modal.Sandbox,
        "from_id",
        lambda _sandbox_id: (_ for _ in ()).throw(NotFoundError("missing source")),
    )
    monkeypatch.setattr(
        server.modal.Sandbox,
        "create",
        lambda *_args, **_kwargs: pytest.fail("clone reconciliation booted a VM"),
    )

    cloned_snapshot = server.clone_snapshot(server.get_computer(machine_id))

    assert cloned_snapshot == snapshot_id
    assert_provider_missing_cleanup(server, machine_id, ws_id, snapshot_id)


@pytest.mark.parametrize(
    "snapshot, message, expected",
    [
        ("im_gone", "image im_gone not found", "snapshot_expired"),
        ("im_here", "sandbox scheduling failed", "runtime_start_failed"),
        (None, "image im_gone not found", "runtime_start_failed"),
    ],
)
def test_failed_start_records_why(tmp_path, monkeypatch, snapshot, message, expected):
    """An agency whose office will not boot gets a reason, not a silent 'error'.

    An expired disk is only that when a snapshot was actually referenced, so a generic
    'not found' on a computer that never had one must not be blamed on retention.
    """
    server = isolated_server(tmp_path, monkeypatch)
    machine_id = seed_stopped_computer(server, snapshot)

    def boom(*_args, **_kwargs):
        raise RuntimeError(message)

    monkeypatch.setattr(server.modal.Sandbox, "create", boom)
    with pytest.raises(RuntimeError):
        server.start_runtime(machine_id)

    row = server.get_computer(machine_id)
    assert row["status"] == "error"
    assert row["error_reason"] == expected
    assert row["status_changed_at"] is not None
    health = server.runtime_health(row, server.now())
    assert health["healthy"] is False
    assert health["reason"] == expected


def test_health_reports_when_an_agency_disk_expires(control, monkeypatch):
    """disk_retained_until is the agency-visible deadline for an abandoned workspace."""
    server, client = control
    ws = workspace(client, "retention")
    machine = computer(client, ws["id"])
    stopped_at = server.now()
    server.execute(
        """
        UPDATE computers SET status = 'stopped', snapshot_image_id = 'im_snap',
            status_changed_at = ? WHERE id = ?
        """,
        (stopped_at, machine["id"]),
    )

    entry = client.get(f"/workspaces/{ws['id']}/health", headers=AUTH).json()["computers"][0]
    assert entry["healthy"] is True, "a stopped office is off, not broken"
    assert entry["disk_retained_until"] == stopped_at + server.snapshot_ttl()


def test_bootstrap_rotation_retires_the_previous_key(control, monkeypatch):
    """Re-seeding with a new secret retires the old bootstrap key and keeps scoped keys."""
    server, client = control
    ws = workspace(client, "rotate")
    created = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "scoped", "workspace_id": ws["id"]},
    )
    assert created.status_code == 200, created.text
    scoped_auth = {"Authorization": f"Bearer {created.json()['key']}"}
    assert client.get(f"/workspaces/{ws['id']}", headers=scoped_auth).status_code == 200

    rotated = "backlot_test_rotated_key"
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", rotated)
    server.init_db()

    assert client.get("/api-keys", headers=AUTH).status_code == 401
    rotated_auth = {"Authorization": f"Bearer {rotated}"}
    assert client.get("/api-keys", headers=rotated_auth).status_code == 200
    assert client.get(f"/workspaces/{ws['id']}", headers=scoped_auth).status_code == 200
    assert (
        len(
            server.many(
                "SELECT id FROM api_keys WHERE name = 'bootstrap' AND workspace_id IS NULL"
            )
        )
        == 1
    )


def test_bootstrap_rotation_keeps_scoped_key_named_bootstrap(control, monkeypatch):
    """Only the unscoped row is retired; a workspace key named 'bootstrap' survives."""
    server, client = control
    ws = workspace(client, "named")
    created = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "bootstrap", "workspace_id": ws["id"]},
    )
    assert created.status_code == 200, created.text
    scoped_auth = {"Authorization": f"Bearer {created.json()['key']}"}

    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", "backlot_test_rotated_again")
    server.init_db()

    assert client.get(f"/workspaces/{ws['id']}", headers=scoped_auth).status_code == 200


def test_bootstrap_reseed_is_idempotent(control):
    """Re-running init with an unchanged secret leaves exactly one usable bootstrap row."""
    server, client = control
    server.init_db()
    server.init_db()
    assert (
        len(
            server.many(
                "SELECT id FROM api_keys WHERE name = 'bootstrap' AND workspace_id IS NULL"
            )
        )
        == 1
    )
    assert client.get("/api-keys", headers=AUTH).status_code == 200


def test_yard_html_u3_workspace_admin_contract():
    """U3 admin: /admin, workspace+key management, one-time raw reveal, no key storage."""
    source = (REPO / "backlot" / "server.py").read_text()
    yard = source.split("YARD_HTML = ", 1)[1]
    assert '@api.get("/admin"' in source
    assert 'id="adminView"' in yard
    assert 'id="adminNav"' in yard
    assert "showAdmin" in yard
    assert "location.pathname === '/admin'" in yard
    assert 'id="workspaceCreateDialog"' in yard
    assert 'id="workspaceSettingsDialog"' in yard
    assert "api('/workspaces', {method: 'POST'" in yard
    assert "api(`/workspaces/${workspace.id}`, {method: 'DELETE'})" in yard
    assert 'id="keyCreateDialog"' in yard
    assert 'id="keyRevealDialog"' in yard
    assert "api('/api-keys', {method: 'POST'" in yard
    assert "api('/api-keys')" in yard
    assert "api(`/api-keys/${item.id}`, {method: 'DELETE'})" in yard
    assert "oneTimeKey.value = created.key" in yard
    assert "function closeKeyReveal()" in yard
    assert "oneTimeKey.value = ''" in yard
    assert "keyRevealDialog.addEventListener('close'" in yard
    assert "localStorage" not in yard
    assert "sessionStorage" not in yard
    assert not re.search(r"backlot_[A-Za-z0-9_-]{20,}", yard)
    assert 'id="confirmationDialog"' in yard
    assert "window.confirm" not in yard


def test_curated_template_list_scope_and_launch(control):
    """GET /templates is bootstrap-only; curated ref launches and persists template_ref."""
    server, client = control
    listed = client.get("/templates", headers=AUTH)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["ref"] == server.CURATED_TEMPLATE_REF
    assert row["name"] == "Linux desktop"
    assert row["purpose"] == server.CURATED_TEMPLATE_SPEC["purpose"]
    assert row["defaults"] == {
        "cpu": 1,
        "ram": 4,
        "disk_size_gb": None,
        "resolution": "1280x720x24",
        "idle_timeout_minutes": 30,
    }
    assert row["image_id"] is None
    assert server.CURATED_TEMPLATE_IMAGE_ID not in listed.text
    assert "__backlot_desktop__" not in listed.text

    ws = workspace(client, "templates")
    scoped = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "scoped", "workspace_id": ws["id"]},
    )
    assert scoped.status_code == 200, scoped.text
    forbidden = client.get(
        "/templates",
        headers={"Authorization": f"Bearer {scoped.json()['key']}"},
    )
    assert forbidden.status_code == 403, forbidden.text
    assert forbidden.json()["detail"]["code"] == "workspace_scope_mismatch"

    created = client.post(
        "/computers",
        headers=AUTH,
        json={
            "workspace_id": ws["id"],
            "name": "from-template",
            "ram": 4,
            "cpu": 1,
            "template_ref": server.CURATED_TEMPLATE_REF,
        },
    )
    assert created.status_code == 200, created.text
    payload = created.json()
    assert payload["template_ref"] == server.CURATED_TEMPLATE_REF
    stored = server.get_computer(payload["id"])
    assert stored["template_ref"] == server.CURATED_TEMPLATE_REF


def test_register_existing_template_persists_the_build_shape_without_modal(
    control, monkeypatch
):
    server, client = control
    assert "modal." not in inspect.getsource(server.register_template)

    def modal_was_touched(*_args, **_kwargs):
        pytest.fail("registering an existing image must not call a Modal image or sandbox API")

    monkeypatch.setattr(server.modal.Image, "from_id", modal_was_touched)
    monkeypatch.setattr(server.modal.Sandbox, "create", modal_was_touched)
    body = template_registration_body()
    response = client.post("/templates/register", headers=AUTH, json=body)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "ref": body["ref"],
        "image_id": body["image_id"],
        "name": body["name"],
        "purpose": body["purpose"],
        "defaults": {
            "cpu": 1,
            "ram": 4,
            "disk_size_gb": None,
            "resolution": "1280x720x24",
            "idle_timeout_minutes": 30,
        },
        "created_at": response.json()["created_at"],
    }
    stored = server.one("SELECT * FROM templates WHERE ref = ?", (body["ref"],))
    assert stored is not None
    equivalent_build = server.TemplateBuild(
        ref=body["ref"],
        name=body["name"],
        purpose=body["purpose"],
        hardware=body["hardware"],
    )
    assert stored["spec_json"] == equivalent_build.model_dump_json()


def test_register_identical_replay_is_200_and_executes_no_write(control):
    server, client = control
    body = template_registration_body()
    first = client.post("/templates/register", headers=AUTH, json=body)
    assert first.status_code == 200, first.text
    before = dict(server.one("SELECT * FROM templates WHERE ref = ?", (body["ref"],)))

    connection = server.connect()
    try:
        connection.executescript(
            """
            CREATE TRIGGER reject_template_reinsert
            BEFORE INSERT ON templates
            BEGIN SELECT RAISE(FAIL, 'idempotent replay attempted INSERT'); END;
            CREATE TRIGGER reject_template_update
            BEFORE UPDATE ON templates
            BEGIN SELECT RAISE(FAIL, 'registration attempted UPDATE'); END;
            CREATE TRIGGER reject_template_delete
            BEFORE DELETE ON templates
            BEGIN SELECT RAISE(FAIL, 'registration attempted DELETE'); END;
            """
        )
        connection.commit()
    finally:
        connection.close()

    replay = client.post("/templates/register", headers=AUTH, json=body)
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert dict(server.one("SELECT * FROM templates WHERE ref = ?", (body["ref"],))) == before


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ({"image_id": "im_different"}, "image_id"),
        ({"purpose": "A byte-different stored specification."}, "spec_json"),
    ],
    ids=("image-id", "spec-json"),
)
def test_register_conflicts_name_the_exact_different_field(control, change, field):
    server, client = control
    body = template_registration_body()
    assert client.post("/templates/register", headers=AUTH, json=body).status_code == 200
    before = dict(server.one("SELECT * FROM templates WHERE ref = ?", (body["ref"],)))
    changed = {**body, **change}

    conflict = client.post("/templates/register", headers=AUTH, json=changed)
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["detail"]["code"] == "template_registration_conflict"
    assert conflict.json()["detail"]["field"] == field
    assert dict(server.one("SELECT * FROM templates WHERE ref = ?", (body["ref"],))) == before


def test_register_rejects_bad_ref_grammar(control):
    server, client = control
    body = template_registration_body()
    body["ref"] = "Probe/Invalid@v1"
    response = client.post("/templates/register", headers=AUTH, json=body)
    assert response.status_code == 422, response.text
    assert server.one("SELECT ref FROM templates WHERE ref = ?", (body["ref"],)) is None


def test_register_is_admin_only(control):
    _, client = control
    ws = workspace(client, "register-scope")
    scoped = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "register-scope", "workspace_id": ws["id"]},
    ).json()
    response = client.post(
        "/templates/register",
        headers={"Authorization": f"Bearer {scoped['key']}"},
        json=template_registration_body(),
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "workspace_scope_mismatch"


def test_template_binding_forward_write_changes_only_template_ref(control):
    server, client = control
    _, machine = stopped_computer(control, "bind-forward")
    before = dict(server.get_computer(machine["id"]))

    response = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers=AUTH,
        json=binding_body(server, machine),
    )
    assert response.status_code == 200, response.text
    after = dict(server.get_computer(machine["id"]))
    assert after["template_ref"] == server.CURATED_TEMPLATE_REF
    assert {k: v for k, v in after.items() if k != "template_ref"} == {
        k: v for k, v in before.items() if k != "template_ref"
    }


def test_template_binding_null_is_the_guarded_rollback(control):
    server, client = control
    _, machine = stopped_computer(control, "bind-rollback")
    forward = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers=AUTH,
        json=binding_body(server, machine),
    )
    assert forward.status_code == 200, forward.text
    bound = forward.json()
    before_rollback = dict(server.get_computer(machine["id"]))

    rollback = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers=AUTH,
        json=binding_body(
            server,
            bound,
            template_ref=None,
            expected_template_ref=server.CURATED_TEMPLATE_REF,
        ),
    )
    assert rollback.status_code == 200, rollback.text
    after = dict(server.get_computer(machine["id"]))
    assert after["template_ref"] is None
    assert {k: v for k, v in after.items() if k != "template_ref"} == {
        k: v for k, v in before_rollback.items() if k != "template_ref"
    }


@pytest.mark.parametrize(
    "failure",
    (
        "not_stopped",
        "sandbox_present",
        "workspace_mismatch",
        "template_ref_mismatch",
        "snapshot_mismatch",
        "not_found",
    ),
)
def test_template_binding_each_precondition_fails_alone(control, failure):
    server, client = control
    if failure == "not_found":
        machine = {
            "id": "computer_missing",
            "workspace_id": "ws_missing",
            "template_ref": None,
            "snapshot_image_id": "im_snapshot",
        }
        before = None
    else:
        _, machine = stopped_computer(control, f"bind-{failure}")
        if failure == "not_stopped":
            server.execute(
                "UPDATE computers SET status = 'running' WHERE id = ?", (machine["id"],)
            )
        elif failure == "sandbox_present":
            server.execute(
                "UPDATE computers SET sandbox_id = 'sb_present' WHERE id = ?",
                (machine["id"],),
            )
        elif failure == "template_ref_mismatch":
            server.execute(
                "UPDATE computers SET template_ref = ? WHERE id = ?",
                (server.CURATED_TEMPLATE_REF, machine["id"]),
            )
        before = dict(server.get_computer(machine["id"]))

    changes = {}
    if failure == "workspace_mismatch":
        changes["expected_workspace_id"] = "ws_different"
    elif failure == "snapshot_mismatch":
        changes["expected_snapshot_image_id"] = "im_different"
    response = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers=AUTH,
        json=binding_body(server, machine, **changes),
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == {
        "code": failure,
        "computer_id": machine["id"],
        "failed_preconditions": [failure],
    }
    if before is not None:
        assert dict(server.get_computer(machine["id"])) == before


def test_template_binding_unknown_target_is_a_typed_404(control):
    server, client = control
    _, machine = stopped_computer(control, "bind-missing-template")
    before = dict(server.get_computer(machine["id"]))
    missing = "probe/not-registered@1.0.0"
    response = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers=AUTH,
        json=binding_body(server, machine, template_ref=missing),
    )
    assert response.status_code == 404, response.text
    assert response.json()["detail"] == {"code": "unknown_template_ref", "ref": missing}
    assert dict(server.get_computer(machine["id"])) == before


def test_template_binding_is_admin_only_even_for_its_own_workspace(control):
    server, client = control
    ws, machine = stopped_computer(control, "bind-scope")
    scoped = client.post(
        "/api-keys",
        headers=AUTH,
        json={"name": "bind-scope", "workspace_id": ws["id"]},
    ).json()
    response = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers={"Authorization": f"Bearer {scoped['key']}"},
        json=binding_body(server, machine),
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "workspace_scope_mismatch"
    assert server.get_computer(machine["id"])["template_ref"] is None


def test_template_binding_asserts_exactly_one_row_was_updated(control, monkeypatch):
    server, client = control
    _, machine = stopped_computer(control, "bind-rowcount")
    monkeypatch.setattr(
        server, "compare_and_swap_template_binding", lambda *_args: (2, None)
    )
    with pytest.raises(AssertionError, match="updated 2 rows"):
        client.patch(
            f"/computers/{machine['id']}/template-binding",
            headers=AUTH,
            json=binding_body(server, machine),
        )


def test_concurrent_status_flip_cannot_pass_the_atomic_binding_update(control, monkeypatch):
    server, client = control
    _, machine = stopped_computer(control, "bind-race")
    real_connect = server.connect
    observed = {"armed": True, "sql": None}

    class RacingConnection:
        def __init__(self):
            self.inner = real_connect()

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def close(self):
            self.inner.close()

        def execute(self, sql, params=()):
            normalized = " ".join(sql.split())
            if observed["armed"] and normalized.startswith(
                "UPDATE computers SET template_ref = ?"
            ):
                observed.update(armed=False, sql=normalized)
                racing = real_connect()
                try:
                    racing.execute(
                        "UPDATE computers SET status = 'running' WHERE id = ?",
                        (machine["id"],),
                    )
                    racing.commit()
                finally:
                    racing.close()
            return self.inner.execute(sql, params)

    monkeypatch.setattr(server, "connect", RacingConnection)
    response = client.patch(
        f"/computers/{machine['id']}/template-binding",
        headers=AUTH,
        json=binding_body(server, machine),
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "not_stopped"
    assert server.get_computer(machine["id"])["template_ref"] is None
    assert observed["sql"] is not None
    for clause in (
        "workspace_id = ?",
        "status = 'stopped'",
        "sandbox_id IS NULL",
        "snapshot_image_id IS ?",
        "template_ref IS ?",
    ):
        assert clause in observed["sql"]


def test_snapshot_image_takes_precedence_over_template_binding(control, monkeypatch):
    server, _ = control
    seen = []
    snapshot = object()
    monkeypatch.setattr(
        server.modal.Image,
        "from_id",
        lambda image_id: (seen.append(image_id), snapshot)[1],
    )
    monkeypatch.setattr(
        server,
        "one",
        lambda *_args, **_kwargs: pytest.fail(
            "image_for queried the template even though a snapshot was present"
        ),
    )
    resolved = server.image_for(
        {
            "snapshot_image_id": "im_customer_snapshot",
            "template_ref": server.CURATED_TEMPLATE_REF,
        }
    )
    assert resolved is snapshot
    assert seen == ["im_customer_snapshot"]


def test_yard_html_u4_templates_and_palette_contract():
    """U4: templates library, inline launch, palette + ⌘K, parked surfaces stay out."""
    source = (REPO / "backlot" / "server.py").read_text()
    yard = source.split("YARD_HTML = ", 1)[1]
    assert '@api.get("/library"' in source
    assert 'id="templatesView"' in yard
    assert 'id="templatesNav"' in yard
    assert "showTemplates" in yard
    assert "location.pathname === '/library'" in yard
    assert "api('/templates')" in yard
    assert "template_ref: template.ref" in yard
    assert "api('/computers', {method: 'POST', body: JSON.stringify(body)})" in yard
    assert 'id="paletteDialog"' in yard
    assert 'id="paletteButton"' in yard
    assert "function openPalette()" in yard
    assert "function paletteItems()" in yard
    assert "label: 'New computer'" in yard
    assert "label: 'Templates'" in yard
    assert "for (const workspace of state.workspaces)" in yard
    assert "for (const machine of state.machines)" in yard
    assert "event.metaKey || event.ctrlKey" in yard
    assert "event.key.toLowerCase() === 'k'" in yard
    assert "⌘K" in yard
    for banned in (
        "chat",
        "model",
        "agent",
        "members",
        "comments",
        "share",
        "marketplace",
    ):
        assert not re.search(rf"\b{banned}\b", yard, re.I), banned


def test_a_failed_wake_never_deletes_the_row(tmp_path, monkeypatch):
    """Only POST /computers rolls a row back, and only because that machine never ran.

    A machine that booted once and later fails to wake must survive as status='error'.
    Deleting it would make a transient boot failure indistinguishable from "this was
    never yours", and a consumer reconciling against a 404 has no way to tell the
    difference. Reported as the suspected cause of two machines vanishing after hours
    of healthy use; this pins it closed so it cannot become true later.
    """
    server = isolated_server(tmp_path, monkeypatch)
    client = TestClient(server.api)
    machine_id = seed_stopped_computer(server, "im_snapshot")

    def refuses_to_boot(_computer_id, *, implicit: bool = True):
        raise RuntimeError("sandbox backend unavailable")

    monkeypatch.setattr(server, "start_runtime", refuses_to_boot)

    for route in (f"/computers/{machine_id}/start", f"/computers/{machine_id}/restart"):
        with pytest.raises(RuntimeError):
            client.post(route, headers=AUTH)
        survivor = server.one("SELECT * FROM computers WHERE id = ?", (machine_id,))
        assert survivor is not None, f"{route} deleted a machine that had already run"


def test_repeated_supervision_failures_reach_the_stranded_bound(
    tmp_path, monkeypatch, capsys
):
    """Repeated failures cannot move the abandonment deadline.

    The supervisor ticks more than once under a simulated clock and ``stop_runtime``
    fails every time.  Updating ``status_changed_at`` on each tick must not buy the
    sandbox another full grace window.  The failure also has to leave a useful,
    redacted traceback before the final abandonment stops the billing sandbox.
    """
    server = isolated_server(tmp_path, monkeypatch)
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    secret = "supersecretvalue"
    clock = {"t": 1_000_000}
    monkeypatch.setattr(server, "now", lambda: clock["t"])
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, env_json, created_at, last_active_at
        ) VALUES (?, ?, 'audit', 4, 2, '1280x720x24', 30, 'running',
            'sb_live', ?, ?, ?)
        """,
        (
            machine_id,
            ws_id,
            json.dumps({"UPSTREAM_TOKEN": secret}),
            server.now(),
            server.now() - 99_999,
        ),
    )

    attempts: list[int] = []
    terminated: list[str] = []

    def stop_always_fails(computer_id):
        assert computer_id == machine_id
        attempts.append(clock["t"])
        raise RuntimeError(f"snapshot backend rejected {secret}")

    class TerminalSandbox:
        def terminate(self, wait=False):
            assert wait is True
            terminated.append("sb_live")

    monkeypatch.setattr(server, "stop_runtime", stop_always_fails)
    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: TerminalSandbox())

    # First failure establishes the onset. Every later tick is still below the
    # per-attempt grace window but the cumulative time crosses the hard bound.
    server.supervise_once()
    first = server.one("SELECT * FROM computers WHERE id = ?", (machine_id,))
    assert first["sandbox_id"] == "sb_live", "a failed reap must remain retryable"
    assert first["stranded_since"] == clock["t"]

    for _ in range(
        server.STRANDED_TERMINATE_SECONDS // server.SUPERVISOR_TICK_SECONDS - 1
    ):
        clock["t"] += server.SUPERVISOR_TICK_SECONDS
        server.supervise_once()

    before_bound = server.one("SELECT * FROM computers WHERE id = ?", (machine_id,))
    assert before_bound["sandbox_id"] == "sb_live"
    assert before_bound["stranded_since"] == first["stranded_since"]
    assert before_bound["status_changed_at"] == clock["t"]
    assert terminated == [], "the grace window must still protect a retryable disk"

    clock["t"] += server.SUPERVISOR_TICK_SECONDS
    server.supervise_once()

    row = server.one("SELECT * FROM computers WHERE id = ?", (machine_id,))
    output = capsys.readouterr().out
    assert len(attempts) > 1, "a single supervisor tick cannot prove this regression"
    assert terminated == ["sb_live"], "billing must stop once the disk is unrecoverable"
    assert row["sandbox_id"] is None, "the row must stop claiming a sandbox it lost"
    assert row["error_reason"] == server.ERROR_SNAPSHOT_UNRECOVERABLE
    assert server.supervise_once() == 0, "a terminated machine must stop being retried"
    assert "BACKLOT_SUPERVISION_ERROR" in output
    assert f"computer_id={machine_id}" in output
    assert f"workspace_id={ws_id}" in output
    assert "exception_type=RuntimeError" in output
    assert "traceback=" in output
    assert server.REDACTED in output
    assert secret not in output


def test_ordinary_stop_terminally_clears_a_typed_not_found_and_restarts_from_snapshot(
    tmp_path, monkeypatch, capsys
):
    """The ordinary stop path cleans a dead task without parsing vendor wording.

    Every runtime claim is cleared in the same transition, identity and the last good
    disk survive, and the next authorized start actually selects that retained image.
    """
    server = isolated_server(tmp_path, monkeypatch)
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    snapshot_id = "im_last_good_customer_disk"
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, snapshot_image_id, agent_url, agent_token,
            vnc_url, vnc_token, vnc_password, created_at, started_at,
            last_active_at, expires_at, template_ref
        ) VALUES (?, ?, 'audit', 4, 2, '1280x720x24', 30, 'running',
            'sb_dead', ?, 'https://example.invalid', 'agent-secret-value',
            'https://example.invalid', 'vnc-secret-value', 'vnc-password-value',
            ?, ?, ?, ?, ?)
        """,
        (
            machine_id,
            ws_id,
            snapshot_id,
            server.now() - 900,
            server.now() - 900,
            server.now() - 60,
            server.now() + 86_400,
            server.CURATED_TEMPLATE_REF,
        ),
    )

    class DeadSandbox:
        def snapshot_filesystem(self, timeout=None, ttl=None):
            raise NotFoundError("vendor wording deliberately changed")

        def terminate(self, wait=False):
            pytest.fail("a task missing during snapshot cannot be terminated")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: DeadSandbox())

    row = server.stop_runtime(machine_id)
    output = capsys.readouterr().out
    assert row["id"] == machine_id
    assert row["workspace_id"] == ws_id
    assert row["template_ref"] == server.CURATED_TEMPLATE_REF
    assert row["snapshot_image_id"] == snapshot_id
    assert row["sandbox_id"] is None
    assert row["status"] == "error"
    assert row["error_reason"] == server.ERROR_SNAPSHOT_UNRECOVERABLE
    assert row["stranded_since"] is None
    for field in (
        "agent_url",
        "agent_token",
        "vnc_url",
        "vnc_token",
        "vnc_password",
        "started_at",
        "expires_at",
    ):
        assert row[field] is None, f"dead runtime field {field} stayed attached"
    assert "BACKLOT_DEAD_SANDBOX_DETACHED" in output
    assert f"computer_id={machine_id}" in output
    assert f"workspace_id={ws_id}" in output

    selected = {}
    retained_image = object()

    def image_from_id(image_id):
        selected["image_id"] = image_id
        return retained_image

    class StartedSandbox:
        object_id = "sb_restarted"

        def wait_until_ready(self, timeout):
            return None

        def create_connect_token(self, metadata, port):
            return SimpleNamespace(url=f"https://{port}.invalid", token=f"token-{port}")

        def detach(self):
            return None

        def terminate(self, wait=False):
            pytest.fail("the retained-snapshot start should not fail")

    def create_sandbox(*_args, **kwargs):
        selected["image"] = kwargs["image"]
        return StartedSandbox()

    monkeypatch.setattr(server.modal.Image, "from_id", image_from_id)
    monkeypatch.setattr(server.modal.Sandbox, "create", create_sandbox)

    started = server.start_runtime(machine_id, implicit=False)
    assert selected == {"image_id": snapshot_id, "image": retained_image}
    assert started["status"] == "running"
    assert started["snapshot_image_id"] == snapshot_id
    assert started["id"] == machine_id
    assert started["workspace_id"] == ws_id
    assert started["template_ref"] == server.CURATED_TEMPLATE_REF


def test_stranded_abandon_terminally_clears_a_typed_not_found(
    tmp_path, monkeypatch, capsys
):
    """The grace-bound abandon path also treats a missing Modal task as terminal."""
    server = isolated_server(tmp_path, monkeypatch)
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    snapshot_id = "im_last_good_customer_disk"
    clock = {"t": 3_000_000}
    monkeypatch.setattr(server, "now", lambda: clock["t"])
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, snapshot_image_id, agent_url, agent_token,
            vnc_url, vnc_token, vnc_password, created_at, started_at,
            last_active_at, expires_at, error_reason, status_changed_at,
            stranded_since, template_ref
        ) VALUES (?, ?, 'audit', 4, 2, '1280x720x24', 30, 'error',
            'sb_dead', ?, 'https://example.invalid', 'agent-secret-value',
            'https://example.invalid', 'vnc-secret-value', 'vnc-password-value',
            ?, ?, ?, ?, 'runtime_supervision_failed', ?, ?, ?)
        """,
        (
            machine_id,
            ws_id,
            snapshot_id,
            server.now() - 1_800,
            server.now() - 1_800,
            server.now() - 1_000,
            server.now() + 86_400,
            server.now() - 1_000,
            server.now() - server.STRANDED_TERMINATE_SECONDS,
            server.CURATED_TEMPLATE_REF,
        ),
    )

    class MissingSandbox:
        def terminate(self, wait=False):
            assert wait is True
            raise NotFoundError("different vendor wording")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: MissingSandbox())

    assert server.supervise_once() == 1
    row = server.get_computer(machine_id)
    output = capsys.readouterr().out
    assert row["id"] == machine_id
    assert row["workspace_id"] == ws_id
    assert row["template_ref"] == server.CURATED_TEMPLATE_REF
    assert row["snapshot_image_id"] == snapshot_id
    assert row["status"] == "error"
    assert row["error_reason"] == server.ERROR_SNAPSHOT_UNRECOVERABLE
    assert row["stranded_since"] is None
    for field in (
        "sandbox_id",
        "agent_url",
        "agent_token",
        "vnc_url",
        "vnc_token",
        "vnc_password",
        "started_at",
        "expires_at",
    ):
        assert row[field] is None, f"dead runtime field {field} stayed attached"
    assert server.supervise_once() == 0
    assert "BACKLOT_DEAD_SANDBOX_DETACHED" in output
    assert f"computer_id={machine_id}" in output
    assert f"workspace_id={ws_id}" in output


@pytest.mark.parametrize(
    ("exception_type", "message"),
    [
        (ConflictError, "Task has already finished with status terminated"),
        (RuntimeError, "Task has already finished with status terminated"),
    ],
)
def test_message_text_cannot_widen_the_typed_not_found_cleanup(
    tmp_path, monkeypatch, exception_type, message
):
    """Vendor wording is never a classifier; non-NotFound types stay retryable."""
    server = isolated_server(tmp_path, monkeypatch)
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, snapshot_image_id, created_at, last_active_at
        ) VALUES (?, ?, 'audit', 4, 2, '1280x720x24', 30, 'running',
            'sb_retryable', 'im_last_good', ?, ?)
        """,
        (machine_id, ws_id, server.now(), server.now() - 99_999),
    )

    class RetryableSandbox:
        def snapshot_filesystem(self, timeout=None, ttl=None):
            raise exception_type(message)

    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: RetryableSandbox())

    with pytest.raises(exception_type, match=re.escape(message)):
        server.stop_runtime(machine_id)
    row = server.get_computer(machine_id)
    assert row["sandbox_id"] == "sb_retryable"
    assert row["snapshot_image_id"] == "im_last_good"
    assert row["status"] == "running"


def test_typed_not_found_during_terminate_preserves_the_new_snapshot(
    tmp_path, monkeypatch
):
    """A task exit racing terminate retains the disk captured immediately before it."""
    server = isolated_server(tmp_path, monkeypatch)
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, snapshot_image_id, created_at, last_active_at
        ) VALUES (?, ?, 'audit', 4, 2, '1280x720x24', 30, 'running',
            'sb_finishing', 'im_previous', ?, ?)
        """,
        (machine_id, ws_id, server.now(), server.now() - 99_999),
    )

    class FinishingSandbox:
        def snapshot_filesystem(self, timeout=None, ttl=None):
            return SimpleNamespace(object_id="im_newly_captured")

        def terminate(self, wait=False):
            raise NotFoundError("vendor wording changed after snapshot")

    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: FinishingSandbox())

    row = server.stop_runtime(machine_id)
    assert row["status"] == "error"
    assert row["sandbox_id"] is None
    assert row["snapshot_image_id"] == "im_newly_captured"
    assert row["error_reason"] == server.ERROR_SNAPSHOT_UNRECOVERABLE


def test_a_transient_snapshot_failure_is_retried_and_the_disk_survives(
    tmp_path, monkeypatch
):
    """The grace window is only worth having if the snapshot is actually re-attempted.

    A reaper that strands the row, waits the window out and then terminates would lose a
    customer's disk to a single backend blip while looking, from the outside, identical
    to one that retried. Both end with a terminated sandbox; only one keeps the data.
    """
    server = isolated_server(tmp_path, monkeypatch)
    ws_id = f"ws_{uuid4().hex}"
    machine_id = f"computer_{uuid4().hex}"
    server.execute(
        "INSERT INTO workspaces(id, name, created_at) VALUES (?, 'iso', ?)",
        (ws_id, server.now()),
    )
    server.execute(
        """
        INSERT INTO computers(
            id, workspace_id, name, ram, cpu, resolution, idle_timeout_minutes,
            status, sandbox_id, created_at, last_active_at
        ) VALUES (?, ?, 'audit', 4, 2, '1280x720x24', 30, 'running', 'sb_live', ?, ?)
        """,
        (machine_id, ws_id, server.now(), server.now() - 99_999),
    )

    attempts = {"n": 0}

    class FlakySandbox:
        def snapshot_filesystem(self, timeout=None, ttl=None):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("snapshot backend blip")
            return SimpleNamespace(object_id="im_saved")

        def terminate(self, wait=False):
            return None

    monkeypatch.setattr(server.modal.Sandbox, "from_id", lambda _: FlakySandbox())

    server.supervise_once()
    assert attempts["n"] == 1
    assert server.one("SELECT * FROM computers WHERE id = ?", (machine_id,))["status"] == "error"

    server.supervise_once()

    row = server.one("SELECT * FROM computers WHERE id = ?", (machine_id,))
    assert attempts["n"] == 2, "the stranded machine was never re-snapshotted"
    assert row["status"] == "stopped", "a recovered snapshot must park the machine"
    assert row["snapshot_image_id"] == "im_saved", "the disk must survive a blip"
    assert row["sandbox_id"] is None, "a parked machine holds no sandbox"


def _fake_build_sandbox(monkeypatch, server, *, stdout="", stderr="", code=0, seen=None):
    class FakeSandbox:
        def __init__(self, **kwargs):
            if seen is not None:
                seen.update(kwargs)

        def wait_until_ready(self, timeout):
            return None

        def exec(self, *_argv, timeout=None):
            return SimpleNamespace(
                stdout=SimpleNamespace(read=lambda: stdout),
                stderr=SimpleNamespace(read=lambda: stderr),
                wait=lambda: code,
            )

        def snapshot_filesystem(self, timeout=None, ttl=None):
            return SimpleNamespace(object_id="im_built")

        def terminate(self, wait=False):
            return None

    monkeypatch.setattr(server.modal.Sandbox, "create", lambda *a, **k: FakeSandbox(**k))
    return FakeSandbox


SECRET = "ghp_liveclonetoken0123456789abcdef"


def test_template_secrets_never_reach_the_registry(tmp_path, monkeypatch):
    """spec_json is permanent. There is no image delete in Modal 1.5.2 and a template
    cannot be dropped while a computer references it, so a credential written into that
    row is unrecoverable: not rotatable out of storage, only revocable at the issuer.

    Moving a token from the command string into `env` fixed the escaping sink and made
    the storage sink worse, because env is serialised by model_dump_json. `secrets`
    reaches the sandbox and is never persisted.
    """
    server = isolated_server(tmp_path, monkeypatch)
    seen: dict = {}
    _fake_build_sandbox(monkeypatch, server, stdout="build ok", seen=seen)

    built = server.build_template(
        server.TemplateBuild(
            ref="acme/engine@1.0.0",
            env={"PUBLIC_SETTING": "fine"},
            secrets={"CLONE_TOKEN": SECRET},
            build={"run": ["git clone https://test-contact-02@example.invalid/r"]},
        )
    )
    assert built["image_id"] == "im_built"

    # It has to actually arrive, or the build cannot clone and the field is decoration.
    assert seen["env"]["CLONE_TOKEN"] == SECRET, "secrets must reach the build sandbox"
    assert seen["env"]["PUBLIC_SETTING"] == "fine", "env must still be passed"

    stored = server.one(
        "SELECT spec_json FROM templates WHERE ref = ?", ("acme/engine@1.0.0",)
    )["spec_json"]
    assert SECRET not in stored, "a credential was written into a row nobody can delete"
    assert "CLONE_TOKEN" not in stored, "even the secret's name stays out of storage"
    assert "PUBLIC_SETTING" in stored, "ordinary env is still part of the template"


def test_template_secrets_are_redacted_from_build_logs_and_errors(tmp_path, monkeypatch):
    """A secret inlined into a command or echoed by the build must not survive into the
    returned logs, and must not survive into spec_json either.

    Redaction runs before truncation. Truncating first would let a 200 character cut
    land mid-token and return the front half of a live credential.
    """
    server = isolated_server(tmp_path, monkeypatch)
    _fake_build_sandbox(monkeypatch, server, stdout=f"cloning with {SECRET} ok")

    built = server.build_template(
        server.TemplateBuild(
            ref="acme/logs@1.0.0",
            secrets={"CLONE_TOKEN": SECRET},
            build={"run": [f"git clone https://{SECRET}@example.test/r"]},
        )
    )
    blob = json.dumps(built)
    assert SECRET not in blob, "the credential came back in the build response"
    assert server.REDACTED in blob, "redaction must be visible, not silent"

    stored = server.one(
        "SELECT spec_json FROM templates WHERE ref = ?", ("acme/logs@1.0.0",)
    )["spec_json"]
    assert SECRET not in stored, "an inlined credential was persisted in build.run"


def test_a_failed_build_does_not_return_the_secret_in_its_error(tmp_path, monkeypatch):
    """The failure paths echo the command and the output tail, and a build that fails is
    exactly when a caller pastes the whole error into a ticket."""
    server = isolated_server(tmp_path, monkeypatch)
    _fake_build_sandbox(
        monkeypatch, server, stdout=f"fatal: auth failed for {SECRET}", code=1
    )

    with pytest.raises(HTTPException) as caught:
        server.build_template(
            server.TemplateBuild(
                ref="acme/broken@1.0.0",
                secrets={"CLONE_TOKEN": SECRET},
                build={"run": [f"git clone https://{SECRET}@example.test/r"]},
            )
        )
    assert SECRET not in json.dumps(caught.value.detail), "error detail leaked the token"


def test_credential_shaped_env_is_called_out_by_name_not_by_value(capsys):
    """Warn, do not reject: a build that fails closed teaches people to work around the
    check. The warning names the key so it is actionable, and never the value."""
    import backlot.server as server

    assert server.secretish_env_keys({"GITHUB_TOKEN": "x"}) == ["GITHUB_TOKEN"]
    assert server.secretish_env_keys({"ANYTHING": "ghp_abcdefghijklmnop"}) == ["ANYTHING"]
    assert server.secretish_env_keys({"PATH": "/usr/bin", "LANG": "C"}) == []
    assert server.secretish_env_keys({"KEYBOARD_LAYOUT": "us"}) == []


def test_a_short_secret_does_not_blank_out_the_whole_build_log():
    """Redacting an 8-character-or-shorter value would replace ordinary substrings and
    make logs unreadable, trading one broken thing for another."""
    import backlot.server as server

    redact = server.redactor_for({"1", "ok", "true"})
    assert redact("step 1 ok true") == "step 1 ok true"

    redact = server.redactor_for({"supersecretvalue", "supersecret"})
    # Longest first, or the shorter match leaves "value" dangling in the output.
    assert redact("using supersecretvalue now") == f"using {server.REDACTED} now"


def test_auth_headers_and_common_tokens_are_redacted_without_secret_field(
    tmp_path, monkeypatch
):
    """Inline credentials are unsafe even when callers forget the secrets field."""
    server = isolated_server(tmp_path, monkeypatch)
    fine_grained_pat = "github_pat_" + "A" * 40
    basic_value = base64.b64encode(b"user:password").decode()
    command = (
        f'git -c http.extraHeader="Authorization: Basic {basic_value}" '
        f"clone https://{fine_grained_pat}@example.test/repo"
    )
    _fake_build_sandbox(
        monkeypatch,
        server,
        stdout=f"Authorization: Bearer {fine_grained_pat}\nbuild ok",
    )

    built = server.build_template(
        server.TemplateBuild(ref="acme/generic-redaction@1.0.0", build={"run": [command]})
    )
    stored = server.one(
        "SELECT spec_json FROM templates WHERE ref = ?",
        ("acme/generic-redaction@1.0.0",),
    )["spec_json"]
    for output in (json.dumps(built), stored):
        assert fine_grained_pat not in output
        assert basic_value not in output
        assert server.REDACTED in output


def test_redaction_runs_before_truncation_not_after(tmp_path, monkeypatch):
    """Echoed commands are cut to 200 characters. Redacting after that cut returns the
    front half of a live credential, which is still a credential leak and reads as a
    clean log. The mutation that reorders these two lines is invisible to any test
    whose command happens to be shorter than the cut, so this one straddles it.
    """
    server = isolated_server(tmp_path, monkeypatch)
    _fake_build_sandbox(monkeypatch, server, stdout="ok")

    head = "echo " + "x" * 163
    command = f"{head} && git clone https://{SECRET}@example.test/r"
    start = command.index(SECRET)
    assert start < 200 < start + len(SECRET), "setup: the token must straddle the cut"

    built = server.build_template(
        server.TemplateBuild(
            ref="acme/cut@1.0.0",
            secrets={"CLONE_TOKEN": SECRET},
            build={"run": [command]},
        )
    )
    echoed = built["logs"][0]["command"]
    assert SECRET not in echoed
    # Any surviving prefix is a leak, and guessing which one lands on the cut is how a
    # mutation slips through: assert against every prefix worth redacting instead.
    leaked = [n for n in range(server.MIN_REDACTABLE_SECRET, len(SECRET) + 1)
              if SECRET[:n] in echoed]
    assert not leaked, f"the cut kept a {max(leaked)} character prefix of the token"


def test_template_schema_says_which_fields_are_persisted(control):
    _, client = control
    """A caller deciding where to put a token reads this endpoint. Listing `secrets` as
    merely supported, alongside fields that are written to storage, would leave the one
    fact that matters implied."""
    schema = client.get("/template-schema", headers=AUTH).json()
    assert "secrets" in schema["supported"]
    assert "secrets" in schema["not_persisted"]
    assert "secrets" not in schema["persisted"]
    for field in ("env", "files", "build.run"):
        assert field in schema["persisted"], f"{field} is written to spec_json"


@pytest.fixture
def app_tunnel(control, monkeypatch):
    """A recording stand-in for Modal's connect-token minting."""
    server, client = control
    minted: list[dict] = []

    class FakeSandbox:
        def __init__(self, sandbox_id: str):
            self.sandbox_id = sandbox_id

        def create_connect_token(self, metadata, port: int):
            minted.append({"sandbox_id": self.sandbox_id, "metadata": metadata, "port": port})
            issue = len(minted)
            return SimpleNamespace(
                url=f"https://tunnel-{issue}.modal.run", token=f"connect-{issue}"
            )

    monkeypatch.setattr(server.modal.Sandbox, "from_id", FakeSandbox)
    return server, client, minted


def test_app_url_opens_a_tunnel_to_the_port_the_caller_names(app_tunnel):
    """agent_url is the control plane and vnc_url is a desktop. Neither is the app."""
    _, client, minted = app_tunnel
    machine = computer(client)

    body = client.get(
        f"/computers/{machine['id']}/app-url", headers=AUTH, params={"port": 3100}
    )
    assert body.status_code == 200, body.text
    payload = body.json()
    assert payload["port"] == 3100
    assert payload["host"] == "https://tunnel-1.modal.run"
    assert payload["token"] == "connect-1"
    # The front-door URL must carry the token, or the first request is rejected and the
    # session cookie that every later asset relies on is never set.
    assert payload["url"] == "https://tunnel-1.modal.run/?_modal_connect_token=connect-1"
    assert minted == [
        {
            "sandbox_id": "sb_test",
            "metadata": {"computer_id": machine["id"], "purpose": "app", "port": "3100"},
            "port": 3100,
        }
    ]


def test_app_url_mints_fresh_every_call_and_never_stores_the_token(app_tunnel):
    """The tunnel host moves on every stop, start and 23 hour rollover; the old one 404s.

    A stored URL is a stale URL waiting to be handed to a customer, so nothing here may
    be cached and no token may reach the registry.
    """
    server, client, minted = app_tunnel
    machine = computer(client)

    first = client.get(
        f"/computers/{machine['id']}/app-url", headers=AUTH, params={"port": 3100}
    ).json()
    second = client.get(
        f"/computers/{machine['id']}/app-url", headers=AUTH, params={"port": 3100}
    ).json()
    assert first["token"] != second["token"], "a reused token means it was cached"
    assert len(minted) == 2

    row = dict(server.get_computer(machine["id"]))
    for column, value in row.items():
        assert "connect-" not in str(value), f"{column} persisted a connect token"


def test_app_url_wakes_a_reaped_machine_instead_of_404ing_at_a_customer(app_tunnel):
    """The idle reaper stops machines. A customer clicking through must not meet a 404."""
    server, client, minted = app_tunnel
    machine = computer(client)
    client.post(f"/computers/{machine['id']}/stop", headers=AUTH)
    stopped = server.get_computer(machine["id"])
    assert stopped["status"] == "stopped"
    # Setup check, not decoration: a stopped machine has no sandbox_id, so minting before
    # the wake would call from_id(None) rather than merely returning a dead URL.
    assert stopped["sandbox_id"] is None

    payload = client.get(
        f"/computers/{machine['id']}/app-url", headers=AUTH, params={"port": 3100}
    )
    assert payload.status_code == 200, payload.text
    assert minted[0]["sandbox_id"] == "sb_test"
    assert server.get_computer(machine["id"])["status"] == "running"


def test_app_url_refuses_backlots_own_control_port(app_tunnel):
    """A browser-reachable tunnel to the agent puts the command surface on the internet."""
    server, client, minted = app_tunnel
    machine = computer(client)

    refused = client.get(
        f"/computers/{machine['id']}/app-url",
        headers=AUTH,
        params={"port": server.AGENT_PORT},
    )
    assert refused.status_code == 422, refused.text
    assert minted == [], "the token was minted before the port was checked"


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_app_url_rejects_a_port_outside_the_valid_range(app_tunnel, port):
    _, client, minted = app_tunnel
    machine = computer(client)
    refused = client.get(
        f"/computers/{machine['id']}/app-url", headers=AUTH, params={"port": port}
    )
    assert refused.status_code == 422, refused.text
    assert minted == []


def test_app_url_is_scoped_to_the_calling_workspace(app_tunnel):
    """Opening someone else's machine is the whole blast radius of this route."""
    _, client, minted = app_tunnel
    mine = workspace(client, "mine")
    theirs = workspace(client, "theirs")
    machine = computer(client, theirs["id"])
    scoped = client.post(
        "/api-keys", headers=AUTH, json={"name": "scoped", "workspace_id": mine["id"]}
    ).json()

    crossed = client.get(
        f"/computers/{machine['id']}/app-url",
        headers={"Authorization": f"Bearer {scoped['key']}"},
        params={"port": 3100},
    )
    assert crossed.status_code in (403, 404), crossed.text
    assert client.get(
        f"/computers/{machine['id']}/app-url", params={"port": 3100}
    ).status_code == 401
    assert minted == []


# --- implementation milestone B5.0: an implicit boot is a defect for a bounded caller ----------
#
# These tests deliberately do NOT use the `control` fixture's fake start_runtime.
# The whole point is the guard inside the real start_runtime, so faking the
# function under test would prove nothing. Instead the real function runs and
# modal.Sandbox.create is replaced with a sentinel: if the sentinel fires, a boot
# was attempted; if it does not, no machine was created. That is the actual
# claim, stated as an observation rather than an absence.


class _BootAttempted(Exception):
    """Raised in place of modal.Sandbox.create so a boot attempt is observable."""


@pytest.fixture
def live_start(tmp_path, monkeypatch):
    """A control plane with the REAL start_runtime and no reachable Modal."""
    monkeypatch.setenv("BACKLOT_DB_PATH", str(tmp_path / "backlot.db"))
    monkeypatch.setenv("BACKLOT_BOOTSTRAP_KEY", BOOTSTRAP)
    import backlot.server as server

    def boom(*_args, **_kwargs):
        raise _BootAttempted()

    monkeypatch.setattr(server.modal.Sandbox, "create", boom)
    monkeypatch.setattr(server, "stop_runtime", lambda cid: server.get_computer(cid))
    monkeypatch.setattr(server, "terminate_runtime", lambda _: None)
    with TestClient(server.make_api(), raise_server_exceptions=False) as client:
        yield server, client


def _stopped_machine(server, client) -> str:
    """A row in 'stopped', created without ever booting."""
    ws = client.post("/workspaces", headers=AUTH, json={"name": "b50"}).json()
    computer_id = f"computer_{uuid4().hex}"
    server.execute(
        """
        INSERT INTO computers(id, workspace_id, name, ram, cpu, resolution,
            idle_timeout_minutes, status, created_at)
        VALUES (?, ?, 'b50', 4, 1, '1280x720x24', 30, 'stopped', ?)
        """,
        (computer_id, ws["id"], server.now()),
    )
    assert server.get_computer(computer_id)["status"] == "stopped"
    return computer_id


BOUNDED = {**AUTH, "X-Backlot-Bounded-Execution": "1"}


def test_bounded_action_against_a_stopped_machine_refuses_and_boots_nothing(live_start):
    """The defect, closed. A bounded call must never mint a machine.

    $0.66 per implicit boot at the observed 4c/8g shape, against a reservation
    sized for one bounded call. Invisible to every spend ceiling, because the
    caller never asked for a machine.
    """
    server, client = live_start
    computer_id = _stopped_machine(server, client)

    response = client.post(
        f"/computers/{computer_id}/click",
        headers=BOUNDED,
        json={"x": 1, "y": 1, "button": "left", "double": False},
    )

    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "machine_not_running"
    assert response.json()["detail"]["computer_id"] == computer_id
    # The load-bearing half: no boot was even attempted. A 409 returned after a
    # sandbox was created would still have cost the money.
    assert server.get_computer(computer_id)["status"] == "stopped"
    assert server.get_computer(computer_id)["sandbox_id"] is None


@pytest.mark.parametrize("path", ["vnc-password", "app-url?port=3100"])
def test_bounded_vnc_and_app_url_refuse_too(live_start, path):
    """All four implicit paths, not just the one that was easiest to test."""
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    response = client.get(f"/computers/{computer_id}/{path}", headers=BOUNDED)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "machine_not_running"
    assert server.get_computer(computer_id)["status"] == "stopped"


def test_bounded_chat_refuses(live_start):
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    response = client.post(
        "/v1/chat/completions",
        headers=BOUNDED,
        json={
            "model": "backlot",
            "computer_id": computer_id,
            "messages": [{"role": "user", "content": "hi"}],
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "machine_not_running"
    assert server.get_computer(computer_id)["status"] == "stopped"


def test_bounded_caller_can_still_start_a_machine_explicitly(live_start):
    """The refusal is about implicitness, not about the caller.

    A bounded caller that means to provision says so, and the explicit route
    still boots. Proven by the boot sentinel firing, not by a status code.
    """
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    response = client.post(f"/computers/{computer_id}/start", headers=BOUNDED)
    assert response.status_code != 409
    assert "machine_not_running" not in response.text
    # The positive claim, not just the absence of a refusal: the boot sentinel
    # fired, so the guard let this through to the real provisioning path.
    assert response.status_code == 500, "expected the boot sentinel, not a short circuit"
    assert server.get_computer(computer_id)["status"] == "error"


def test_an_unbounded_caller_keeps_todays_auto_start(live_start):
    """Every consumer that exists right now sends no header, including the live
    customer runtime. Their behavior must be byte-identical to before."""
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    response = client.get(f"/computers/{computer_id}/vnc-password", headers=AUTH)
    assert response.status_code != 409
    assert "machine_not_running" not in response.text
    assert response.status_code == 500, "expected the boot sentinel, not a short circuit"
    assert server.get_computer(computer_id)["status"] == "error", (
        "an unbounded caller must still reach the boot path, which is what the "
        "live customer runtime depends on"
    )


@pytest.mark.parametrize("value", ["", "0", "no", "false", "yes please", "TRUE-ish"])
def test_a_malformed_bounded_header_fails_open(live_start, value):
    """Deliberately fails OPEN.

    Failing closed on a typo would refuse work for a caller who never asked to
    be bounded, on the live customer path. Failing open costs at most one boot
    that caller could already have had.
    """
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    response = client.get(
        f"/computers/{computer_id}/vnc-password",
        headers={**AUTH, "X-Backlot-Bounded-Execution": value},
    )
    assert response.status_code != 409, f"{value!r} should not have bound the request"
    assert response.status_code == 500, f"{value!r} should have reached the boot path"
    assert server.get_computer(computer_id)["status"] == "error"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", " 1 "])
def test_the_accepted_bounded_values_are_exactly_these(live_start, value):
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    response = client.get(
        f"/computers/{computer_id}/vnc-password",
        headers={**AUTH, "X-Backlot-Bounded-Execution": value},
    )
    assert response.status_code == 409, f"{value!r} should have bound the request"


def test_the_bounded_flag_does_not_leak_between_requests(live_start):
    """A leaked True would refuse boots for callers who never opted in, which is
    the silent misattributed failure this whole gate exists to prevent."""
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    assert client.get(f"/computers/{computer_id}/vnc-password", headers=BOUNDED).status_code == 409
    for _ in range(3):
        assert client.get(f"/computers/{computer_id}/vnc-password", headers=AUTH).status_code != 409
    assert client.get(f"/computers/{computer_id}/vnc-password", headers=BOUNDED).status_code == 409


def test_start_runtime_defaults_to_implicit_so_a_new_call_site_is_safe():
    """The fail-safe default, asserted rather than assumed.

    Flipping this default would silently reopen the leak for every call site
    that has not been audited, so it is worth a test that breaks loudly.
    """
    import backlot.server as server

    parameter = inspect.signature(server.start_runtime).parameters["implicit"]
    assert parameter.default is True
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, (
        "keyword-only, so a positional argument can never land in it by accident"
    )


def test_only_the_lifecycle_routes_and_the_supervisor_opt_out_of_the_guard():
    """Pins WHICH call sites are explicit.

    Five today: create's first boot, POST /start, restart, the resize restore,
    and the supervisor's 23h rollover. A sixth appearing without this test being
    updated is exactly how the leak comes back.
    """
    source = (REPO / "backlot" / "server.py").read_text()
    # Real invocations only. The docstring inside start_runtime explains the
    # flag and would otherwise be counted as a sixth opt-out.
    calls = re.findall(r"start_runtime\(([^)]*)\)", source)
    explicit = [c for c in calls if "implicit=False" in c]
    implicit = [c for c in calls if "implicit=False" not in c and "implicit: bool" not in c]
    assert len(explicit) == 5, (
        f"{len(explicit)} sites opt out of the guard, expected 5 "
        f"(create first boot, POST /start, restart, resize restore, supervisor rollover)"
    )
    assert len(implicit) == 1, (
        f"{len(implicit)} convenience call sites, expected the shared "
        "runtime_for_consumer boundary; re-audit each new one"
    )
    assert source.count("runtime_for_consumer(") == 5, (
        "expected one shared definition plus agent_request, vnc_payload, "
        "app_payload and run_chat; re-audit each new consumer"
    )


def test_the_supervisor_rollover_is_not_bounded():
    """The supervisor runs outside any request, so the default False applies and
    a 23h rollover is never refused. Asserted because a rollover that silently
    stopped rolling over would strand a customer machine at Modal's hard cap."""
    import backlot.server as server

    assert server.BOUNDED_EXECUTION.get() is False


# --- implementation milestone B5.0: trusted clock (gap L14, threat T13) -----------------------


def test_clock_drift_is_measured_against_a_clock_that_cannot_be_adjusted(monkeypatch):
    """The detector is monotonic, not another wall clock.

    A wall clock checked against a wall clock detects nothing, which is exactly
    the state the runtime was in: now() is bare time.time() and a backward jump
    was unobservable.
    """
    import backlot.server as server

    assert server.clock_state()["trusted"] is True
    assert abs(server.clock_state()["drift_seconds"]) < 5

    # Wall clock jumps BACKWARD while monotonic keeps counting. This is the
    # unsafe direction: it makes an expired authorization look live.
    monkeypatch.setattr(server.time, "time", lambda: server._CLOCK_ANCHOR_WALL - 3600)
    state = server.clock_state()
    assert state["trusted"] is False
    assert state["direction"] == "backward"
    assert state["drift_seconds"] < -3000


def test_a_forward_jump_is_caught_too(monkeypatch):
    import backlot.server as server

    monkeypatch.setattr(server.time, "time", lambda: server._CLOCK_ANCHOR_WALL + 3600)
    state = server.clock_state()
    assert state["trusted"] is False
    assert state["direction"] == "forward"


def test_the_skew_bound_has_a_floor_and_survives_a_typo(monkeypatch):
    """A bound of 0 would make every scheduler hiccup an outage, and a garbage
    value must not silently become one either."""
    import backlot.server as server

    monkeypatch.setenv("BACKLOT_CLOCK_SKEW_BOUND_SECONDS", "0")
    assert server.clock_skew_bound() == 5
    monkeypatch.setenv("BACKLOT_CLOCK_SKEW_BOUND_SECONDS", "not-a-number")
    assert server.clock_skew_bound() == server.CLOCK_SKEW_BOUND_SECONDS_DEFAULT
    monkeypatch.setenv("BACKLOT_CLOCK_SKEW_BOUND_SECONDS", "120")
    assert server.clock_skew_bound() == 120


def test_an_untrusted_clock_refuses_a_bounded_start(live_start, monkeypatch):
    """Fails CLOSED, unlike the bounded-execution header.

    That header's failure mode is refusing a caller who never opted in. This
    one's failure mode is honoring an expired authorization, so the safe default
    is the other way round.
    """
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    monkeypatch.setattr(server.time, "time", lambda: server._CLOCK_ANCHOR_WALL - 3600)

    response = client.post(f"/computers/{computer_id}/start", headers=BOUNDED)

    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "untrusted_clock"
    assert response.json()["detail"]["direction"] == "backward"
    # No boot was attempted: the sentinel would have produced a 500.
    assert server.get_computer(computer_id)["status"] == "stopped"


def test_an_untrusted_clock_does_not_take_the_customer_path_down(live_start, monkeypatch):
    """The deliberate narrowing of the gate, asserted so it cannot drift.

    An unbounded caller is the live customer path. Refusing every start on a
    clock correction would protect against a lease risk that surface does not
    carry, at the cost of an outage that is entirely real. Recorded in
    DECISIONS.md.
    """
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    monkeypatch.setattr(server.time, "time", lambda: server._CLOCK_ANCHOR_WALL - 3600)

    response = client.post(f"/computers/{computer_id}/start", headers=AUTH)

    assert response.status_code != 503
    assert "untrusted_clock" not in response.text
    assert response.status_code == 500, "the boot sentinel should have fired"


def test_health_reports_clock_state_before_it_is_load_bearing(live_start):
    """Drift visible on every health check is drift somebody can act on. Drift
    discovered during an incident is not."""
    _, client = live_start
    body = client.get("/health").json()
    assert body["clock"]["trusted"] is True
    assert "drift_seconds" in body["clock"]
    assert body["clock"]["skew_bound_seconds"] >= 5


def test_ordinary_bookkeeping_still_works_on_an_untrusted_clock(monkeypatch):
    """now() is called 20 times for housekeeping like last_active_at. Making it
    raise would turn a measurement fault into an outage, so the guard is
    consulted where a wrong answer costs money, not everywhere time is read."""
    import backlot.server as server

    monkeypatch.setattr(server.time, "time", lambda: server._CLOCK_ANCHOR_WALL - 3600)
    assert isinstance(server.now(), int)  # does not raise


# --- implementation milestone B5.0: the operator clock-distrust lever -------------------------


@pytest.fixture(autouse=True)
def _clear_clock_override():
    """Reset between tests. Module-level state that leaks across tests would
    make the whole clock suite order-dependent."""
    import backlot.server as server

    server._clock_distrust_until = 0.0
    yield
    server._clock_distrust_until = 0.0


def test_the_lever_can_only_withdraw_trust_never_grant_it(live_start):
    """The safety property, asserted directly.

    If this could grant trust it would be a way to mask real drift, which is the
    one thing the detector exists to catch.
    """
    server, client = live_start
    assert client.get("/health").json()["clock"]["trusted"] is True

    response = client.post(
        "/admin/clock-trust", headers=AUTH, json={"untrusted_for_seconds": 60}
    )
    assert response.status_code == 200, response.text
    assert response.json()["trusted"] is False
    assert response.json()["operator_declared_untrusted"] is True
    assert client.get("/health").json()["clock"]["trusted"] is False

    # There is no value that turns trust back on beyond letting it expire, and
    # zero only clears the override rather than asserting a good clock.
    client.post("/admin/clock-trust", headers=AUTH, json={"untrusted_for_seconds": 0})
    assert client.get("/health").json()["clock"]["trusted"] is True

    # And with genuine drift present, clearing the override does NOT restore
    # trust. That is the difference between withdrawing trust and granting it.
    import backlot.server as server_mod

    real_drift = server_mod._CLOCK_ANCHOR_WALL - 3600
    original = server_mod.time.time
    try:
        server_mod.time.time = lambda: real_drift
        client.post(
            "/admin/clock-trust", headers=AUTH, json={"untrusted_for_seconds": 0}
        )
        assert client.get("/health").json()["clock"]["trusted"] is False
    finally:
        server_mod.time.time = original


def test_the_lever_refuses_a_bounded_start_on_the_deployed_shape(live_start):
    """This is what makes the B5.0 clock gate provable against a real control
    plane. Wall-clock skew cannot be induced inside a Modal container from
    outside it, so without this the refusal path would ship proven only by a
    unit test."""
    server, client = live_start
    computer_id = _stopped_machine(server, client)
    client.post("/admin/clock-trust", headers=AUTH, json={"untrusted_for_seconds": 60})

    response = client.post(f"/computers/{computer_id}/start", headers=BOUNDED)

    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "untrusted_clock"
    assert response.json()["detail"]["operator_declared_untrusted"] is True
    assert server.get_computer(computer_id)["status"] == "stopped"


def test_the_lever_is_admin_only(live_start):
    """A workspace-scoped key must not be able to fail the whole runtime closed."""
    server, client = live_start
    ws = client.post("/workspaces", headers=AUTH, json={"name": "scoped"}).json()
    key = client.post(
        "/api-keys", headers=AUTH, json={"name": "scoped", "workspace_id": ws["id"]}
    ).json()
    scoped = {"Authorization": f"Bearer {key['key']}"}

    response = client.post(
        "/admin/clock-trust", headers=scoped, json={"untrusted_for_seconds": 60}
    )
    assert response.status_code == 403
    assert client.get("/health").json()["clock"]["trusted"] is True


def test_the_lever_is_bounded_and_self_expiring(live_start):
    """A forgotten override must not become permanent."""
    server, client = live_start
    response = client.post(
        "/admin/clock-trust", headers=AUTH, json={"untrusted_for_seconds": 999_999}
    )
    assert response.status_code == 422, "over the cap is rejected, not silently clamped"

    import backlot.server as server_mod

    server_mod.declare_clock_untrusted(server_mod.CLOCK_DISTRUST_MAX_SECONDS + 10_000)
    assert (
        server_mod._clock_distrust_until - server_mod.time.monotonic()
        <= server_mod.CLOCK_DISTRUST_MAX_SECONDS + 1
    ), "the internal helper clamps even if a caller reaches it directly"


def test_the_override_window_is_measured_on_the_monotonic_clock(live_start, monkeypatch):
    """Otherwise a wall-clock jump would be an escape hatch out of the very
    state that exists because the wall clock cannot be trusted."""
    server, client = live_start
    client.post("/admin/clock-trust", headers=AUTH, json={"untrusted_for_seconds": 600})
    import backlot.server as server_mod

    monkeypatch.setattr(
        server_mod.time, "time", lambda: server_mod._CLOCK_ANCHOR_WALL + 86_400
    )
    assert client.get("/health").json()["clock"]["operator_declared_untrusted"] is True


# --- implementation milestone section 8A.0: the runtime signing key (gaps L1, L2) -------------


def _seed() -> str:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    key = ed25519.Ed25519PrivateKey.generate()
    return base64.b64encode(
        key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()


def test_a_runtime_with_no_key_refuses_rather_than_signing_nothing(live_start, monkeypatch):
    """The default state today, and the safe one.

    An unsigned acknowledgement is indistinguishable from a real one to a
    consumer that does not check, so the absence of a key must be a refusal, not
    a degraded success.
    """
    import backlot.server as server

    monkeypatch.delenv(server.RUNTIME_KEY_ENV, raising=False)
    assert server.signing_state()["available"] is False
    with pytest.raises(HTTPException) as caught:
        server.sign_runtime_payload({"hello": "world"})
    assert caught.value.status_code == 503
    assert caught.value.detail["code"] == "signing_key_unavailable"


def test_a_signature_verifies_against_the_published_public_key(live_start, monkeypatch):
    """End to end: sign here, verify with only what /runtime-keys hands out."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    server, client = live_start
    monkeypatch.setenv(server.RUNTIME_KEY_ENV, _seed())

    signed = server.sign_runtime_payload({"lease_id": "l1", "persisted_seq": 7})
    published = client.get("/runtime-keys", headers=AUTH).json()
    active = next(k for k in published["keys"] if k["use"] == "active")

    public = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(active["x"] + "==")
    )
    body = json.dumps(signed["payload"], separators=(",", ":"), sort_keys=True).encode()
    public.verify(base64.urlsafe_b64decode(signed["signature"] + "=="), body)  # raises on mismatch

    assert signed["kid"] == active["thumbprint"]
    assert signed["alg"] == "EdDSA"


def test_the_signature_is_byte_identical_on_a_retry(live_start, monkeypatch):
    """Section 8A.1 requires that a crash between persist and sign regenerates a
    byte-identical acknowledgement. That is only true if the signed bytes are
    canonical, so key order and whitespace must not leak into them."""
    import backlot.server as server

    monkeypatch.setenv(server.RUNTIME_KEY_ENV, _seed())
    first = server.sign_runtime_payload({"b": 2, "a": 1, "nested": {"z": 1, "y": 2}})
    second = server.sign_runtime_payload({"nested": {"y": 2, "z": 1}, "a": 1, "b": 2})
    assert first["signature"] == second["signature"], (
        "same content in a different key order must produce the same signature"
    )


def test_the_thumbprint_follows_rfc_7638(live_start, monkeypatch):
    """Fixed by the RFC, not by us. That is the point: two implementations that
    both follow it derive the same key id without having agreed on anything."""
    import backlot.server as server

    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(
            b'{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}'
        ).digest()
    ).decode().rstrip("=")
    assert server.jwk_thumbprint(jwk) == expected


def test_rotation_publishes_the_previous_key_so_leases_in_flight_survive(
    live_start, monkeypatch
):
    """Publishing only the active key would silently invalidate every lease that
    was valid when it was minted. Overlap is the whole rotation design."""
    server, client = live_start
    old_seed, new_seed = _seed(), _seed()
    monkeypatch.setenv(server.RUNTIME_KEY_ENV, new_seed)
    monkeypatch.setenv(server.RUNTIME_KEY_PREVIOUS_ENV, old_seed)

    published = client.get("/runtime-keys", headers=AUTH).json()
    uses = {k["use"] for k in published["keys"]}
    assert uses == {"active", "previous"}
    thumbprints = {k["thumbprint"] for k in published["keys"]}
    assert len(thumbprints) == 2, "two distinct keys, not the same one twice"

    state = server.signing_state()
    assert state["rotation_overlap_active"] is True
    assert state["active_thumbprint"] != state["previous_thumbprint"]
    # Signing always uses the ACTIVE key. A rotation that kept signing with the
    # old key would make the overlap pointless.
    assert server.sign_runtime_payload({"x": 1})["kid"] == state["active_thumbprint"]


def test_no_private_key_material_reaches_any_response(live_start, monkeypatch):
    """The one failure here that is unrecoverable."""
    server, client = live_start
    seed = _seed()
    monkeypatch.setenv(server.RUNTIME_KEY_ENV, seed)

    for body in (
        client.get("/runtime-keys", headers=AUTH).text,
        client.get("/health").text,
        json.dumps(server.signing_state()),
        json.dumps(server.sign_runtime_payload({"a": 1})),
    ):
        assert seed not in body
        assert seed.rstrip("=") not in body
        assert "private" not in body.lower()


def test_a_corrupt_key_is_treated_as_absent_and_never_echoed(live_start, monkeypatch, capsys):
    """A subtly corrupted key that still loaded would produce signatures nobody
    can verify, which is worse than having none. And the diagnostic must name
    the variable, never any part of its value."""
    import backlot.server as server

    monkeypatch.setenv(server.RUNTIME_KEY_ENV, "not-valid-base64-!!!")
    assert server.signing_state()["available"] is False
    assert server.RUNTIME_KEY_ENV in capsys.readouterr().out

    monkeypatch.setenv(server.RUNTIME_KEY_ENV, base64.b64encode(b"tooshort").decode())
    assert server.signing_state()["available"] is False


def test_the_key_set_is_not_reachable_without_a_bearer_key(live_start):
    """INTERNAL-ONLY is product law. Public keys being safe to publish is not a
    reason to grow an unauthenticated surface."""
    _, client = live_start
    assert client.get("/runtime-keys").status_code == 401
