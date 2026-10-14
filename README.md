# Backlot

Backlot is an experimental control plane for remote Linux desktops in Modal sandboxes. It includes a REST service, a Python CLI/client, a sandbox-side desktop agent, and an OpenAI-compatible computer-use endpoint.

## Setup

Requires Python 3.11 or newer, `uv`, and Modal credentials for deployment.

```sh
uv sync
uv run modal secret create backlot-secrets \
  BACKLOT_BOOTSTRAP_KEY="<your-bootstrap-key>" \
  OPENROUTER_API_KEY="<your-provider-key>"
uv run modal deploy backlot/server.py
```

The provider key is needed for provider-backed computer-use requests. Set `BACKLOT_PROVIDER_URL` and `BACKLOT_PROVIDER_MODEL` in the Modal secret only if you need to override the defaults. For the CLI, set `BACKLOT_BASE_URL="https://your-service.example.invalid"` and `BACKLOT_API_KEY="<your-api-key>"`, then run commands such as `uv run backlot ls`.

Deployment creates remote resources and may incur charges. The commands above are documentation only; this snapshot was not installed or deployed.

## Status

This is an experimental as-is source snapshot. Runtime behavior, cloud deployment, authentication, provider requests, desktop interaction, and dependency security/currentness were not verified here. Existing bugs and incomplete behavior may remain. No production or hosted-service assurance is made. Runtime tools downloaded by the sandbox image are separate dependencies and remain under their own upstream terms.

## License

MIT; see [LICENSE](LICENSE). Dependencies and separately downloaded runtime tools retain their upstream terms.
