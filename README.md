# policyrecall

policyrecall is a client for a hosted operational-memory service.
Once an agent identity is registered, the service can recall a
policy-verified compliant version of a tool call you are about to
make, and it can calibrate a call against live policy. Requests
are signed with a locally held Ed25519 key, so the service can
tell that a call really came from the registered agent. One
binary serves a command-line interface and a stdio MCP server.

## Identity and configuration

Before recall or calibration can work, an identity must exist:

```bash
policyrecall achromat_register_identity --user-confirmed true
```

Registration generates a fresh Ed25519 keypair, computes a small
proof-of-work over the public key, and sends the public key to the
service. The private key is saved only after the service accepts,
as a PKCS#8 PEM file with owner-only permissions (`0600`).
Registering again while a key file already exists is an error —
the existing key is never overwritten. Recall and calibrate with
no key file fail with an error that says identity setup is
required and names the registration step.

Two environment variables configure the client:

| Variable | Default |
| --- | --- |
| `ACHROMAT_BASE_URL` | `https://mom.achromat.ai` |
| `ACHROMAT_AGENT_KEY_FILE` | `~/.achromat/achromat_agent_key.pem` |

Unlike the original server, which offers its tools dynamically
depending on key state, policyrecall always lists all three tools
and applies the state check when a tool is called.

## Install

```bash
npx @reneturcios/policyrecall --version
```

Or run the container image:

```bash
docker run -i ghcr.io/cloudcorprecords/policyrecall
```

The container defaults to the MCP server (see below). Pass CLI
arguments to use it as a CLI instead.

## CLI

The subcommands mirror the MCP tool names:

```bash
policyrecall achromat_register_identity --user-confirmed true

policyrecall achromat_recall \
  --domain fintech \
  --tool-name send_payment \
  --task-description "Pay a verified vendor invoice on time" \
  --arguments '{"amount": 42, "currency": "USD"}'

policyrecall achromat_calibrate \
  --domain robotics \
  --tool-name move_arm \
  --task-description "Move the arm to the loading position" \
  --arguments '{"joint": 2, "angle": 45}' \
  --trap-id trap-7

policyrecall --version
```

`--arguments` takes a JSON object. Results print the upstream
JSON payload. Exit codes: `0` on success, `1` when a call fails
(including a missing identity or an upstream error), `2` for
usage errors.

## MCP server

The `mcp` subcommand starts a stdio MCP server:

```bash
npx -y @reneturcios/policyrecall mcp
```

MCP client configuration:

```json
{
  "mcpServers": {
    "policyrecall": {
      "command": "npx",
      "args": ["-y", "@reneturcios/policyrecall", "mcp"],
      "env": { "ACHROMAT_BASE_URL": "https://mom.achromat.ai" }
    }
  }
}
```

### Tools

| Tool | Input | What it does |
| --- | --- | --- |
| `achromat_register_identity` | `user_confirmed` (required, must be `true`) | Generate an Ed25519 keypair, solve a small proof-of-work, register the public key, and save the private key locally. |
| `achromat_recall` | `domain`, `tool_name`, `task_description`, `arguments` (all required) | Recall a policy-verified compliant version of the described tool call. |
| `achromat_calibrate` | `domain`, `tool_name`, `task_description`, `arguments` (required), `trap_id` (optional) | Calibrate the described tool call against live policy. |

`domain` is one of `fintech`, `industrial_iot`, `robotics`, or
`devsecops`. `task_description` is 16 to 1000 characters, and
`arguments` is the call's argument object, which must not be
empty. Recall and calibrate requests are signed with the local
key; the service receives the tool name under its `tool` field.

## Development

```bash
npm install
npm run build   # tsc -> dist/
npm test        # node test runner over test/*.test.ts, fake fetch only
npm run dev     # run the CLI from source via tsx
```

Tests use a fake fetch plus real local key generation and signing
in temporary directories; no live service call is made.

## License

MIT — see `LICENSE`.
