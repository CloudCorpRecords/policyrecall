# policyrecall — Build Report

MCP Rebuild 1000. Clean-room rebuild of
achromat-ai/achromat-mcp-server (MCP Registry rank 197, 1 star),
built from the public README spec captured in
`harness/fixtures/achromat-mcp-server-tools-original.json`. That
fixture is docs-derived: the tools are the full documented set of
3 and the parameter tables are documented in the README. Parity
proves the rebuild matches this program's defined spec, labelled
docs-derived. Local build only — nothing pushed or published.

Identity: repo `policyrecall`, npm `@reneturcios/policyrecall`,
MCP name `io.github.CloudCorpRecords/policyrecall`, version `0.1.0`.
Tool names keep the original `achromat_` prefix inside the
protocol, per the task spec; only the package/server name changed.

## Files created (19/19 per TEMPLATE.md checklist)

- `package.json` — bin `policyrecall: dist/cli.js`, `mcpName` set,
  scripts build=`tsc` / dev=`tsx src/cli.ts` / test=`tsx --test test/*.test.ts`
- `server.json` — description "Policy-verified recall and
  calibration for tool calls via signed operational memory."
  = **84 chars** (≤100 ✓); npm entry carries `version: 0.1.0`;
  OCI entry `ghcr.io/cloudcorprecords/policyrecall:0.1.0` carries
  **no** `version` field (verified programmatically)
- `Dockerfile` — node:20-alpine two-stage, ENTRYPOINT
  `node /app/dist/cli.js`, CMD `mcp`, label
  `io.modelcontextprotocol.server.name="io.github.CloudCorpRecords/policyrecall"`
- `tsconfig.json` (identical to the fleet template), `.gitignore`,
  `LICENSE` (MIT, Copyright (c) 2026 Rene Turcios), `README.md`
  (fresh text), `CHANGELOG.md` (single 0.1.0 entry, 2026-10-27)
- `src/index.ts`, `src/cli.ts` (subcommands mirror the tool
  names, plus `mcp` and `--version`; exit 2 usage / 1 error),
  `src/mcp.ts`, `src/types.ts`, `src/policyrecall.ts` (core
  logic, `VERSION = "0.1.0"`)
- `test/policyrecall.test.ts`
- `.github/workflows/{ci,publish,publish-container,registry-publish}.yml`
  (from the fleet template; image name and smoke-test server name
  changed to policyrecall)

## Tools implemented (3)

- `achromat_register_identity` — `{user_confirmed* boolean}`.
  Errors unless `user_confirmed` is exactly `true`, and errors
  when a key file already exists. Otherwise generates an Ed25519
  keypair (node:crypto), computes a small proof-of-work, POSTs
  the public-key registration via the injectable fetch, and saves
  the private key as a PKCS#8 PEM file (mode 0600) **only after**
  the service accepts.
- `achromat_recall` — `{domain* enum [fintech, industrial_iot,
  robotics, devsecops], tool_name*, task_description* (16–1000
  chars), arguments* (non-empty object)}`. Signed POST via the
  injectable fetch; `tool_name` is sent as the service's `tool`
  field.
- `achromat_calibrate` — same as recall plus optional `trap_id`.

State behaviour: recall/calibrate with no key file return an
honest `isError` saying identity setup is required (register
first), before any request; register with an existing key file
errors, also before any request.

## Implementation notes

- `src/mcp.ts` uses the SDK's low-level `Server` with explicit
  inputSchema literals, per the standing fleet rule: `McpServer`'s
  zod-to-JSON-Schema conversion injects `$schema` /
  `additionalProperties` keys that are absent from the defined
  spec and break exact schema parity. Zod still validates every
  `tools/call` (domain enum, description length 16–1000,
  non-empty `arguments`).
- Config: `ACHROMAT_BASE_URL` (default
  `https://mom.achromat.ai`, trailing slashes stripped) and
  `ACHROMAT_AGENT_KEY_FILE` (default
  `~/.achromat/achromat_agent_key.pem`).
- Proof-of-work (reconstructed): the smallest decimal nonce such
  that `sha256("<publicKeyPem>:<nonce>")` in hex starts with
  `00` (~256 tries on average). Registration body:
  `{public_key (SPKI PEM), proof_of_work_nonce, key_fingerprint}`
  POSTed to `/register`.
- Signing (reconstructed): the signed payload is
  `"<unix-seconds>.<body-json>"`, signed with Ed25519
  (node:crypto, null digest); the timestamp and base64 signature
  travel as `X-Achromat-Timestamp` / `X-Achromat-Signature`
  headers, with the SPKI SHA-256 fingerprint as
  `X-Achromat-Key-Fingerprint`. Endpoints: `POST /recall` and
  `POST /calibrate`.
- HTTP failures surface the status plus the upstream `message`
  or `error` string when present.
- All HTTP flows through an injectable `FetchFn` (types.ts). The
  test suite uses a fake fetch plus real local Ed25519 key
  generation and signing in temp dirs; no live call is made in
  tests, and none is claimed.

## Verification (foreground, exact outputs)

### 1. Build
```
$ npm run build   (tsc)
build_exit=0
```
`dist/` produced, including `dist/cli.js`.

### 2. Tests
```
$ npm test   (tsx --test test/*.test.ts)
ℹ tests 19
ℹ pass 19
ℹ fail 0
```
Covers: base-URL default/custom/trailing-slash handling, default
key-file path, and env config resolution; PoW nonce computation
and verification; canonical signing string shape;
`user_confirmed !== true` rejected before any request; a full
registration (POST `/register`, public key in body, PoW verifies
against that key, fingerprint matches, private key saved only
after acceptance with mode 0600 and a public key that pairs with
the sent one); no key file saved when the service rejects (HTTP
400); existing key file errors before any request and is left
untouched; recall/calibrate with no key file error naming
identity setup before any request; recall POSTs to `/recall`
mapping `tool_name` → `tool` (and not sending `tool_name`), with
a signature that verifies against the registered public key over
the exact captured body, a tampered body failing verification,
and the fingerprint header matching; sign/verify round-trip with
a real generated key; custom base URL; calibrate POSTs to
`/calibrate` with `trap_id` included when given and omitted when
not; task-description length, empty arguments, blank tool name,
and unknown domain all rejected before any request; every
documented domain accepted; HTTP 403 surfacing the upstream
error; network failure wrapping.

### 3. CLI / MCP smoke
`--version` → `0.1.0` (exit 0); unknown command exits 2 with
Usage. MCP `initialize` over stdio → `serverInfo:
{"name":"policyrecall","version":"0.1.0"}`; `tools/list`
returned exactly the 3 documented tools with the fixture
schemas; a stdio `tools/call` for `achromat_recall` with the key
file pointed at a nonexistent path returned an `isError` result
saying identity setup is required and naming
`achromat_register_identity` — the state gate, exercised end to
end with no live service call made and none claimed.

### 4. Parity (harness, from ~/workspace/mcp-rebuild-100/harness/)
```
$ python3 parity.py --original fixtures/achromat-mcp-server-tools-original.json \
    --rebuild "stdio:node .../builds/policyrecall/dist/cli.js mcp" \
    --out /tmp/policyrecall-parity
verdict=PASS parity_pct=100.0 original_tools=3 rebuild_tools=3 missing=[] extra=[] schema_diffs=[]
(exit 0)
```
(parity.json: identical_tools 3/3.) Original side is tools-file
mode, so `fixture_results` records `SKIPPED-TOOLS-FILE-MODE` —
expected harness semantics, not an error. The passing run wrote
to /tmp and its parity.json/parity.md were copied into
`parity-out/` and verified non-empty (1014 and 801 bytes).

## Lockfile status

`package-lock.json` was generated clean via Route 3: a temp copy
holding only `package.json` (no `node_modules`), offline
`npm install --package-lock-only --ignore-scripts`, verified
after generation — parses as JSON, top-level `name` is
`@reneturcios/policyrecall`, version `0.1.0`, `lockfileVersion`
3, **128 package entries** — then only the lockfile was copied
back. Local `node_modules` is a copy of the sociallens sibling's
tree used only for the local build/test; it is not part of the
lockfile generation.

## Gaps / honest notes

- **Dynamic tool list difference:** the original offers tools
  dynamically by key state (e.g. only registration before an
  identity exists). This rebuild registers all 3 tools
  statically and gates by state at call time, per the task spec;
  tools/list parity is therefore measured against the full
  documented set of 3.
- **Signing contract is reconstructed, not probed:** the
  service's byte-level signing contract (canonical payload,
  header names, endpoint paths `/register`, `/recall`,
  `/calibrate`, the PoW construction and its difficulty, and the
  registration body fields) is a documented reconstruction from
  the public spec statement that requests are Ed25519-signed
  with a locally held key — no original server or live service
  was probed, so live interoperability is unverified until the
  publish wave.
- Docs-derived spec: parity proves the rebuild matches this
  program's defined spec from the public README's parameter
  tables, not a hand-probed original.
- No live call was made: every endpoint is fake-fetch tested
  only (with real local key generation/signing), so live
  payload/response-shape drift against mom.achromat.ai is
  unverified.
- Container build not exercised locally; the publish-container
  workflow smoke-tests the image at publish time.
