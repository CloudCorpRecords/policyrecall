# Changelog

## 0.1.0 (2026-10-27)

- Initial release.
- CLI subcommands mirror the MCP tools (`achromat_register_identity`,
  `achromat_recall`, `achromat_calibrate`), plus `policyrecall mcp`
  and `--version`.
- MCP server (`policyrecall mcp`, stdio) with the full documented
  tool set of three tools, registered statically; state is gated at
  call time instead of by offering tools dynamically.
- Registration generates an Ed25519 keypair, computes a small
  proof-of-work, registers the public key with the service, and
  saves the private key as a PKCS#8 PEM file (mode 0600) only after
  the service accepts; an existing key file is never overwritten.
- Recall and calibrate are Ed25519-signed POSTs; `tool_name` is sent
  to the service as its `tool` field. With no key file they error,
  saying identity setup is required.
- Configuration via `ACHROMAT_BASE_URL` (default
  `https://mom.achromat.ai`) and `ACHROMAT_AGENT_KEY_FILE` (default
  `~/.achromat/achromat_agent_key.pem`).
- All HTTP goes through an injectable fetch function, so the test
  suite runs entirely on fake-fetch fixtures plus real local key
  generation and signing, with no network access.
