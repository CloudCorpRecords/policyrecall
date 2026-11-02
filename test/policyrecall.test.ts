import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  calibrate,
  canonicalSigningString,
  computeProofOfWork,
  defaultKeyFile,
  publicKeyFingerprint,
  publicKeyPemFromPrivate,
  recall,
  registerIdentity,
  resolveBaseUrl,
  resolveConfig,
  resolveKeyFile,
  signBody,
  verifyBodySignature,
  verifyProofOfWork,
} from "../src/policyrecall.js";
import type { FetchFn, HttpResponse, PolicyrecallConfig } from "../src/types.js";

function jsonResponse(body: unknown, status = 200, statusText = "OK"): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    headers: { get: () => "application/json" },
    text: async () => JSON.stringify(body),
    json: async () => body,
  };
}

interface Captured {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  calls: number;
}

function fakeFetch(body: unknown = {}): { fetchFn: FetchFn; captured: Captured } {
  const captured: Captured = { calls: 0 };
  const fetchFn: FetchFn = async (url, init) => {
    captured.calls += 1;
    captured.url = url;
    captured.method = init?.method;
    captured.headers = init?.headers;
    captured.body = init?.body;
    return jsonResponse(body);
  };
  return { fetchFn, captured };
}

function tempConfig(): { config: PolicyrecallConfig; dir: string; keyFile: string } {
  const dir = mkdtempSync(join(tmpdir(), "policyrecall-test-"));
  const keyFile = join(dir, "nested", "agent_key.pem");
  return { config: { baseUrl: "https://mom.achromat.ai", keyFile }, dir, keyFile };
}

const RECALL_ARGS = {
  domain: "fintech" as const,
  tool_name: "send_payment",
  task_description: "Pay a verified vendor invoice on time",
  arguments: { amount: 42, currency: "USD" },
};

async function registeredConfig(): Promise<{ config: PolicyrecallConfig; keyFile: string }> {
  const { config, keyFile } = tempConfig();
  const { fetchFn } = fakeFetch({ accepted: true });
  await registerIdentity(fetchFn, config, { user_confirmed: true });
  return { config, keyFile };
}

describe("config resolution", () => {
  it("defaults base URL, strips trailing slashes, and resolves the default key file", () => {
    assert.equal(resolveBaseUrl(undefined), "https://mom.achromat.ai");
    assert.equal(resolveBaseUrl("  "), "https://mom.achromat.ai");
    assert.equal(resolveBaseUrl("https://example.test/api/"), "https://example.test/api");
    assert.equal(defaultKeyFile("/home/tester"), "/home/tester/.achromat/achromat_agent_key.pem");
    assert.equal(resolveKeyFile(undefined, "/home/tester"), "/home/tester/.achromat/achromat_agent_key.pem");
    assert.equal(resolveKeyFile(" /tmp/k.pem "), "/tmp/k.pem");
    const cfg = resolveConfig({ ACHROMAT_BASE_URL: "https://x.test/" });
    assert.equal(cfg.baseUrl, "https://x.test");
    assert.ok(cfg.keyFile.endsWith(".achromat/achromat_agent_key.pem"));
  });
});

describe("proof of work and signing helpers", () => {
  it("computes a nonce whose hash starts with 00 and verifies it", () => {
    const pem = "-----BEGIN PUBLIC KEY-----\nfake-for-pow-test\n-----END PUBLIC KEY-----\n";
    const nonce = computeProofOfWork(pem);
    assert.equal(verifyProofOfWork(pem, nonce), true);
    assert.match(nonce, /^\d+$/);
  });

  it("canonical signing string is <timestamp>.<body>", () => {
    assert.equal(canonicalSigningString("1700000000", '{"a":1}'), '1700000000.{"a":1}');
  });
});

describe("achromat_register_identity", () => {
  it("requires user_confirmed to be true, before any request", async () => {
    const { config } = tempConfig();
    const { fetchFn, captured } = fakeFetch({});
    await assert.rejects(
      () => registerIdentity(fetchFn, config, { user_confirmed: false }),
      /user_confirmed must be true/,
    );
    assert.equal(captured.calls, 0);
  });

  it("registers, POSTs public key + valid PoW, and saves the private key 0600 only after acceptance", async () => {
    const { config, keyFile } = tempConfig();
    const { fetchFn, captured } = fakeFetch({ accepted: true, agent_id: "ag1" });
    assert.equal(existsSync(keyFile), false);
    const out = (await registerIdentity(fetchFn, config, { user_confirmed: true })) as Record<string, unknown>;
    assert.equal(out.registered, true);
    assert.equal(out.key_file, keyFile);
    assert.equal(captured.method, "POST");
    assert.equal(captured.url, "https://mom.achromat.ai/register");
    const sent = JSON.parse(captured.body ?? "{}") as Record<string, string>;
    assert.match(sent.public_key, /BEGIN PUBLIC KEY/);
    assert.equal(verifyProofOfWork(sent.public_key, sent.proof_of_work_nonce), true);
    assert.equal(sent.key_fingerprint, publicKeyFingerprint(sent.public_key));
    // The saved file is the matching PKCS#8 private key, mode 0600.
    assert.equal(existsSync(keyFile), true);
    const saved = readFileSync(keyFile, "utf8");
    assert.match(saved, /BEGIN PRIVATE KEY/);
    assert.equal(publicKeyPemFromPrivate(saved), sent.public_key);
    assert.equal(statSync(keyFile).mode & 0o777, 0o600);
  });

  it("does NOT save a key file when the service rejects registration", async () => {
    const { config, keyFile } = tempConfig();
    const failing: FetchFn = async () => jsonResponse({ message: "bad proof of work" }, 400, "Bad Request");
    await assert.rejects(
      () => registerIdentity(failing, config, { user_confirmed: true }),
      /HTTP 400.*bad proof of work/,
    );
    assert.equal(existsSync(keyFile), false);
  });

  it("errors when a key file already exists, before any request", async () => {
    const { config, dir } = tempConfig();
    const existing = join(dir, "existing.pem");
    writeFileSync(existing, "sentinel");
    const cfg: PolicyrecallConfig = { baseUrl: config.baseUrl, keyFile: existing };
    const { fetchFn, captured } = fakeFetch({});
    await assert.rejects(
      () => registerIdentity(fetchFn, cfg, { user_confirmed: true }),
      /identity already exists/,
    );
    assert.equal(captured.calls, 0);
    assert.equal(readFileSync(existing, "utf8"), "sentinel");
  });
});

describe("identity gate for recall / calibrate", () => {
  it("recall with no key file errors naming identity setup, before any request", async () => {
    const { config } = tempConfig();
    const { fetchFn, captured } = fakeFetch({});
    await assert.rejects(() => recall(fetchFn, config, RECALL_ARGS), /identity setup is required.*achromat_register_identity/);
    assert.equal(captured.calls, 0);
  });

  it("calibrate with no key file errors naming identity setup, before any request", async () => {
    const { config } = tempConfig();
    const { fetchFn, captured } = fakeFetch({});
    await assert.rejects(() => calibrate(fetchFn, config, RECALL_ARGS), /identity setup is required/);
    assert.equal(captured.calls, 0);
  });
});

describe("achromat_recall", () => {
  it("POSTs a signed request mapping tool_name to the service's tool field", async () => {
    const { config, keyFile } = await registeredConfig();
    const payload = { compliant: true, tool: "send_payment", arguments: { amount: 42 } };
    const { fetchFn, captured } = fakeFetch(payload);
    const out = await recall(fetchFn, config, RECALL_ARGS);
    assert.deepEqual(out, payload);
    assert.equal(captured.calls, 1);
    assert.equal(captured.method, "POST");
    assert.equal(captured.url, "https://mom.achromat.ai/recall");
    const sent = JSON.parse(captured.body ?? "{}") as Record<string, unknown>;
    assert.deepEqual(sent, {
      domain: "fintech",
      tool: "send_payment",
      task_description: RECALL_ARGS.task_description,
      arguments: { amount: 42, currency: "USD" },
    });
    assert.equal("tool_name" in sent, false);
    // The signature verifies against the public key paired with the saved private key.
    const privatePem = readFileSync(keyFile, "utf8");
    const publicPem = publicKeyPemFromPrivate(privatePem);
    const ts = captured.headers?.["X-Achromat-Timestamp"] ?? "";
    const sig = captured.headers?.["X-Achromat-Signature"] ?? "";
    assert.match(ts, /^\d+$/);
    assert.equal(verifyBodySignature(publicPem, ts, captured.body ?? "", sig), true);
    assert.equal(captured.headers?.["X-Achromat-Key-Fingerprint"], publicKeyFingerprint(publicPem));
    // A tampered body does not verify.
    assert.equal(verifyBodySignature(publicPem, ts, '{"tampered":true}', sig), false);
  });

  it("signBody / verify round-trip works with a real generated key", async () => {
    const { keyFile } = await registeredConfig();
    const privatePem = readFileSync(keyFile, "utf8");
    const sig = signBody(privatePem, "1700000001", '{"x":2}');
    assert.equal(
      verifyBodySignature(publicKeyPemFromPrivate(privatePem), "1700000001", '{"x":2}', sig),
      true,
    );
  });

  it("honours a custom base URL", async () => {
    const { config } = await registeredConfig();
    const { fetchFn, captured } = fakeFetch({});
    await recall(fetchFn, { ...config, baseUrl: "https://example.test/api/" }, RECALL_ARGS);
    assert.equal(captured.url, "https://example.test/api/recall");
  });
});

describe("achromat_calibrate", () => {
  it("POSTs a signed calibrate request, including trap_id when given", async () => {
    const { config } = await registeredConfig();
    const { fetchFn, captured } = fakeFetch({ verdict: "allow" });
    const out = await calibrate(fetchFn, config, { ...RECALL_ARGS, trap_id: "trap-7" });
    assert.deepEqual(out, { verdict: "allow" });
    assert.equal(captured.url, "https://mom.achromat.ai/calibrate");
    const sent = JSON.parse(captured.body ?? "{}") as Record<string, unknown>;
    assert.equal(sent.tool, "send_payment");
    assert.equal(sent.trap_id, "trap-7");
    assert.ok(captured.headers?.["X-Achromat-Signature"]);
  });

  it("omits trap_id when not given", async () => {
    const { config } = await registeredConfig();
    const { fetchFn, captured } = fakeFetch({});
    await calibrate(fetchFn, config, RECALL_ARGS);
    const sent = JSON.parse(captured.body ?? "{}") as Record<string, unknown>;
    assert.equal("trap_id" in sent, false);
  });
});

describe("argument validation", () => {
  it("rejects a short task_description before any request", async () => {
    const { config } = await registeredConfig();
    const { fetchFn, captured } = fakeFetch({});
    await assert.rejects(
      () => recall(fetchFn, config, { ...RECALL_ARGS, task_description: "too short" }),
      /task_description must be between 16 and 1000/,
    );
    assert.equal(captured.calls, 0);
  });

  it("rejects empty arguments, a blank tool_name, and an unknown domain", async () => {
    const { config } = await registeredConfig();
    const { fetchFn, captured } = fakeFetch({});
    await assert.rejects(() => recall(fetchFn, config, { ...RECALL_ARGS, arguments: {} }), /non-empty object/);
    await assert.rejects(() => recall(fetchFn, config, { ...RECALL_ARGS, tool_name: "  " }), /tool_name/);
    await assert.rejects(
      () => recall(fetchFn, config, { ...RECALL_ARGS, domain: "space" as never }),
      /domain must be one of/,
    );
    assert.equal(captured.calls, 0);
  });

  it("accepts every documented domain", async () => {
    const { config } = await registeredConfig();
    for (const domain of ["fintech", "industrial_iot", "robotics", "devsecops"] as const) {
      const { fetchFn, captured } = fakeFetch({});
      await recall(fetchFn, config, { ...RECALL_ARGS, domain });
      const sent = JSON.parse(captured.body ?? "{}") as Record<string, unknown>;
      assert.equal(sent.domain, domain);
    }
  });
});

describe("errors", () => {
  it("HTTP 403 surfaces status and upstream message", async () => {
    const { config } = await registeredConfig();
    const failing: FetchFn = async () => jsonResponse({ error: "signature rejected" }, 403, "Forbidden");
    await assert.rejects(() => recall(failing, config, RECALL_ARGS), /HTTP 403.*signature rejected/);
  });

  it("network failure is wrapped with context", async () => {
    const { config } = await registeredConfig();
    const failing: FetchFn = async () => {
      throw new Error("connection reset");
    };
    await assert.rejects(() => calibrate(failing, config, RECALL_ARGS), /Achromat service request failed: connection reset/);
  });
});
