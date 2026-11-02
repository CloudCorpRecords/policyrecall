/**
 * policyrecall core: a client for a hosted operational-memory
 * service that recalls policy-verified compliant versions of tool
 * calls and calibrates calls against live policy.
 *
 * Identity: a locally held Ed25519 keypair. Registration
 * (achromat_register_identity) generates a keypair, computes a
 * small proof-of-work over the public key, and POSTs the public
 * key to the service; the private key is written as a PKCS#8 PEM
 * file with mode 0600 ONLY after the service accepts. Registering
 * when a key file already exists is an error. Recall and calibrate
 * with no key file are errors that name the missing setup step and
 * make no request.
 *
 * Signing (reconstructed contract, see BUILD-REPORT gaps): each
 * recall / calibrate body is serialised once as JSON; the signed
 * payload is "<unix-seconds>.<body-json>", signed with Ed25519
 * (node:crypto sign with a null digest). The timestamp and the
 * base64 signature travel as X-Achromat-Timestamp /
 * X-Achromat-Signature headers, alongside the public-key
 * fingerprint as X-Achromat-Key-Fingerprint. The service's
 * byte-level signing contract was not probed; this shape is a
 * documented reconstruction from the public spec statement that
 * requests are Ed25519-signed with a locally held key.
 *
 * Endpoint map (reconstructed):
 *   achromat_register_identity  POST /register   (unsigned; PoW + public key)
 *   achromat_recall             POST /recall     (signed; tool_name -> tool)
 *   achromat_calibrate          POST /calibrate (signed; tool_name -> tool)
 *
 * Config: ACHROMAT_BASE_URL (default https://mom.achromat.ai) and
 * ACHROMAT_AGENT_KEY_FILE (default ~/.achromat/achromat_agent_key.pem).
 * All HTTP goes through an injected FetchFn so everything is
 * testable offline with a fake fetch; key generation and signing
 * use the real node:crypto implementation.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DOMAINS } from "./types.js";
import type {
  CalibrateOptions,
  FetchFn,
  PolicyDomain,
  PolicyrecallConfig,
  RecallOptions,
  RegisterOptions,
} from "./types.js";

export const VERSION = "0.1.0";

export const DEFAULT_BASE_URL = "https://mom.achromat.ai";
export const BASE_URL_ENV = "ACHROMAT_BASE_URL";
export const KEY_FILE_ENV = "ACHROMAT_AGENT_KEY_FILE";

/** Default key file: ~/.achromat/achromat_agent_key.pem. */
export function defaultKeyFile(homeDir?: string): string {
  return join(homeDir ?? homedir(), ".achromat", "achromat_agent_key.pem");
}

export function resolveBaseUrl(value?: string): string {
  const v = typeof value === "string" ? value.trim() : "";
  return (v ? v : DEFAULT_BASE_URL).replace(/\/+$/, "");
}

export function resolveKeyFile(value?: string, homeDir?: string): string {
  const v = typeof value === "string" ? value.trim() : "";
  return v ? v : defaultKeyFile(homeDir);
}

export function resolveConfig(env: {
  [BASE_URL_ENV]?: string;
  [KEY_FILE_ENV]?: string;
}): PolicyrecallConfig {
  return {
    baseUrl: resolveBaseUrl(env[BASE_URL_ENV]),
    keyFile: resolveKeyFile(env[KEY_FILE_ENV]),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// --- proof of work ------------------------------------------------------

/**
 * Small proof-of-work: find the smallest non-negative integer nonce
 * (as a decimal string) such that sha256("<publicKeyPem>:<nonce>")
 * in hex starts with "00" (8 zero bits, ~256 tries on average).
 */
export function computeProofOfWork(publicKeyPem: string): string {
  for (let n = 0; ; n += 1) {
    const hash = createHash("sha256").update(`${publicKeyPem}:${n}`).digest("hex");
    if (hash.startsWith("00")) return String(n);
  }
}

export function verifyProofOfWork(publicKeyPem: string, nonce: string): boolean {
  const hash = createHash("sha256").update(`${publicKeyPem}:${nonce}`).digest("hex");
  return hash.startsWith("00");
}

// --- signing --------------------------------------------------------------

/** The exact byte string that is signed for a request body. */
export function canonicalSigningString(timestamp: string, bodyJson: string): string {
  return `${timestamp}.${bodyJson}`;
}

/** Ed25519-sign a serialised body; returns the base64 signature. */
export function signBody(privateKeyPem: string, timestamp: string, bodyJson: string): string {
  const key = createPrivateKey(privateKeyPem);
  const sig = cryptoSign(null, Buffer.from(canonicalSigningString(timestamp, bodyJson), "utf8"), key);
  return sig.toString("base64");
}

/** Verify a base64 Ed25519 signature over a serialised body. */
export function verifyBodySignature(
  publicKeyPem: string,
  timestamp: string,
  bodyJson: string,
  signatureBase64: string,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return cryptoVerify(
      null,
      Buffer.from(canonicalSigningString(timestamp, bodyJson), "utf8"),
      key,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

/** SHA-256 hex fingerprint of a public key's SPKI DER encoding. */
export function publicKeyFingerprint(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

/** Derive the SPKI PEM public key that pairs with a private key PEM. */
export function publicKeyPemFromPrivate(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem))
    .export({ type: "spki", format: "pem" })
    .toString();
}

// --- shared HTTP helper ---------------------------------------------------

async function parseResponse(response: {
  ok: boolean;
  status: number;
  statusText?: string;
  json(): Promise<unknown>;
}): Promise<unknown> {
  if (!response.ok) {
    let detail = "";
    try {
      const payload: unknown = await response.json();
      if (isRecord(payload)) {
        if (typeof payload.message === "string" && payload.message) detail = `: ${payload.message}`;
        else if (typeof payload.error === "string" && payload.error) detail = `: ${payload.error}`;
      }
    } catch {
      // A non-JSON error body still reports its HTTP status below.
    }
    throw new Error(
      `Achromat service request failed: HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}${detail}`,
    );
  }
  try {
    return await response.json();
  } catch {
    throw new Error("Achromat service returned a response that was not valid JSON");
  }
}

async function postJson(
  fetchFn: FetchFn,
  url: string,
  body: Record<string, unknown>,
  headers: Record<string, string>,
): Promise<unknown> {
  let response;
  try {
    response = await fetchFn(url, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new Error(
      `Achromat service request failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseResponse(response);
}

// --- validation -------------------------------------------------------------

function requireIdentity(config: PolicyrecallConfig): string {
  if (!config || typeof config.keyFile !== "string" || !config.keyFile.trim()) {
    throw new Error(
      "identity setup is required: no agent key file is configured; run achromat_register_identity first",
    );
  }
  if (!existsSync(config.keyFile)) {
    throw new Error(
      `identity setup is required: no agent key file found at ${config.keyFile}; run achromat_register_identity first`,
    );
  }
  return readFileSync(config.keyFile, "utf8");
}

function validateCall(options: RecallOptions | CalibrateOptions): {
  domain: PolicyDomain;
  tool: string;
  taskDescription: string;
  args: Record<string, unknown>;
} {
  if (!isRecord(options) || !(DOMAINS as readonly string[]).includes(options.domain)) {
    throw new Error(`domain must be one of: ${DOMAINS.join(", ")}`);
  }
  const tool = typeof options.tool_name === "string" ? options.tool_name.trim() : "";
  if (!tool) throw new Error("tool_name must be a non-empty string");
  const taskDescription = typeof options.task_description === "string" ? options.task_description : "";
  if (taskDescription.length < 16 || taskDescription.length > 1000) {
    throw new Error("task_description must be between 16 and 1000 characters");
  }
  if (!isRecord(options.arguments) || Object.keys(options.arguments).length === 0) {
    throw new Error("arguments must be a non-empty object");
  }
  return { domain: options.domain, tool, taskDescription, args: options.arguments };
}

async function signedPost(
  fetchFn: FetchFn,
  config: PolicyrecallConfig,
  path: string,
  body: Record<string, unknown>,
): Promise<unknown> {
  const privateKeyPem = requireIdentity(config);
  const bodyJson = JSON.stringify(body);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = signBody(privateKeyPem, timestamp, bodyJson);
  const fingerprint = publicKeyFingerprint(publicKeyPemFromPrivate(privateKeyPem));
  let response;
  try {
    response = await fetchFn(`${resolveBaseUrl(config.baseUrl)}${path}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Achromat-Timestamp": timestamp,
        "X-Achromat-Signature": signature,
        "X-Achromat-Key-Fingerprint": fingerprint,
      },
      body: bodyJson,
    });
  } catch (err) {
    throw new Error(
      `Achromat service request failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseResponse(response);
}

// --- tools ------------------------------------------------------------------

/**
 * Register a new identity. Errors when a key file already exists or
 * when user_confirmed is not true. The private key is saved (PKCS#8
 * PEM, mode 0600) only after the service accepts the registration.
 */
export async function registerIdentity(
  fetchFn: FetchFn,
  config: PolicyrecallConfig,
  options: RegisterOptions,
): Promise<unknown> {
  if (!options || options.user_confirmed !== true) {
    throw new Error("user_confirmed must be true to register an identity");
  }
  const keyFile = resolveKeyFile(config?.keyFile);
  // resolveKeyFile maps a blank value onto the default; an explicitly
  // configured path is used verbatim.
  const target = config && typeof config.keyFile === "string" && config.keyFile.trim() ? config.keyFile : keyFile;
  if (existsSync(target)) {
    throw new Error(
      `identity already exists: a key file is already present at ${target}; refusing to overwrite it`,
    );
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const nonce = computeProofOfWork(publicKeyPem);
  const payload = await postJson(fetchFn, `${resolveBaseUrl(config.baseUrl)}/register`, {
    public_key: publicKeyPem,
    proof_of_work_nonce: nonce,
    key_fingerprint: publicKeyFingerprint(publicKeyPem),
  }, {});
  // The service accepted: only now is the private key persisted.
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, privateKeyPem, { mode: 0o600 });
  try {
    chmodSync(target, 0o600);
  } catch {
    // The write mode above already requests 0600.
  }
  return {
    registered: true,
    key_file: target,
    public_key: publicKeyPem,
    key_fingerprint: publicKeyFingerprint(publicKeyPem),
    proof_of_work_nonce: nonce,
    service_response: payload,
  };
}

/** Recall a policy-verified compliant version of a tool call. */
export async function recall(
  fetchFn: FetchFn,
  config: PolicyrecallConfig,
  options: RecallOptions,
): Promise<unknown> {
  const v = validateCall(options);
  return signedPost(fetchFn, config, "/recall", {
    domain: v.domain,
    tool: v.tool,
    task_description: v.taskDescription,
    arguments: v.args,
  });
}

/** Calibrate a tool call against live policy. */
export async function calibrate(
  fetchFn: FetchFn,
  config: PolicyrecallConfig,
  options: CalibrateOptions,
): Promise<unknown> {
  const v = validateCall(options);
  const body: Record<string, unknown> = {
    domain: v.domain,
    tool: v.tool,
    task_description: v.taskDescription,
    arguments: v.args,
  };
  if (typeof options.trap_id === "string" && options.trap_id.trim()) {
    body.trap_id = options.trap_id.trim();
  }
  return signedPost(fetchFn, config, "/calibrate", body);
}

/** Render a payload as the JSON text block MCP clients show. */
export function formatPayload(payload: unknown): string {
  return typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}
