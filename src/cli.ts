#!/usr/bin/env node
/**
 * policyrecall CLI. Subcommands mirror the MCP tool names:
 *
 *   policyrecall achromat_register_identity --user-confirmed true
 *   policyrecall achromat_recall --domain fintech --tool-name send_payment \
 *     --task-description "Pay a verified vendor invoice" --arguments '{"amount":10}'
 *   policyrecall achromat_calibrate --domain fintech --tool-name send_payment \
 *     --task-description "Pay a verified vendor invoice" --arguments '{"amount":10}' \
 *     [--trap-id <id>]
 *   policyrecall mcp
 *
 * Env: ACHROMAT_BASE_URL (default https://mom.achromat.ai),
 * ACHROMAT_AGENT_KEY_FILE (default ~/.achromat/achromat_agent_key.pem).
 * Exit codes: 0 success, 1 API/state error, 2 usage error.
 */
import {
  calibrate,
  formatPayload,
  recall,
  registerIdentity,
  resolveConfig,
  VERSION,
} from "./policyrecall.js";
import { DOMAINS } from "./types.js";
import type { FetchFn, PolicyDomain } from "./types.js";

const TOOLS = ["achromat_register_identity", "achromat_recall", "achromat_calibrate"];

function usage(): never {
  console.error(`Usage:
  policyrecall <tool> [flags]
  policyrecall mcp
  policyrecall --version

Tools: ${TOOLS.join(", ")}

Flags: --user-confirmed true|false --domain <d> --tool-name <name>
  --task-description <text, 16-1000 chars> --arguments <json object>
  --trap-id <id>

Domains: ${DOMAINS.join(", ")}`);
  process.exit(2);
}

function flag(rest: string[], name: string): string | undefined {
  const i = rest.indexOf(name);
  return i >= 0 ? rest[i + 1] : undefined;
}

function hasFlag(rest: string[], name: string): boolean {
  return rest.indexOf(name) >= 0;
}

function reqFlag(rest: string[], name: string): string {
  const v = flag(rest, name);
  if (!v) usage();
  return v;
}

function parseArguments(rest: string[]): Record<string, unknown> {
  const raw = reqFlag(rest, "--arguments");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    usage();
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) usage();
  return parsed as Record<string, unknown>;
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd || !TOOLS.includes(cmd)) usage();
  const fetchFn = globalThis.fetch as unknown as FetchFn;
  const config = resolveConfig(process.env);
  try {
    let out: unknown;
    if (cmd === "achromat_register_identity") {
      const raw = flag(rest, "--user-confirmed");
      const confirmed = raw !== undefined ? raw === "true" : hasFlag(rest, "--user-confirmed");
      const value = raw === undefined && hasFlag(rest, "--user-confirmed") ? true : confirmed;
      out = await registerIdentity(fetchFn, config, { user_confirmed: value });
    } else {
      const callArgs = {
        domain: reqFlag(rest, "--domain") as PolicyDomain,
        tool_name: reqFlag(rest, "--tool-name"),
        task_description: reqFlag(rest, "--task-description"),
        arguments: parseArguments(rest),
      };
      if (cmd === "achromat_recall") {
        out = await recall(fetchFn, config, callArgs);
      } else {
        out = await calibrate(fetchFn, config, { ...callArgs, trap_id: flag(rest, "--trap-id") });
      }
    }
    console.log(formatPayload(out));
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

void main();
