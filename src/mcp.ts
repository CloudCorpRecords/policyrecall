/**
 * policyrecall MCP server.
 *
 * Why the low-level Server instead of McpServer: the high-level
 * helper converts zod schemas to JSON Schema and injects keys that
 * are not in this tool's public spec ("$schema" and
 * "additionalProperties"), which breaks exact tool-list/schema
 * parity with the spec. This file serves tools/list with the
 * spec's exact input schemas as explicit literals, while zod still
 * validates every tools/call argument set.
 *
 * Note: the original offers tools dynamically by key state. This
 * rebuild registers all three documented tools statically and
 * gates by state at call time: recall and calibrate without a key
 * file return an isError result saying identity setup is required.
 *
 * Config is read from the environment at call time:
 * ACHROMAT_BASE_URL (default https://mom.achromat.ai) and
 * ACHROMAT_AGENT_KEY_FILE (default ~/.achromat/achromat_agent_key.pem).
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  calibrate,
  formatPayload,
  recall,
  registerIdentity,
  resolveConfig,
  VERSION,
} from "./policyrecall.js";
import { DOMAINS } from "./types.js";
import type { FetchFn } from "./types.js";

const RegisterArgs = z.object({ user_confirmed: z.boolean() });
const RecallArgs = z.object({
  domain: z.enum(DOMAINS),
  tool_name: z.string(),
  task_description: z.string().min(16).max(1000),
  arguments: z.record(z.string(), z.unknown()).refine((o) => Object.keys(o).length > 0, {
    message: "arguments must be a non-empty object",
  }),
});
const CalibrateArgs = z.object({
  domain: z.enum(DOMAINS),
  tool_name: z.string(),
  task_description: z.string().min(16).max(1000),
  arguments: z.record(z.string(), z.unknown()).refine((o) => Object.keys(o).length > 0, {
    message: "arguments must be a non-empty object",
  }),
  trap_id: z.string().optional(),
});

const DOMAIN_SCHEMA = {
  type: "string" as const,
  enum: ["fintech", "industrial_iot", "robotics", "devsecops"],
  description: "Policy domain: fintech, industrial_iot, robotics, or devsecops.",
};

const TOOLS = [
  {
    name: "achromat_register_identity",
    description:
      "Register a new agent identity: generate an Ed25519 keypair, solve a small proof-of-work, and register the public key. user_confirmed must be true.",
    inputSchema: {
      type: "object" as const,
      properties: { user_confirmed: { type: "boolean", description: "Must be true: the user confirmed registering a new agent identity." } },
      required: ["user_confirmed"],
    },
  },
  {
    name: "achromat_recall",
    description:
      "Recall a policy-verified compliant version of a tool call for a domain, signed with the local agent key.",
    inputSchema: {
      type: "object" as const,
      properties: {
        domain: DOMAIN_SCHEMA,
        tool_name: { type: "string", description: "Name of the tool call to recall a compliant version of." },
        task_description: { type: "string", minLength: 16, maxLength: 1000, description: "Description of the task the tool call serves (16 to 1000 characters)." },
        arguments: { type: "object", description: "Original tool call arguments object." },
      },
      required: ["domain", "tool_name", "task_description", "arguments"],
    },
  },
  {
    name: "achromat_calibrate",
    description:
      "Calibrate a tool call against live policy for a domain, signed with the local agent key, with an optional trap id.",
    inputSchema: {
      type: "object" as const,
      properties: {
        domain: DOMAIN_SCHEMA,
        tool_name: { type: "string", description: "Name of the tool call to calibrate against policy." },
        task_description: { type: "string", minLength: 16, maxLength: 1000, description: "Description of the task the tool call serves (16 to 1000 characters)." },
        arguments: { type: "object", description: "Tool call arguments object to calibrate." },
        trap_id: { type: "string", description: "Optional trap id supplied by the caller for policy testing." },
      },
      required: ["domain", "tool_name", "task_description", "arguments"],
    },
  },
];

function textResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof value === "string" ? value : JSON.stringify(value, null, 2),
      },
    ],
  };
}

function errorResult(err: unknown) {
  return {
    content: [
      { type: "text" as const, text: err instanceof Error ? err.message : String(err) },
    ],
    isError: true,
  };
}

const server = new Server(
  { name: "policyrecall", version: VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const fetchFn = globalThis.fetch as unknown as FetchFn;
  const config = resolveConfig(process.env);
  try {
    let out: unknown;
    switch (name) {
      case "achromat_register_identity":
        out = await registerIdentity(fetchFn, config, RegisterArgs.parse(args ?? {}));
        break;
      case "achromat_recall":
        out = await recall(fetchFn, config, RecallArgs.parse(args ?? {}));
        break;
      case "achromat_calibrate":
        out = await calibrate(fetchFn, config, CalibrateArgs.parse(args ?? {}));
        break;
      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
    return textResult(formatPayload(out));
  } catch (err) {
    if (err instanceof McpError) throw err;
    return errorResult(err);
  }
});

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
