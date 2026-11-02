/**
 * policyrecall types.
 *
 * Shapes follow the documented parameter tables for the hosted
 * operational-memory service: recall and calibrate share a domain,
 * a tool name, a task description (16-1000 characters) and a
 * non-empty arguments object; calibrate adds an optional trap id.
 * Registration takes a single confirmation flag. HTTP access is
 * described by a minimal response surface so tests can inject a
 * fake fetch and never touch the network.
 */

export const DOMAINS = ["fintech", "industrial_iot", "robotics", "devsecops"] as const;
export type PolicyDomain = (typeof DOMAINS)[number];

export interface PolicyrecallConfig {
  baseUrl: string;
  keyFile: string;
}

export interface RegisterOptions {
  user_confirmed: boolean;
}

export interface RecallOptions {
  domain: PolicyDomain;
  tool_name: string;
  task_description: string;
  arguments: Record<string, unknown>;
}

export interface CalibrateOptions {
  domain: PolicyDomain;
  tool_name: string;
  task_description: string;
  arguments: Record<string, unknown>;
  trap_id?: string;
}

/** Minimal HTTP response surface so tests can inject fixtures. */
export interface HttpResponse {
  ok: boolean;
  status: number;
  statusText?: string;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  json(): Promise<unknown>;
}

export type FetchFn = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    redirect?: string;
  },
) => Promise<HttpResponse>;
