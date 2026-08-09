/** Minimal public types for @agenthub/gateway-sdk (JSDoc-backed). */

export type AgentHubGatewayOptions = {
  baseUrl: string;
  apiKey?: string;
  actorRole?: string;
  actorId?: string;
  environment?: string;
  agentId?: string;
  scopeType?: string;
  scopeId?: string;
  trackCost?: boolean;
  virtualKeyId?: string;
  fetchImpl?: typeof fetch;
  sessionId?: string;
  user?: string;
  properties?: Record<string, unknown>;
};

export type ChatCompletionsOptions = {
  traceId?: string;
  sessionId?: string;
  requestTag?: string;
  userProperties?: Record<string, unknown>;
  properties?: Record<string, unknown>;
  user?: string;
  virtualKeyId?: string;
  promptId?: string;
  configId?: string;
  guardrailId?: string;
  cacheMode?: string;
};

export type GatewayAnalyticsSummary = {
  environment?: string | null;
  hours: number;
  total_events: number;
  distinct_requests: number;
  total_estimated_cost_cents: number;
  avg_input_tokens: number;
  avg_output_tokens: number;
  top_models: Array<Record<string, unknown>>;
  top_endpoint_families: Array<Record<string, unknown>>;
  on_plane_events?: number;
  off_plane_detected?: number;
  on_plane_coverage_percent?: number | null;
  on_plane_coverage?: Record<string, unknown>;
  [key: string]: unknown;
};

export declare class AgentHubGateway {
  constructor(options?: AgentHubGatewayOptions);
  chatCompletions(body: Record<string, unknown>, opts?: ChatCompletionsOptions): Promise<Record<string, unknown>>;
  responses(body: Record<string, unknown>, opts?: ChatCompletionsOptions): Promise<Record<string, unknown>>;
  getGatewayAnalyticsSummary(opts?: {
    hours?: number;
    environment?: string;
  }): Promise<GatewayAnalyticsSummary>;
  getLeadershipQbrSnapshot(opts?: {
    hours?: number;
    environment?: string;
  }): Promise<Record<string, unknown>>;
  listLeadershipDrillRuns(opts?: {
    drillId?: string;
    limit?: number;
  }): Promise<Record<string, unknown>>;
  recordLeadershipDrillRun(body?: Record<string, unknown>): Promise<Record<string, unknown>>;
  [key: string]: unknown;
}

export declare function createGatewayFetchInstrumenter(options?: {
  sessionId?: string;
  user?: string;
  properties?: Record<string, unknown>;
  fetchImpl?: typeof fetch;
}): typeof fetch;

export default AgentHubGateway;
