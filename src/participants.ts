/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

export const PARTICIPANTS = ["grok_bot", "dot", "claude"] as const;
export type Participant = typeof PARTICIPANTS[number];
export type OAuthParticipant = Exclude<Participant, "grok_bot">;

export function isParticipant(value: unknown): value is Participant {
  return value === "grok_bot" || value === "dot" || value === "claude";
}

export const CHATGPT_CLIENT_ID = "https://chatgpt.com/oauth/client.json";
export const CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
export const CLAUDE_CLIENT_ID = "https://claude.ai/oauth/mcp-oauth-client-metadata";
export const CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

const DOT = { participant: "dot", clientId: CHATGPT_CLIENT_ID, redirectUri: CHATGPT_REDIRECT, name: "Dot", host: "chatgpt.com" } as const;
const CLAUDE = { participant: "claude", clientId: CLAUDE_CLIENT_ID, redirectUri: CLAUDE_REDIRECT, name: "Claude", host: "claude.ai" } as const;
export type OAuthClient = typeof DOT | typeof CLAUDE;

/** Fixed server policy. A client name, URL prefix, or token label is never authority. */
export function oauthClient(clientId: unknown): OAuthClient | null {
  if (clientId === CHATGPT_CLIENT_ID) return DOT;
  if (clientId === CLAUDE_CLIENT_ID) return CLAUDE;
  return null;
}

export function oauthParticipant(participant: unknown): OAuthClient | null {
  if (participant === "dot") return DOT;
  if (participant === "claude") return CLAUDE;
  return null;
}
