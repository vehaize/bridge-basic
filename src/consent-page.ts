/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Consent page for Dot. No script, no email, no item, and no connect code.
 * Every echoed value is escaped for an HTML attribute or text node.
 * "@" is escaped so an address is not a literal substring of the page.
 */

import { oauthClient } from "./participants.ts";
import { LIVE_DISABLED_REASON } from "./live-switch.ts";

export const AUTHORIZE_CSP =
  "default-src 'none'; form-action 'self' https://chatgpt.com https://claude.ai; frame-ancestors 'none'; base-uri 'none'";

const ESCAPE: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "@": "&#64;",
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"'@]/g, (char) => ESCAPE[char] ?? char);
}

export interface ConsentFields {
  clientId: string;
  redirectUri: string;
  responseType: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource: string;
  state: string;
  /** Present only when the caller sent `scope`. Echoed so it can be escaped. */
  scope?: string;
}

function hidden(name: string, value: string): string {
  return `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`;
}

/** Visible scope and resource plus hidden OAuth fields. The form posts only to this Worker. */
export function consentPage(fields: ConsentFields): string {
  const client = oauthClient(fields.clientId);
  if (!client || fields.redirectUri !== client.redirectUri) return consentFailure();
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Connect ${client.name}</title>
</head>
<body>
<h1>Connect ${client.name}</h1>
<p>${client.host} will connect as ${client.name}.</p>
<p>Redirect URI: ${escapeHtml(fields.redirectUri)}</p>
<p>Requested resource: ${escapeHtml(fields.resource)}</p>
<p>Requested scope: ${fields.scope === undefined ? "not supplied" : fields.scope === "" ? "(empty)" : escapeHtml(fields.scope)}</p>
<p>A requested scope does not limit which tools a token can use.</p>
<p>Only enter a connect code or approve a connection you started yourself from your own ChatGPT or Claude settings.</p>
<p>Completing this connection revokes and replaces the current ${escapeHtml(client.name)} connection.</p>
<form method="post" action="/authorize">
${hidden("client_id", fields.clientId)}
${hidden("redirect_uri", fields.redirectUri)}
${hidden("response_type", fields.responseType)}
${hidden("code_challenge", fields.codeChallenge)}
${hidden("code_challenge_method", fields.codeChallengeMethod)}
${hidden("resource", fields.resource)}
${hidden("state", fields.state)}
${fields.scope === undefined ? "" : hidden("scope", fields.scope)}
<label>Connect code <input name="connect_code" autocomplete="off" spellcheck="false"></label>
<button type="submit">Connect</button>
</form>
</body>
</html>`;
}

/** Browser refusal for POST /authorize while writes are off. No request value is interpolated. */
export function liveDisabledPage(): string {
  const reason = escapeHtml(LIVE_DISABLED_REASON);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Writes are off</title>
</head>
<body>
<p>Writes are off (${reason}).</p>
</body>
</html>`;
}

/** Generic failure. No request value is interpolated. */
export function consentFailure(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Connection failed</title>
</head>
<body>
<p>Connection failed.</p>
</body>
</html>`;
}

export function withAuthorizeHeaders(response: Response, extra?: HeadersInit): Response {
  const headers = new Headers(extra);
  for (const [name, value] of response.headers) headers.set(name, value);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Content-Security-Policy", AUTHORIZE_CSP);
  // same-origin, not no-referrer: under no-referrer a browser sends Origin "null"
  // on the Connect submit. A cross-origin request, including the redirect to the
  // client, still gets no referrer.
  headers.set("Referrer-Policy", "same-origin");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(response.body, { status: response.status, headers });
}
