/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { liveDisabledPage, withAuthorizeHeaders } from "./consent-page.ts";
import { liveDisabledResponse, liveWritesEnabled, logLiveDisabled } from "./live-switch.ts";
import { logError, logInfo } from "./log.ts";
import { handleMcpRoute } from "./mcp-route.ts";
import { claimOwner, presentedBootstrapSecret } from "./owner-claim.ts";
import { authorizeSpendsAddressLimit, canonicalOrigin, handleOAuth, isRefreshTokenGrant, sameOriginPostAllowed, type BridgeEnv } from "./oauth-routes.ts";
import { enforceUnauthenticatedLimit, type UnauthenticatedRoute } from "./rate-limit.ts";

const HEALTH_PATH = "/health";
const OWNER_CLAIM_PATH = "/owner/claim";

const LOGGED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

type Route =
  | "health"
  | "owner_claim"
  | "authorize"
  | "token"
  | "oauth_protected_resource"
  | "oauth_authorization_server"
  | "mcp"
  | "not_found";

const healthBody = {
  ok: true,
  service: "admrn-bridge",
  phase: "v0.1-candidate",
  status: "v0.1-candidate",
  mvp: "grok-bot-dot",
} as const;

export async function routeRequest(
  request: Request,
  env: BridgeEnv,
  ctx?: ExecutionContext,
): Promise<Response> {
  const route = classify(request);

  // The route name, not the path, and a known method or "other": a secret
  // pasted into the path or the method stays out of logs.
  logInfo({
    message: "incoming request",
    method: LOGGED_METHODS.has(request.method) ? request.method : "other",
    route,
  });

  // Health, discovery, GET /authorize, unknown paths, and /mcp do not read
  // LIVE_ENABLED here. POST /token still runs when its single grant_type is
  // refresh_token. Write tools on /mcp are refused later. The retention cron
  // does not use this path.
  if (consultsLiveSwitch(route, request) && !liveWritesEnabled(env.LIVE_ENABLED)) {
    const refused = await refusedLiveWrite(route, request);
    if (refused) return refused;
  }

  // Bind claims to the canonical URL before spending a bucket or handling the secret.
  if (route === "owner_claim") {
    const origin = canonicalOrigin(env.BRIDGE_ORIGIN);
    if (!origin) {
      logError({ message: "owner claim", status: 500, error: "internal_error" });
      return Response.json({ error: "internal_error" }, { status: 500, headers: { "Cache-Control": "no-store" } });
    }
    if (new URL(request.url).origin !== origin) {
      logInfo({ message: "owner claim", status: 404, error: "not_found" });
      return Response.json({ ok: false, error: "not_found" }, { status: 404, headers: { "Cache-Control": "no-store" } });
    }
  }

  // Health and OAuth discovery stay up when the binding is missing, so a client
  // can still read metadata. Unknown paths do no D1 work. A limited route is
  // charged only after its method, path, and content type match. GET /authorize
  // is not charged. POST /authorize is charged only after the consent site
  // check and the OAuth prefilter accept it. A cross-site or same-site form
  // is not charged. POST /owner/claim is bound to BRIDGE_ORIGIN before any
  // bucket is charged, then uses the strict form of that site
  // check, which refuses Origin "null", and spends its bucket only when a
  // well-formed Bootstrap-Secret is presented. Each
  // charged route has its own address bucket. The credential bucket for /mcp
  // is unchanged. Charged requests still fail closed when the limiter is down.
  const bucket = await unauthenticatedBucket(route, request, env);
  if (bucket) {
    const limited = await enforceUnauthenticatedLimit(request, env, bucket);
    if (limited) return limited;
  }

  switch (route) {
    case "health":
      return Response.json(healthBody);
    case "owner_claim":
      if (!claimSiteAllowed(request, env)) {
        logInfo({ message: "owner claim", status: 403, error: "cross_site" });
        return Response.json({ error: "cross_site" }, { status: 403 });
      }
      return claimOwner(request, env);
    case "authorize":
    case "token":
    case "oauth_protected_resource":
    case "oauth_authorization_server":
      return handleOAuth(request, env, ctx);
    case "mcp":
      return handleMcpRoute(request, env, ctx);
    case "not_found":
      return Response.json({ ok: false, error: "not_found" }, { status: 404 });
    default: {
      const neverRoute: never = route;
      return neverRoute;
    }
  }
}

async function unauthenticatedBucket(
  route: Route,
  request: Request,
  env: BridgeEnv,
): Promise<UnauthenticatedRoute | null> {
  switch (route) {
    case "authorize":
      return await authorizeSpendsAddressLimit(request, env) ? "authorize" : null;
    case "token":
      return tokenAccepted(request) ? "token" : null;
    case "owner_claim":
      return claimSpendsAddressLimit(request, env) ? "owner_claim" : null;
    case "mcp":
      return mcpAccepted(request) ? "mcp" : null;
    case "health":
    case "oauth_protected_resource":
    case "oauth_authorization_server":
    case "not_found":
      return null;
    default: {
      const neverRoute: never = route;
      return neverRoute;
    }
  }
}

// Type before the first ";", trimmed and lower case. /token and /mcp use this
// same parse, so a charset parameter stays on the accepted type. /authorize
// uses the same parse inside the OAuth prefilter.
function mediaType(request: Request): string {
  return request.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() ?? "";
}

/** POST form data with no query. /token refuses a query before it reads the body. */
function tokenAccepted(request: Request): boolean {
  const url = new URL(request.url);
  return url.pathname === "/token"
    && request.method === "POST"
    && url.search === ""
    && mediaType(request) === "application/x-www-form-urlencoded";
}

/** POST /owner/claim. This route does not constrain Content-Type. */
function ownerClaimAccepted(request: Request): boolean {
  return request.method === "POST" && new URL(request.url).pathname === OWNER_CLAIM_PATH;
}

/**
 * Strict Origin / Sec-Fetch-Site rule. Unlike POST /authorize, Origin "null"
 * is refused here even with Sec-Fetch-Site same-origin. The router already
 * binds the request to BRIDGE_ORIGIN before this check; the null-origin
 * branch is kept as defence in depth.
 */
function claimSiteAllowed(request: Request, env: BridgeEnv): boolean {
  const origin = canonicalOrigin(env.BRIDGE_ORIGIN);
  if (request.headers.get("Origin") !== null && origin === null) return false;
  return sameOriginPostAllowed(request, origin ?? "");
}

/** Spend only when a same-origin POST presents a well-formed Bootstrap-Secret. */
function claimSpendsAddressLimit(request: Request, env: BridgeEnv): boolean {
  return ownerClaimAccepted(request) && claimSiteAllowed(request, env) && presentedBootstrapSecret(request) !== null;
}

/** POST application/json, including a charset parameter. */
function mcpAccepted(request: Request): boolean {
  return new URL(request.url).pathname === "/mcp" && request.method === "POST" && mediaType(request) === "application/json";
}

function consultsLiveSwitch(route: Route, request: Request): boolean {
  switch (route) {
    case "owner_claim":
    case "token":
      return true;
    case "authorize":
      return request.method === "POST";
    case "health":
    case "oauth_protected_resource":
    case "oauth_authorization_server":
    case "mcp":
    case "not_found":
      return false;
    default: {
      const neverRoute: never = route;
      return neverRoute;
    }
  }
}

async function refusedLiveWrite(route: Route, request: Request): Promise<Response | null> {
  switch (route) {
    case "owner_claim":
      logLiveDisabled({ route: "owner_claim" });
      return liveDisabledResponse();
    case "authorize":
      if (request.method !== "POST") return null;
      logLiveDisabled({ route: "authorize" });
      return authorizeLiveDisabled(request);
    case "token":
      if (await isRefreshTokenGrant(request)) return null;
      logLiveDisabled({ route: "token" });
      return liveDisabledResponse();
    case "health":
    case "oauth_protected_resource":
    case "oauth_authorization_server":
    case "mcp":
    case "not_found":
      return null;
    default: {
      const neverRoute: never = route;
      return neverRoute;
    }
  }
}

/** A browser form navigation gets HTML. Other clients keep the JSON refusal. */
function authorizeLiveDisabled(request: Request): Response {
  if (!browserAuthorizePost(request)) return liveDisabledResponse();
  return withAuthorizeHeaders(new Response(liveDisabledPage(), {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  }));
}

function browserAuthorizePost(request: Request): boolean {
  if (request.headers.get("Sec-Fetch-Dest") === "document") return true;
  if (request.headers.get("Sec-Fetch-Mode") === "navigate") return true;
  return acceptPrefersHtml(request.headers.get("Accept"));
}

function acceptPrefersHtml(header: string | null): boolean {
  if (!header) return false;
  let html = -1;
  let json = -1;
  for (const part of header.split(",")) {
    const [typePart, ...params] = part.split(";");
    const type = typePart?.trim().toLowerCase() ?? "";
    let quality = 1;
    for (const param of params) {
      const [rawKey, rawValue] = param.split("=");
      if (rawKey?.trim().toLowerCase() !== "q") continue;
      const parsed = Number(rawValue?.trim());
      if (Number.isFinite(parsed)) quality = parsed;
    }
    if (type === "text/html" || type === "application/xhtml+xml") html = Math.max(html, quality);
    if (type === "application/json") json = Math.max(json, quality);
  }
  return html >= 0 && html >= json;
}

function classify(request: Request): Route {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === HEALTH_PATH) return "health";
  if (request.method === "POST" && url.pathname === OWNER_CLAIM_PATH) return "owner_claim";
  switch (url.pathname) {
    case "/authorize":
      return "authorize";
    case "/token":
      return "token";
    case "/.well-known/oauth-protected-resource/mcp":
      return "oauth_protected_resource";
    case "/.well-known/oauth-authorization-server":
      return "oauth_authorization_server";
    case "/mcp":
      return "mcp";
    default:
      return "not_found";
  }
}
