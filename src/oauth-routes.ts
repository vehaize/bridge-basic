/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Dot and Claude's OAuth surface. The pinned provider serves authorization-server
 * metadata and /token. This Worker serves protected-resource metadata and
 * /authorize. /mcp is not this provider's API route.
 *
 * Fixed hosted client identities, KV for the provider's hashed tokens,
 * D1 as the authority on whether the participant may act,
 * a one-time connect code, and explicit token lifetimes pinned to the
 * library defaults (1 hour access, 30 day refresh). No scope
 * catalogue is advertised. A requested scope is shown on the consent page
 * and stored only if it is a valid scope parameter.
 */

import { OAuthAuthorizationServer, OAuthResourceServer, type TokenExchangeCallbackOptions } from "@cloudflare/workers-oauth-provider";
import { consentFailure, consentPage, withAuthorizeHeaders } from "./consent-page.ts";
import { completeParticipantConnection } from "./dot-connect.ts";
import { logError, logInfo, logNonSuccess } from "./log.ts";
import type { OwnerClaimEnv } from "./owner-claim.ts";
import type { RateLimitEnv } from "./rate-limit.ts";
import { ParticipantDisabled, PARTICIPANT_RETRY_AFTER_SECONDS } from "./participant-status.ts";
import {
  REFRESH_BUSY_RETRY_AFTER_SECONDS, REFRESH_TOKEN_TTL_SECONDS, RefreshFamilyBusy, RefreshFamilyDeferred,
  RefreshFamilyExchange, RefreshFamilyRefused, RefreshFamilyUnavailable, refreshTokenHash,
} from "./refresh-family.ts";

import { oauthClient } from "./participants.ts";
export { CHATGPT_CLIENT_ID, CHATGPT_REDIRECT, CLAUDE_CLIENT_ID, CLAUDE_REDIRECT } from "./participants.ts";

/**
 * Pinned library defaults. Explicit so a later edit cannot silently become 300 seconds.
 * `refreshTokenTTL: undefined` would mean no expiry, so this is the number 2_592_000.
 * Refresh checks the D1 credential before minting. The callback must not throw invalid_grant.
 * The library revokes the KV grant when that hook throws invalid_grant.
 */
export const ACCESS_TOKEN_TTL_SECONDS = 3600;
// Defined beside the family budget whose history bound is derived from it.
export { REFRESH_TOKEN_TTL_SECONDS };

const LIMIT = 16 * 1024;
const CODE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const SAFE_CODE = /^[a-z0-9_-]{1,80}$/;
const GROK_TOKEN = /admrn_gb_[A-Za-z0-9_-]{43}/;
const CONTROLS = /[\u0000-\u001f\u007f]/;
// GET-only advisory hint. Validate bounded syntax; never select or echo a locale.
const UI_LOCALES_MAX_LENGTH = 64;
const UI_LOCALES_MAX_TAGS = 8;
const UI_LOCALES = /^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*(?: [A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*)*$/;
const SHAPED_REFRESH = /^(dot|claude):[A-Za-z0-9_-]{1,128}:[^:\s]+$/;
/**
 * workers-oauth-provider 1.2.3 rejects a refresh whose remaining lifetime is
 * below KV's minimum stored TTL, before it writes a grant or token.
 */
const PROVIDER_REFRESH_MIN_REMAINING_SECONDS = 60;
const AUTHORIZE_FIELDS = new Set([
  "client_id", "redirect_uri", "response_type", "code_challenge",
  "code_challenge_method", "resource", "scope", "state", "connect_code",
]);
const TOKEN_FIELDS = new Set([
  "grant_type", "code", "redirect_uri", "client_id", "code_verifier", "resource",
  "refresh_token", "scope", "client_assertion", "client_assertion_type",
  "token", "token_type_hint",
]);

export interface BridgeEnv extends OwnerClaimEnv, RateLimitEnv {
  OAUTH_KV?: KVNamespace;
  BRIDGE_ORIGIN?: string;
  // Optional. Only an unset value or the exact string "true" allows writes.
  // Every other string fails closed. Absent from wrangler.example.jsonc so
  // copying that file does not turn writes off. The retention cron does not
  // read this.
  LIVE_ENABLED?: string;
  // Worker secret, absent until an operator sets it. Not a Wrangler var:
  // `wrangler types` reads only the config, and this secret must not be committed.
  WAKE_SECRET_GROK_BOT?: string;
}

type OAuthPath = "authorize" | "token" | "protected_resource" | "authorization_server";
type OAuthReason =
  | "unknown_client"
  | "redirect_uri"
  | "invalid_request"
  | "no_owner_lock"
  | "code_in_url"
  | "wrong_scope"
  | "unsupported_grant"
  | "origin_not_configured"
  | "origin_mismatch"
  | "oauth_not_configured"
  | "method_not_allowed"
  | "body_too_large"
  | "unsupported_media_type"
  | "cross_site"
  | "internal_error"
  | "connect_code";

type TokenRefusal = "unknown_client" | "unsupported_grant" | "redirect_uri" | "wrong_scope" | "invalid_request";

class BodyTooLarge extends Error {}

interface EmailRow {
  owner_email: string;
}

interface OauthKvEnv {
  OAUTH_KV?: KVNamespace;
}

/** https origin with no userinfo, port, path, query, or fragment. */
export function canonicalOrigin(value: string | undefined): string | null {
  if (!value) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.origin !== value) return null;
  if (url.protocol !== "https:" || url.username || url.password || url.port) return null;
  if (url.pathname !== "/" || url.search || url.hash) return null;
  if (url.hostname !== url.hostname.toLowerCase()) return null;
  return url.origin;
}

export function openAuthorizationServer(env: BridgeEnv): {
  origin: string;
  resource: string;
  server: OAuthAuthorizationServer<OauthKvEnv>;
} | null {
  const origin = canonicalOrigin(env.BRIDGE_ORIGIN);
  if (!origin || !env.OAUTH_KV) return null;
  return { origin, resource: `${origin}/mcp`, server: createAuthorizationServer(origin) };
}

/**
 * Audience-checked provider validation for the configured resource.
 * Returns null for a missing, expired, or wrong-audience token. Caller
 * identity still has to pass the Dot verifier before a tool runs.
 */
export async function validateDotAccessToken(env: BridgeEnv, token: string): Promise<unknown> {
  const opened = openAuthorizationServer(env);
  if (!opened || !env.OAUTH_KV || !token) return null;
  try {
    return await opened.server.validateToken(opened.resource, token, { OAUTH_KV: env.OAUTH_KV });
  } catch {
    return null;
  }
}

export async function handleOAuth(
  request: Request,
  env: BridgeEnv,
  ctx?: ExecutionContext,
): Promise<Response> {
  try {
    const path = oauthPath(new URL(request.url).pathname);
    if (path === null) return json({ ok: false, error: "not_found" }, 404);
    const origin = canonicalOrigin(env.BRIDGE_ORIGIN);
    if (!origin) return fail("origin_not_configured", 500, "json");
    if (new URL(request.url).origin !== origin) return fail("origin_mismatch", 404, "json");
    switch (path) {
      case "protected_resource":
        return await scrub(await resourceServer(origin).fetch(request, {}, requestContext(ctx)));
      case "authorization_server":
        return await scrub(await createAuthorizationServer(origin).fetch(request, kvBinding(env), requestContext(ctx)));
      case "token":
        if (!env.OAUTH_KV) return fail("oauth_not_configured", 500, "json");
        return await token(request, env, origin, ctx);
      case "authorize":
        if (!env.OAUTH_KV) return fail("oauth_not_configured", 500, "html");
        return await authorize(request, env, origin);
      default: {
        const neverPath: never = path;
        return neverPath;
      }
    }
  } catch {
    return fail("internal_error", 500, "json");
  }
}

function oauthPath(pathname: string): OAuthPath | null {
  switch (pathname) {
    case "/authorize":
      return "authorize";
    case "/token":
      return "token";
    case "/.well-known/oauth-protected-resource/mcp":
      return "protected_resource";
    case "/.well-known/oauth-authorization-server":
      return "authorization_server";
    default:
      return null;
  }
}

function createAuthorizationServer(
  origin: string,
  onTokenGrant?: (grant: TokenExchangeCallbackOptions<OauthKvEnv>) => Promise<void>,
): OAuthAuthorizationServer<OauthKvEnv> {
  return new OAuthAuthorizationServer({
    issuer: origin,
    resources: [`${origin}/mcp`],
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientIdMetadataDocumentEnabled: true,
    accessTokenTTL: ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTTL: REFRESH_TOKEN_TTL_SECONDS,
    // The callback must not throw invalid_grant: the library revokes the KV grant
    // when that hook does. D1 family decisions use neutral local sentinels.
    ...(onTokenGrant === undefined ? {} : {
      tokenExchangeCallback: async (options) => {
        await onTokenGrant(options);
      },
    }),
    onError({ code, status }) {
      logInfo({
        message: "bridge event",
        event: "oauth.library",
        reason: typeof code === "string" && SAFE_CODE.test(code) ? code : "oauth_error",
        status: typeof status === "number" ? status : 0,
      });
    },
  });
}

function resourceServer(origin: string): OAuthResourceServer<Record<string, never>> {
  return new OAuthResourceServer({
    resourceMetadata: {
      resource: `${origin}/mcp`,
      authorization_servers: [origin],
      bearer_methods_supported: ["header"],
      resource_name: "ADMRN Bridge",
    },
    // Metadata requests never reach this handler. /mcp is served by the router.
    handler: {
      fetch: () => json({ ok: false, error: "not_found" }, 404),
    },
    validateToken: () => async () => null,
  });
}

function kvBinding(env: BridgeEnv): OauthKvEnv {
  return env.OAUTH_KV ? { OAUTH_KV: env.OAUTH_KV } : {};
}

async function authorize(request: Request, env: BridgeEnv, origin: string): Promise<Response> {
  if (request.method !== "GET" && request.method !== "POST") {
    return fail("method_not_allowed", 405, "html", { Allow: "GET, POST" });
  }
  const url = new URL(request.url);
  if (request.method === "POST" && url.search) {
    await cancel(request);
    return fail(url.searchParams.has("connect_code") ? "code_in_url" : "invalid_request", 400, "html");
  }
  if (request.method === "POST" && !consentPostAllowed(request, origin)) {
    await cancel(request);
    return fail("cross_site", 403, "html");
  }
  const resource = `${origin}/mcp`;
  const parsed = request.method === "GET" ? authorizeQuery(url) : await authorizeBody(request);
  if (parsed instanceof Response) return parsed;
  const refusal = prefilterAuthorize(parsed, resource, request.method === "GET");
  if (refusal) {
    await cancel(request);
    return fail(refusal, 400, "html");
  }
  if (!env.OAUTH_KV) return fail("oauth_not_configured", 500, "html");
  let gate: "ok" | "no_owner_lock" | "invalid_request";
  try {
    gate = await authorizeGate(env.DB, parsed);
  } catch {
    await cancel(request);
    return fail("internal_error", 500, "html");
  }
  if (gate !== "ok") {
    await cancel(request);
    return fail(gate, 400, "html");
  }
  const client = oauthClient(parsed.get("client_id"));
  if (!client) return fail("unknown_client", 400, "html");
  if (request.method === "GET") {
    const scope = parsed.get("scope");
    return html(consentPage({
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      responseType: "code",
      codeChallenge: parsed.get("code_challenge") ?? "",
      codeChallengeMethod: "S256",
      resource,
      state: parsed.get("state") ?? "",
      ...(parsed.has("scope") && scope !== null ? { scope } : {}),
    }), 200);
  }
  const kv = env.OAUTH_KV;
  const server = createAuthorizationServer(origin);
  const api = server.getOAuthApi({ OAUTH_KV: kv });
  let completed: Response;
  try {
    completed = await completeParticipantConnection(request, {
      db: env.DB,
      resource,
      oauth: {
        parseAuthRequest: (authorization) => api.parseAuthRequest(authorization),
        completeAuthorization: (options) => api.completeAuthorization(options),
      },
    });
  } catch {
    return fail("internal_error", 500, "html");
  }
  if (completed.status === 303) {
    logInfo({ message: "bridge event", event: "oauth.connected", participant: client.participant, status: 303 });
    return withAuthorizeHeaders(completed);
  }
  const failed = completed.status >= 500;
  const log = failed ? logError : logInfo;
  log({
    message: "bridge event",
    event: failed ? "oauth.refused" : "oauth.connect_failed",
    reason: failed ? "internal_error" : "connect_code",
    status: completed.status,
  });
  return html(consentFailure(), completed.status);
}

function authorizeQuery(url: URL): URLSearchParams | Response {
  if (url.search.length > LIMIT) return fail("body_too_large", 413, "html");
  if (url.searchParams.has("connect_code")) return fail("code_in_url", 400, "html");
  return url.searchParams;
}

async function authorizeBody(request: Request): Promise<URLSearchParams | Response> {
  if (mediaType(request) !== "application/x-www-form-urlencoded") return fail("unsupported_media_type", 415, "html");
  try {
    const bytes = await readBounded(request.clone());
    return new URLSearchParams(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch (error) {
    await cancel(request);
    const tooLarge = error instanceof BodyTooLarge;
    return fail(tooLarge ? "body_too_large" : "invalid_request", tooLarge ? 413 : 400, "html");
  }
}

/**
 * GET /authorize does not spend the address bucket. A browser can fire that
 * GET cross-origin, including with the public OAuth query. POST spends it
 * only after the consent site check and prefilterAuthorize accept it.
 */
export async function authorizeSpendsAddressLimit(request: Request, env: BridgeEnv): Promise<boolean> {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.pathname !== "/authorize" || url.search !== "") return false;
  if (mediaType(request) !== "application/x-www-form-urlencoded") return false;
  const origin = canonicalOrigin(env.BRIDGE_ORIGIN);
  if (!origin || url.origin !== origin || !consentPostAllowed(request, origin)) return false;
  let parsed: URLSearchParams;
  try {
    const bytes = await readBounded(request.clone());
    parsed = new URLSearchParams(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    return false;
  }
  return prefilterAuthorize(parsed, `${origin}/mcp`, false) === null;
}

/**
 * Origin must be this bridge. When Origin is absent, only Sec-Fetch-Site
 * same-origin is allowed; cross-site and same-site are not. A POST with
 * neither header is allowed, which is how consent POSTs are already accepted.
 * Origin "null" never matches. POST /owner/claim uses this rule as is.
 */
export function sameOriginPostAllowed(request: Request, bridgeOrigin: string): boolean {
  const submitted = request.headers.get("Origin");
  if (submitted !== null) return submitted === bridgeOrigin;
  const site = request.headers.get("Sec-Fetch-Site");
  if (site === null) return true;
  return site === "same-origin";
}

/**
 * POST /authorize only. The sameOriginPostAllowed rule, plus Origin "null"
 * with Sec-Fetch-Site same-origin: a browser sends that pair for the consent
 * form when a referrer policy withholds the page's origin. Origin "null" with
 * any other Sec-Fetch-Site, or none, is refused.
 */
export function consentPostAllowed(request: Request, bridgeOrigin: string): boolean {
  if (request.headers.get("Origin") === "null") return request.headers.get("Sec-Fetch-Site") === "same-origin";
  return sameOriginPostAllowed(request, bridgeOrigin);
}

function prefilterAuthorize(params: URLSearchParams, resource: string, isGet: boolean): OAuthReason | null {
  for (const key of params.keys()) {
    if (isGet && key === "ui_locales") continue;
    if (!AUTHORIZE_FIELDS.has(key) || (isGet && key === "connect_code")) {
      return key === "connect_code" ? "code_in_url" : "invalid_request";
    }
  }
  const client = oauthClient(params.get("client_id"));
  if (params.getAll("client_id").length !== 1 || !client) return "unknown_client";
  if (params.getAll("redirect_uri").length !== 1 || params.get("redirect_uri") !== client.redirectUri) return "redirect_uri";
  if (params.getAll("response_type").length !== 1 || params.get("response_type") !== "code") return "invalid_request";
  if (params.getAll("code_challenge_method").length !== 1 || params.get("code_challenge_method") !== "S256") return "invalid_request";
  if (params.getAll("code_challenge").length !== 1 || !CODE.test(params.get("code_challenge") ?? "")) return "invalid_request";
  if (params.getAll("resource").length !== 1 || params.get("resource") !== resource) return "invalid_request";
  if (params.getAll("state").length > 1) return "invalid_request";
  const scopeRefusal = scopeRefusalFor(params);
  if (scopeRefusal) return scopeRefusal;
  if (!isGet && (params.getAll("connect_code").length !== 1 || !CODE.test(params.get("connect_code") ?? ""))) return "invalid_request";
  if ([...params.values()].some((value) => GROK_TOKEN.test(value) || CONTROLS.test(value))) return "invalid_request";
  const locales = params.getAll("ui_locales");
  if (locales.length > 1) return "invalid_request";
  const locale = locales[0];
  if (locale !== undefined && (locale.length > UI_LOCALES_MAX_LENGTH
    || locale.split(" ").length > UI_LOCALES_MAX_TAGS || !UI_LOCALES.test(locale))) return "invalid_request";
  return null;
}

/**
 * Reads the lock and refuses a live connect code echoed outside the connect_code field.
 * The connect_code field is the credential being presented. Other fields are still checked,
 * so a stored code echoed in state, scope, or the PKCE challenge is refused.
 * Caller input is not compared with owner_email.
 */
async function authorizeGate(db: D1Database, params: URLSearchParams): Promise<"ok" | "no_owner_lock" | "invalid_request"> {
  const reflected = [...params.entries()].filter(([key]) => key !== "connect_code").map(([, value]) => value);
  const candidates = [...new Set(reflected.filter((value) => CODE.test(value)))];
  if (candidates.length > 8) return "invalid_request";
  const session = db.withSession("first-primary");
  const hashes = await Promise.all(candidates.map((value) => sha256Hex(value)));
  const statements = [session.prepare("SELECT owner_email FROM owner_lock WHERE id = 1")];
  if (hashes.length > 0) {
    const marks = hashes.map((_, index) => `?${index + 1}`).join(", ");
    statements.push(session.prepare(
      `SELECT 1 AS hit FROM connect_code WHERE code_sha256 IN (${marks}) LIMIT 1`,
    ).bind(...hashes));
  }
  const results = await session.batch<EmailRow | { hit: number }>(statements);
  const emailResult = results[0];
  if (!emailResult?.success || !Array.isArray(emailResult.results)) throw new Error("internal_error");
  if (emailResult.results.length !== 1) return "no_owner_lock";
  const email = emailResult.results[0];
  if (!email || !("owner_email" in email) || typeof email.owner_email !== "string") throw new Error("internal_error");
  const codeResult = results[1];
  if (codeResult && (!codeResult.success || !Array.isArray(codeResult.results))) throw new Error("internal_error");
  if (codeResult && codeResult.results.length > 0) return "invalid_request";
  return "ok";
}

async function token(
  request: Request,
  env: BridgeEnv,
  origin: string,
  ctx: ExecutionContext | undefined,
): Promise<Response> {
  if (request.method !== "POST") return fail("method_not_allowed", 405, "json", { Allow: "POST" });
  const url = new URL(request.url);
  if (url.search || request.headers.has("Authorization")) return fail("invalid_request", 400, "json");
  if (mediaType(request) !== "application/x-www-form-urlencoded") return fail("unsupported_media_type", 415, "json");
  let bytes: Uint8Array;
  try {
    bytes = await readBounded(request);
  } catch (error) {
    const tooLarge = error instanceof BodyTooLarge;
    return fail(tooLarge ? "body_too_large" : "invalid_request", tooLarge ? 413 : 400, "json");
  }
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    return fail("invalid_request", 400, "json");
  }
  const refusal = prefilterToken(params, `${origin}/mcp`);
  if (refusal) return fail(refusal, tokenStatus(refusal), "json");
  if (!env.OAUTH_KV) return fail("oauth_not_configured", 500, "json");
  const forwarded = new Request(request.url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: bytes,
  });
  const kind = params.get("grant_type");
  const refresh = kind === "refresh_token" ? params.get("refresh_token") : kind === null ? params.get("token") : null;
  const clientId = params.get("client_id") ?? unverifiedIss(params.get("client_assertion") ?? "");
  const shapedRefresh = refresh !== null && SHAPED_REFRESH.test(refresh);
  const family = new RefreshFamilyExchange(env.DB,
    shapedRefresh && refresh !== null ? await refreshTokenHash(refresh) : null,
    clientId, kind === null);
  // The provider parses the body and authenticates the client before it reads
  // a grant. Claim only on that read, so a rejected request does not write D1.
  const admission: { lateClaimKey: string | null } = { lateClaimKey: null };
  const cleanupParts = kind === "authorization_code" ? params.get("code")?.split(":")
    : kind === null ? refresh?.split(":") : undefined;
  const cleanupGrant = cleanupParts?.length === 3 && /^(dot|claude)$/.test(cleanupParts[0] ?? "")
    && /^[A-Za-z0-9_-]{1,128}$/.test(cleanupParts[1] ?? "")
    ? { participant: cleanupParts[0] ?? "", grantId: cleanupParts[1] ?? "" } : null;
  const cleanupPrefix = cleanupGrant === null ? null : `token:${cleanupGrant.participant}:${cleanupGrant.grantId}:`;
  let providerCleanup: Promise<void> | undefined;
  let cleanupFailure: { error: unknown } | undefined;
  const beforeProviderCleanup = async () => {
    if (cleanupGrant === null) throw new RefreshFamilyRefused();
    // Only an observed cleanup operation reaches here. The request reference
    // limits the target; the provider's token/code and client checks authorize
    // it. Revoke D1 before listing/deleting KV, even when there are no tokens.
    providerCleanup ??= family.revokeProviderGrant(cleanupGrant.participant, cleanupGrant.grantId);
    try {
      await providerCleanup;
    } catch (error) {
      // 1.2.3 swallows replay-cleanup exceptions. Retain the failure so a pause
      // or D1 outage cannot silently become an ordinary invalid_grant response.
      cleanupFailure = { error };
      throw error;
    }
  };
  let providerWriteAttempted = false;
  const kv = new Proxy(env.OAUTH_KV, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver);
      if (typeof value !== "function") return value;
      if (property === "list" && cleanupPrefix !== null) {
        return async (...args: unknown[]) => {
          if (isRecord(args[0]) && args[0].prefix === cleanupPrefix) await beforeProviderCleanup();
          return value.apply(target, args);
        };
      }
      if (property === "get") {
        return async (...args: unknown[]) => {
          const key = args[0];
          if (typeof key !== "string" || key !== admission.lateClaimKey) return value.apply(target, args);
          admission.lateClaimKey = null;
          const read = () => value.apply(target, args);
          // Revocation claims only after a read succeeds, then returns a second
          // read taken while the claim is held. The provider sees that second
          // snapshot, and only when it still matches the first, so a pre-claim
          // record cannot authorize the delete. A throw before the claim writes
          // nothing.
          if (family.revocation) {
            let first: unknown;
            try {
              first = await read();
            } catch {
              throw new RefreshFamilyUnavailable();
            }
            if (first == null) return first;
            await family.prepare();
            let second: unknown;
            try {
              second = await read();
            } catch {
              await family.release();
              throw new RefreshFamilyUnavailable();
            }
            if (JSON.stringify(first) !== JSON.stringify(second)) {
              await family.release();
              throw new RefreshFamilyUnavailable();
            }
            return second;
          }
          // Refresh claims before its snapshot is returned, so two rotations
          // cannot both mint from one grant. A failed read charges the rotation
          // budget instead of releasing the claim for another immediate write.
          await family.prepare();
          try {
            return await read();
          } catch {
            await family.release();
            throw new RefreshFamilyUnavailable();
          }
        };
      }
      if (property !== "put" && property !== "delete") return value.bind(target);
      return async (...args: unknown[]) => {
        const key = args[0];
        if (typeof key === "string" && (key.startsWith("grant:") || key.startsWith("token:"))) {
          if (property === "delete" && cleanupGrant !== null
            && (key === `grant:${cleanupGrant.participant}:${cleanupGrant.grantId}`
              || ((kind === "authorization_code" || providerCleanup !== undefined)
                && cleanupPrefix !== null && key.startsWith(cleanupPrefix) && /^[a-f0-9]{64}$/.test(key.slice(cleanupPrefix.length))))) {
            await beforeProviderCleanup();
          } else if (kind === null) {
            // A token deletion enters whole-grant cleanup only after the
            // matching provider list; direct access deletion stays specific.
            // Provider has authenticated the revoking client and proved token
            // ownership before this delete. D1 revocation precedes KV cleanup.
            await family.revoke();
          } else {
            if (!family.held) throw new RefreshFamilyRefused();
            providerWriteAttempted = true;
          }
        }
        return value.apply(target, args);
      };
    },
  });
  const onTokenGrant = async (grant: TokenExchangeCallbackOptions<OauthKvEnv>) => {
    // Only provider-validated identity/props can create or confirm a family.
    if (grant.grantType === "refresh_token") assertRefreshScope(params, grant.scope);
    await assertActiveRefreshGrant(env.DB, grant);
    const client = oauthClient(grant.clientId);
    const credentialId = refreshCredentialId(grant.props);
    if (!client || credentialId === null || grant.resource !== `${origin}/mcp`) throw new InactiveRefreshGrant();
    await family.validated({ credentialId, participant: client.participant, clientId: client.clientId, grantId: grant.grantId });
  };
  let issued: Response;
  try {
    if (kind === null && refresh !== null) {
      // Access-token revocation has no exchange callback. Authenticate it with
      // the provider before checking a temporary pause. Its revocation remains
      // token-specific; owner/family revocation uses the D1 credential timestamp.
      const validation: unknown = await createAuthorizationServer(origin).validateToken(`${origin}/mcp`, refresh, { OAUTH_KV: env.OAUTH_KV });
      if (isRecord(validation) && validation.clientId === clientId && validation.audience === `${origin}/mcp`
        && typeof validation.expiresAt === "number" && validation.expiresAt > Date.now() / 1000
        && typeof validation.clientId === "string" && typeof validation.userId === "string") {
        await assertActiveRefreshGrant(env.DB, {
          clientId: validation.clientId, subjectClientId: validation.clientId,
          userId: validation.userId, props: validation.props,
        });
      }
    }
    const timing = kind === "refresh_token" && shapedRefresh && refresh !== null && family.hash !== null
      ? await refreshClaimTiming(env.OAUTH_KV, refresh, family.hash, params)
      : kind === null && shapedRefresh && refresh !== null
        ? { claim: "late", grantKey: refreshGrantKey(refresh) } as const
        : { claim: "now" } as const;
    switch (timing.claim) {
      case "now":
        // No family hash on this path, so prepare() does not claim. Shaped
        // refreshes and revocations claim when the provider reads the grant.
        await family.prepare();
        break;
      case "skip":
        await family.prepare({ claim: false });
        break;
      case "late":
        admission.lateClaimKey = timing.grantKey;
        // Classify deferral and reuse before the provider runs. The claim
        // waits until the grant read, after the request has been parsed and
        // the client authenticated. Revocation has no budget to classify and
        // claims on that same read.
        if (kind === "refresh_token") await family.prepare({ claim: false });
        break;
      case "unavailable":
        // The pre-read failed. Do not claim: a later provider failure would
        // release that claim without charging the rotation budget.
        throw new RefreshFamilyUnavailable();
      default: {
        const neverTiming: never = timing;
        return neverTiming;
      }
    }
    issued = await createAuthorizationServer(origin, kind === null ? undefined : onTokenGrant).fetch(
      forwarded,
      { OAUTH_KV: kv },
      requestContext(ctx),
    );
    if (cleanupFailure !== undefined) throw cleanupFailure.error;
    if (kind !== null && issued.ok) {
      const body: unknown = await issued.clone().json();
      if (!isRecord(body) || typeof body.refresh_token !== "string") throw new RefreshFamilyRefused();
      await family.complete(body.refresh_token);
    } else if (providerWriteAttempted) {
      // 1.2.3 can translate a storage exception into a returned 429 after a
      // grant write. A non-success response does not prove issuance was inert.
      await family.revoke();
    } else {
      // An ancestor rejected before the callback still proves possession by
      // its full D1 hash. invalid_grant here follows provider client auth;
      // invalid_client and scope errors never revoke the family.
      const body: unknown = issued.status >= 400 ? await issued.clone().json() : null;
      if (family.reuse && ((kind === null && issued.ok)
        || (isRecord(body) && (body.error === "invalid_grant" || body.error === "invalid_scope")))) await family.revoke();
      await family.release();
    }
  } catch (error) {
    if (providerWriteAttempted || (family.reuse && (error instanceof RefreshFamilyRefused || error instanceof RefreshScopeMismatch))) await family.revoke();
    else await family.release();
    if (error instanceof ParticipantDisabled || error instanceof RefreshFamilyBusy
      || error instanceof RefreshFamilyDeferred || error instanceof RefreshFamilyUnavailable) {
      const [reason, retryAfter] = unavailableRefusal(error);
      logInfo({ message: "bridge event", event: "oauth.unavailable", reason, status: 503 });
      return json({ error: "unavailable" }, 503, { "Retry-After": String(retryAfter) });
    }
    if (error instanceof RefreshScopeMismatch) return fail("wrong_scope", 400, "json");
    if (error instanceof InactiveRefreshGrant || error instanceof RefreshFamilyRefused) {
      logInfo({ message: "bridge event", event: "oauth.refused", reason: "invalid_grant", status: 400 });
      return json({ error: "invalid_grant" }, 400);
    }
    if (error instanceof RefreshGrantLookupFailed) return fail("internal_error", 500, "json");
    throw error;
  }
  const response = await scrub(issued);
  await logNonSuccess("oauth.refused", response);
  return response;
}

function unavailableRefusal(error: ParticipantDisabled | RefreshFamilyBusy | RefreshFamilyDeferred | RefreshFamilyUnavailable): readonly [string, number] {
  if (error instanceof RefreshFamilyDeferred) return ["refresh_budget", error.retryAfterSeconds];
  if (error instanceof RefreshFamilyBusy) return ["family_busy", REFRESH_BUSY_RETRY_AFTER_SECONDS];
  if (error instanceof RefreshFamilyUnavailable) return ["storage_unavailable", error.retryAfterSeconds];
  if (error instanceof ParticipantDisabled) return ["participant_disabled", PARTICIPANT_RETRY_AFTER_SECONDS];
  const neverError: never = error;
  return neverError;
}

function prefilterToken(params: URLSearchParams, resource: string): TokenRefusal | null {
  const seen = new Set<string>();
  for (const key of params.keys()) {
    // Any repeated parameter is invalid_request, including a field the selected
    // grant does not use. That rejection is before the family is claimed.
    if (!TOKEN_FIELDS.has(key) || seen.has(key)) return "invalid_request";
    seen.add(key);
  }
  if ([...params.values()].some((value) => GROK_TOKEN.test(value) || CONTROLS.test(value))) return "invalid_request";
  const clientIds = params.getAll("client_id");
  const assertions = params.getAll("client_assertion");
  const assertionTypes = params.getAll("client_assertion_type");
  if (clientIds.length > 1 || assertions.length > 1 || assertionTypes.length > 1) return "invalid_request";
  if (clientIds[0] !== undefined && !oauthClient(clientIds[0])) return "unknown_client";
  let client = oauthClient(clientIds[0]);
  if (assertions.length === 1) {
    const iss = unverifiedIss(assertions[0] ?? "");
    if (iss === null) return "invalid_request";
    const assertionClient = oauthClient(iss);
    if (!assertionClient) return "unknown_client";
    if (client && client.clientId !== assertionClient.clientId) return "invalid_request";
    client = assertionClient;
    if (assertionTypes.length !== 1 || assertionTypes[0] !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
      return "invalid_request";
    }
  } else if (!client) {
    return "unknown_client";
  }
  const scopeRefusal = scopeRefusalFor(params);
  if (scopeRefusal) return scopeRefusal;
  const resources = params.getAll("resource");
  if (resources.length > 1 || (resources.length === 1 && resources[0] !== resource)) return "invalid_request";
  const redirects = params.getAll("redirect_uri");
  if (redirects.length > 1 || (redirects.length === 1 && redirects[0] !== client?.redirectUri)) return "redirect_uri";
  const hints = params.getAll("token_type_hint");
  if (hints.length > 1 || (hints.length === 1 && hints[0] !== "access_token" && hints[0] !== "refresh_token")) {
    return "invalid_request";
  }
  const grants = params.getAll("grant_type");
  if (grants.length > 1) return "invalid_request";
  if (grants.length === 1) {
    if (grants[0] !== "authorization_code" && grants[0] !== "refresh_token") return "unsupported_grant";
    if (grants[0] === "authorization_code") {
      if (redirects.length !== 1) return "redirect_uri";
      if (resources.length !== 1) return "invalid_request";
      if (params.getAll("code").length !== 1 || !params.get("code")) return "invalid_request";
      if (params.getAll("code_verifier").length !== 1 || !VERIFIER.test(params.get("code_verifier") ?? "")) return "invalid_request";
    }
    if (grants[0] === "refresh_token" && (params.getAll("refresh_token").length !== 1 || !params.get("refresh_token"))) {
      return "invalid_request";
    }
    return null;
  }
  if (params.getAll("token").length !== 1 || !params.get("token")) return "invalid_request";
  return null;
}

/**
 * A refresh may omit scope and keep the grant's scope. A present scope must be
 * that same ordered list. A narrower, wider, or reordered scope is invalid_scope
 * in the provider's validated callback, before any grant/token writes. The
 * library would otherwise downscope a strict subset and rotate. An empty
 * scope parameter is a requested scope. Client authentication and token
 * validation always precede the invalid_scope response. The same comparison
 * also runs before the D1 claim when the stored grant is readable, so a
 * mismatch does not write; the provider still chooses the error.
 */
function assertRefreshScope(
  params: URLSearchParams,
  grantScope: unknown,
): void {
  if (!params.has("scope")) return;
  const requested = params.get("scope");
  if (requested === null || !stringList(grantScope)) throw new RefreshGrantLookupFailed();
  if (!sameRefreshScope(requested, grantScope)) throw new RefreshScopeMismatch();
}

function sameRefreshScope(requested: string, grantScope: readonly string[]): boolean {
  const tokens = requested === "" ? [] : requested.split(" ");
  return tokens.length === grantScope.length && tokens.every((entry, index) => entry === grantScope[index]);
}

function refreshGrantKey(refreshToken: string): string {
  const parts = refreshToken.split(":");
  return `grant:${parts[0] ?? ""}:${parts[1] ?? ""}`;
}

type RefreshClaimTiming =
  | { claim: "now" }
  | { claim: "skip" }
  | { claim: "late"; grantKey: string }
  | { claim: "unavailable" };

/**
 * Whether a shaped refresh should claim before the provider runs.
 * `skip` means the stored grant already shows this request cannot rotate
 * (scope, expiry, or an unrecognized refresh secret), so the claim would
 * only be released. `late` waits until the provider reads that grant.
 * Parsing and client authentication have finished by then, so a rejection
 * cannot claim and then release. A failed read is `unavailable`: nothing
 * is claimed, and the caller retries.
 */
async function refreshClaimTiming(
  kv: KVNamespace,
  refreshToken: string,
  hash: string,
  params: URLSearchParams,
): Promise<RefreshClaimTiming> {
  const grantKey = refreshGrantKey(refreshToken);
  let stored: unknown;
  try {
    stored = await kv.get(grantKey, { type: "json" });
  } catch {
    return { claim: "unavailable" };
  }
  if (!isRecord(stored)) return { claim: "skip" };
  if (params.has("scope")) {
    const requested = params.get("scope");
    if (requested === null || !stringList(stored.scope) || !sameRefreshScope(requested, stored.scope)) {
      return { claim: "skip" };
    }
  }
  const current = stored.refreshTokenId === hash;
  const previous = stored.previousRefreshTokenId === hash;
  if (!current && !previous) return { claim: "skip" };
  if (typeof stored.expiresAt === "number" && Number.isFinite(stored.expiresAt)) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (stored.expiresAt - nowSeconds < PROVIDER_REFRESH_MIN_REMAINING_SECONDS) return { claim: "skip" };
  }
  // Claim on the grant read for every request the pre-read still considers
  // rotatable, with or without a client assertion. The provider's parser runs
  // first, so a repeated parameter or a metadata failure writes nothing.
  return { claim: "late", grantKey };
}

/** Neutral callback error: refuses a changed scope without revoking or rotating the grant. */
class RefreshScopeMismatch extends Error {
  constructor() {
    super("bridge_scope_mismatch");
    this.name = "RefreshScopeMismatch";
  }
}

const ACTIVE_REFRESH_GRANT = `SELECT c.id AS id, p.enabled AS enabled
  FROM participant_credential AS c
  JOIN participant AS p ON p.id = c.participant
  JOIN owner_lock AS o ON o.id = 1 AND o.claimed_at = c.owner_claimed_at
  WHERE c.id = ?1 AND c.kind = 'oauth_grant'
    AND c.participant = ?2
    AND c.revoked_at IS NULL
  LIMIT 1`;

/** Raised when the refresh grant's credential is revoked or otherwise not active. Not a lookup failure. */
class InactiveRefreshGrant extends Error {
  constructor() {
    super("invalid_grant");
    this.name = "InactiveRefreshGrant";
  }
}

/** D1 could not answer whether the refresh grant is active. Issuance must deny. */
class RefreshGrantLookupFailed extends Error {
  constructor() {
    super("internal_error");
    this.name = "RefreshGrantLookupFailed";
  }
}

/**
 * D1 is the authority for this refresh. The provider would mint a token for any
 * unexpired KV grant, including one whose credential row is revoked. No row, a
 * non-null revoked_at, or any other inactive row refuses the refresh. A lookup
 * failure throws so issuance is denied. Do not throw the provider's invalid_grant
 * from here: that revokes the KV grant.
 */
async function assertActiveRefreshGrant(db: D1Database,
  grant: Pick<TokenExchangeCallbackOptions<OauthKvEnv>, "clientId" | "subjectClientId" | "userId" | "props">,
): Promise<void> {
  // Only the provider-validated identity selects the participant. Neither the
  // request's client_id nor an opaque token prefix authorizes a D1 credential.
  const client = oauthClient(grant.clientId);
  const id = refreshCredentialId(grant.props);
  if (id === null || !client || grant.userId !== client.participant
    || grant.subjectClientId !== client.clientId) throw new InactiveRefreshGrant();
  try {
    const session = db.withSession("first-primary");
    const results = await session.batch<{ id: string; enabled: number }>([
      session.prepare(ACTIVE_REFRESH_GRANT).bind(id, client.participant),
    ]);
    const result = results[0];
    if (!result?.success || !Array.isArray(result.results)) throw new RefreshGrantLookupFailed();
    if (result.results.length !== 1 || result.results[0]?.id !== id) throw new InactiveRefreshGrant();
    if (result.results[0].enabled === 0) throw new ParticipantDisabled();
  } catch (error) {
    if (error instanceof InactiveRefreshGrant || error instanceof RefreshGrantLookupFailed || error instanceof ParticipantDisabled) throw error;
    throw new RefreshGrantLookupFailed();
  }
}

function refreshCredentialId(props: unknown): string | null {
  if (!isRecord(props) || Object.keys(props).length !== 1 || !Object.hasOwn(props, "credential_id")) return null;
  const id = props.credential_id;
  if (typeof id !== "string" || id.length === 0) return null;
  return id;
}

function stringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function scopeRefusalFor(params: URLSearchParams): "invalid_request" | "wrong_scope" | null {
  const scopes = params.getAll("scope");
  if (scopes.length > 1) return "invalid_request";
  if (scopes.length === 1 && !validScope(scopes[0] ?? "")) return "wrong_scope";
  return null;
}

function validScope(scope: string): boolean {
  if (scope === "") return true;
  const tokens = scope.split(" ");
  return tokens.every((token) => token.length > 0 && SCOPE_TOKEN.test(token));
}

function unverifiedIss(jwt: string): string | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  if (parts.some((part) => part.length === 0 || part.length > 8192 || !/^[A-Za-z0-9_-]+$/.test(part))) return null;
  try {
    const payload: unknown = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1] ?? "")));
    if (!isRecord(payload) || typeof payload.iss !== "string" || payload.iss.length > 200) return null;
    return payload.iss;
  } catch {
    return null;
  }
}

function tokenStatus(reason: TokenRefusal): number {
  switch (reason) {
    case "unknown_client":
      return 401;
    case "unsupported_grant":
    case "redirect_uri":
    case "wrong_scope":
    case "invalid_request":
      return 400;
    default: {
      const neverReason: never = reason;
      return neverReason;
    }
  }
}

function fail(reason: OAuthReason, status: number, body: "html" | "json", extra?: HeadersInit): Response {
  const log = status >= 500 ? logError : logInfo;
  log({ message: "bridge event", event: "oauth.refused", reason, status });
  if (body === "html") return html(consentFailure(), status, extra);
  return json(publicError(reason, status), status, extra);
}

function publicError(reason: OAuthReason, status: number): { error: string } | { ok: false; error: "not_found" } {
  const error = reason === "unknown_client" ? "invalid_client"
    : reason === "unsupported_grant" ? "unsupported_grant_type"
    : reason === "wrong_scope" ? "invalid_scope"
    : reason === "origin_mismatch" ? "not_found"
    : status === 404 ? "not_found"
    : status >= 500 ? "internal_error"
    : "invalid_request";
  return error === "not_found" ? { ok: false, error: "not_found" } : { error };
}

function html(body: string, status: number, extra?: HeadersInit): Response {
  const headers = new Headers(extra);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return withAuthorizeHeaders(new Response(body, { status, headers }));
}

function json(body: unknown, status: number, extra?: HeadersInit): Response {
  const headers = new Headers(extra);
  headers.set("Cache-Control", "no-store");
  return Response.json(body, { status, headers });
}

async function scrub(response: Response): Promise<Response> {
  if (response.status < 400) {
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "no-store");
    headers.delete("Set-Cookie");
    return new Response(response.body, { status: response.status, headers });
  }
  let code = "invalid_request";
  try {
    const body: unknown = await response.json();
    if (isRecord(body) && typeof body.error === "string" && SAFE_CODE.test(body.error)) code = body.error;
  } catch {
    code = "invalid_request";
  }
  const headers = new Headers();
  headers.set("Cache-Control", "no-store");
  const authenticate = safeHeader(response.headers.get("WWW-Authenticate"));
  if (authenticate) headers.set("WWW-Authenticate", authenticate);
  const allow = safeHeader(response.headers.get("Allow"));
  if (allow) headers.set("Allow", allow);
  const payload = code === "not_found" ? { ok: false, error: "not_found" } : { error: code };
  return Response.json(payload, { status: response.status, headers });
}

function safeHeader(value: string | null): string | null {
  if (!value || value.length > 400 || /[\r\n]/.test(value) || GROK_TOKEN.test(value)) return null;
  return value;
}

function mediaType(request: Request): string {
  return request.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() ?? "";
}

/**
 * True only for a form POST whose single grant_type is refresh_token.
 * The original body stays readable. A missing, repeated, or other grant is false.
 * The body is not logged.
 */
export async function isRefreshTokenGrant(request: Request): Promise<boolean> {
  if (request.method !== "POST") return false;
  if (mediaType(request) !== "application/x-www-form-urlencoded") return false;
  let bytes: Uint8Array;
  try {
    bytes = await readBounded(request.clone());
  } catch {
    return false;
  }
  try {
    const params = new URLSearchParams(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
    const grants = params.getAll("grant_type");
    return grants.length === 1 && grants[0] === "refresh_token";
  } catch {
    return false;
  }
}

async function readBounded(request: Request): Promise<Uint8Array> {
  const bytes = new Uint8Array(LIMIT);
  const reader = request.body?.getReader();
  if (!reader) return bytes.subarray(0, 0);
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return bytes.subarray(0, size);
      if (value.byteLength > LIMIT - size) {
        void reader.cancel().catch(() => undefined);
        throw new BodyTooLarge();
      }
      bytes.set(value, size);
      size += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
}

async function cancel(request: Request): Promise<void> {
  await request.body?.cancel().catch(() => undefined);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function requestContext(ctx: ExecutionContext | undefined): ExecutionContext {
  // Production fetch always supplies the Workers context. Tests call the router
  // without one, so this stand-in keeps waitUntil from being dropped. The
  // library reads waitUntil and props; the remaining ExecutionContext fields
  // are not available outside a Worker.
  if (ctx) return ctx;
  const standalone = {
    waitUntil(promise: Promise<unknown>) {
      void promise.catch(() => undefined);
    },
    passThroughOnException() {},
    abort() {},
    props: {},
  };
  return standalone as ExecutionContext;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
