/**
 * Copyright (C) 2026 ADMRN (admrn.com)
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Test preload. The pinned OAuth provider reads
 * `Cloudflare.compatibilityFlags.global_fetch_strictly_public` while the
 * module loads. Production sets that flag in wrangler.example.jsonc; workerd
 * exposes it. Node does not, so the test runner sets it before importing the
 * package and redirects `cloudflare:workers` at the local stub.
 */
import { register } from "node:module";

globalThis.Cloudflare = {
  compatibilityFlags: { global_fetch_strictly_public: true },
};

await register("./cloudflare-workers-loader.mjs", {
  parentURL: import.meta.url,
});

// Node is not the Cloudflare edge, so it does not set CF-Connecting-IP.
// Limited routes fail closed without that address. Supply a documentation
// address unless a test opts out. Production code never reads the opt-out header.
const NativeRequest = globalThis.Request;
globalThis.Request = class extends NativeRequest {
  constructor(input, init) {
    if (typeof input !== "string" && !(input instanceof URL)) {
      super(input, init);
      return;
    }
    const headers = new Headers(init?.headers);
    if (headers.get("x-admrn-test-omit-client-ip") === "1") {
      headers.delete("x-admrn-test-omit-client-ip");
      headers.delete("CF-Connecting-IP");
    } else if (!headers.get("CF-Connecting-IP")) {
      headers.set("CF-Connecting-IP", "203.0.113.10");
    }
    super(input, { ...init, headers });
  }
};
