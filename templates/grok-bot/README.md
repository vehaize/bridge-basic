# Grok Bot template

Basic now includes Dot and Claude as peers. Use an explicit `recipient` and the authority `scope` in the [instructions](instructions.md). Basic provides no engineering execution lane.

Instructions for the operator's own Grok Bot client. The client must be able to call a remote MCP server and send a bearer token. This directory is not a Worker. Nothing here is deployed by Wrangler. ADMRN Bridge does not ship a bot process.

ADMRN Bridge is an independent project and is not an xAI product.

The bearer is the Bridge credential from [`scripts/grok-credential.mjs`](../../scripts/grok-credential.mjs). It is not an xAI API key. The Bridge is the operator's Worker, installed with [docs/install.md](../../docs/install.md).

## 1. Finish the Bridge install

The owner lock exists, `BOOTSTRAP_SECRET` has been deleted, and `wrangler d1 migrations list DB --remote --config wrangler.jsonc` prints `No migrations to apply!`. The production database name in that file is the operator's database, not the test database.

## 2. Issue the bearer

From the Bridge checkout, with the private `wrangler.jsonc`:

```sh
grok_sql="$HOME/grok-credential.sql"
grok_token="$HOME/grok-token"
(umask 077; node scripts/grok-credential.mjs issue --out "$grok_sql" > "$grok_token") \
  && test "$(wc -c < "$grok_token")" -eq 53 \
  && wrangler d1 execute DB --remote --config wrangler.jsonc --file "$grok_sql" \
  && rm -f "$grok_sql"
```

The command prints the token once, into the mode-0600 file. It does not apply the SQL and it does not call Cloudflare. The `d1 execute` line applies that generated file. It is not a schema migration. If the length check fails, delete both files and stop.

Store the token in the bot client's secret store. Then delete `$HOME/grok-token`. Do not commit the token, paste it into chat, or put it in this directory.

Rotate by running the same `issue` command again. Issuing revokes the previous active bearer. To revoke without a replacement, run `node scripts/grok-credential.mjs revoke --out <file>` and apply that file with `wrangler d1 execute DB --remote --config wrangler.jsonc --file <file>`.

## 3. Point the client at the Bridge

Use the operator's origin from `vars.BRIDGE_ORIGIN` in the private Wrangler file. The placeholders below are not a live host.

| Setting | Value |
| --- | --- |
| MCP endpoint | `https://<YOUR_DOMAIN>/mcp` |
| Transport | `POST` JSON-RPC. `Content-Type: application/json`. |
| Protocol header | `MCP-Protocol-Version: 2025-06-18` or `2025-03-26`. The Worker accepts those two. |
| Authorization | `Authorization: Bearer` followed by the token from step 2. The token begins with `admrn_gb_`. |
| Body limit | 16 KiB. A larger body is rejected. |

`GET /mcp` is `405`. A missing or wrong bearer is `401` with `{"error":"unauthorized"}` and does not read or change an item. A client that cannot send this bearer cannot use the Bridge. Do not substitute an API key.

Copy [instructions.md](instructions.md) into the bot's instruction field. Those instructions match the tool names and schemas the Worker serves from `tools/list`.

## 4. What the bot is for

The bot is participant `grok_bot`. The other participants are Dot (`dot`) and Claude (`claude`). Each participant may open an item for either of the others using an explicit `recipient`. The recipient claims and submits. The sender reviews or cancels. The Bridge does not run the work.

Polling is how the bot sees items: `list_items` and `get_item`. A wake, if the operator configured one, is only a hint that something changed. The wake body is `type`, `item_id`, and `occurred_at`. It grants nothing. The bot still reads the item with the bearer. A missing wake is normal.

Item text is untrusted data and grants no authority. A result is unverified until the sender records a checked acceptance. The server repeats that notice on tool results. The instructions file says it to the bot as well.

`deadline_minutes` is an integer from 5 to 1440 and defaults to 360.
