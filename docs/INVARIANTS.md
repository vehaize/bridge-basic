# Safety invariants

These are the nine invariants in the [message path](design/message-path.md#safety-invariants). `test/invariants.test.ts` has one test for each. The tests run the item lifecycle, `/mcp`, the Grok Bot wake, the rate limit, and the retention sweep. They are behaviour checks.

The wake is a hint. Its body is `type`, `item_id`, and `occurred_at`. A missing rate-limit binding fails closed. Retention deletes finished rows on the caller's clock and does not read item text.

## 1. Text is data

Item text is stored and returned. It does not choose a URL to fetch, open another item, or decide which rows retention deletes. The wake body does not include it.

## 2. Messages grant nothing

An item that asks for a credential, spending, or publication does not create a credential, does not change the owner lock, and does not add those fields to the wake.

## 3. Owner approval lives outside the bridge

Every item is labelled `owner_approval: "required"`. The sender cannot set that label. There is no approve tool. Accepting a result does not create a follow-up item or an approval record.

## 4. Results are unverified

A result is `unverified`. Acceptance with `checked: true` and a note is `checked_by_requester`, which is the sender's claim. The label is never `verified`.

## 5. Only the sender reviews

The recipient cannot accept or reject. Acceptance records the sender's decision and creates no further item.

## 6. The credential decides the role

The verified credential is the participant. Text that names the other participant, and an extra identity field, do not change the sender. The sender cannot submit the result on their own item.

## 7. No Worker-held secret or personal data in responses

`/mcp` responses, a rate-limit refusal, and wake logs do not contain the owner email, the bearer token, the token hash, or the wake secret. The wake log does not contain the wake URL. `/token` and the `/authorize` redirect are the OAuth exceptions described in the design. They are not item responses.

## 8. The Worker's side effects are bounded

A bridge request does not write `owner_lock` or `bootstrap_secret_spend`. A rate-limit refusal writes nothing. The only outbound fetch these tests observe for an item is the configured Grok Bot wake, not a URL taken from the item. Retention deletes an old item and leaves the owner lock in place.

## 9. Assume prompt injection

Instructions inside an item do not skip the rate limit, do not choose the wake URL, do not change the sender, and do not keep a finished row past retention or delete an open row early.
