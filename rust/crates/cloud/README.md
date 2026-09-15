# pay-cloud

Local service behind the `gh auth login`-style onboarding flow for the `pay`
CLI. The CLI opens a browser page served here, the page collects an email and
redirects back to a loopback listener in the CLI with a one-time code, and the
CLI redeems the code with PKCE (RFC 7636 S256).

Milestone 1: everything runs locally, state is in memory, and the exchange
returns a `pending` stub — no wallet provisioning yet.

## Build the UI

The onboarding page lives in `web-ui/` (second Vite app, built into
`web-ui/dist-cloud/`) and is embedded into the binary at compile time:

```sh
cd web-ui && pnpm install --frozen-lockfile && pnpm build:cloud
```

Without a built `dist-cloud`, debug builds embed a placeholder page; release
builds fail unless `PAY_CLOUD_ALLOW_PLACEHOLDER=1` is set. `PAY_CLOUD_DIST`
points the build at an alternative dist directory.

## Run

```sh
cargo run -p pay-cloud -- --port 8402
```

Flags: `--bind` (default `127.0.0.1`), `--port` (default `8402`). Logging is
`RUST_LOG`-driven and goes to stderr.

Pages: `GET /`, `GET /onboard`, `GET /onboard/*` serve the SPA; other unknown
paths fall back to `index.html`. `GET /health` returns `{"status":"ok"}`.

Try it end to end without the browser:

```sh
cargo run -p pay -- cloud-onboard --url http://127.0.0.1:8402
```

## JSON endpoints

### `POST /api/onboard/start`

Called by the page once the user submits an email.

```json
{
  "email": "a@b.co",
  "callback": "http://127.0.0.1:53211/callback",
  "state": "<16..128 base64url chars>",
  "code_challenge": "<43..128 base64url chars>",
  "account": "default",
  "host": "my-laptop",
  "cli": "0.29.0"
}
```

`callback` must be `http://127.0.0.1:<port>/callback` or
`http://localhost:<port>/callback` with no query string or fragment.
`account`, `host`, and `cli` are optional and informational.

Response `200`:

```json
{ "redirect": "http://127.0.0.1:53211/callback?code=<code>&state=<state>" }
```

`code` is 32 random bytes (base64url, no padding), valid for 5 minutes,
single use. Validation failures return `400`
`{ "error": "<code>", "message": "..." }` with `error` one of
`invalid_request`, `invalid_email`, `invalid_callback`, `invalid_state`,
`invalid_code_challenge`.

### `POST /v1/onboard/exchange`

Called by the CLI after the loopback listener receives the code.

```json
{ "code": "<code>", "code_verifier": "<verifier>" }
```

The server checks `base64url(sha256(code_verifier)) == code_challenge` and
consumes the session. Unknown, expired, reused, or mismatched codes return
`400 { "error": "invalid_grant", "message": "..." }`.

Response `200`:

```json
{
  "provider": "pay-cloud",
  "status": "pending",
  "email": "a@b.co",
  "network": "mainnet",
  "message": "Wallet provisioning is not available yet."
}
```
