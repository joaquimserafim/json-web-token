# json-web-token

[![CI](https://github.com/joaquimserafim/json-web-token/actions/workflows/ci.yml/badge.svg)](https://github.com/joaquimserafim/json-web-token/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/json-web-token.svg)](https://www.npmjs.com/package/json-web-token)

JSON Web Token (JWT) encode/decode for Node. Zero runtime dependencies,
timing-safe signature verification, synchronous result-object API.

## Install

```sh
npm install json-web-token
# or
pnpm add json-web-token
# or
yarn add json-web-token
```

## Quick start

```js
import { encode, decode } from "json-web-token";        // ESM
// const { encode, decode } = require("json-web-token"); // CJS

const secret = "TOPSECRETTTTT";
const payload = { iss: "me", aud: "you", iat: Date.now() };

const { error, value: token } = encode(secret, payload);
if (error) throw error;

const { error: e2, value: decoded, header } = decode(secret, token);
if (e2) throw e2;
console.log(decoded, header);
```

The library is synchronous — both `encode` and `decode` return their
result immediately. If you want async ergonomics, wrap them yourself:

```js
const tokenP = Promise.resolve(encode(secret, payload));
```

### Custom headers

```js
const { value: token } = encode(secret, {
  payload: { iss: "me", aud: "you" },
  header: { kid: "my-key-id" },
}, "HS512");
```

Header keys you provide are merged with the defaults — `typ` and `alg` are
always set by the library and cannot be overridden through this surface.

### Locking decode to a specific algorithm

```js
const { error, value } = decode(publicKey, token, { algorithms: ["RS256"] });
```

Any token whose `header.alg` is outside the list is rejected before any
signature work happens.

## API

```ts
function encode(
  key: string | Buffer,
  data: unknown,
  algorithm?: string,           // defaults to "HS256"
): EncodeResult;

function decode(
  key: string | Buffer,
  token: string,
  options?: DecodeOptions,
): DecodeResult;

interface DecodeOptions {
  algorithms?: string[];        // optional allowlist; rejects header.alg outside the list
}

function getAlgorithms(): string[];   // ["HS256","HS384","HS512","RS256"]
class    JWTError extends Error { }
```

`EncodeResult` is `{ error: JWTError | null; value: string | null }`.
`DecodeResult` is `{ error: JWTError | null; value: unknown; header?: JWTHeader }`.

## Security notes

- **CVE-2023-48238 (algorithm confusion) is fixed.** v4 refuses to verify
  any token whose algorithm family does not match the key handed to
  `decode`. PEM-encoded keys (anything starting with `-----BEGIN`) can
  only be paired with the asymmetric algorithms (`RS*`); plain secrets
  (string or Buffer without PEM markers) can only be paired with the
  HMAC algorithms (`HS*`). This blocks the classic RS256→HS256 swap
  where an attacker re-signs a token with HMAC using the server's RSA
  public key as the HMAC secret.
- **Optional algorithm allowlist.** Safety-conscious callers can pass
  `{ algorithms: ["RS256"] }` (or any subset) to `decode` to reject
  any token whose `header.alg` is outside that list, in addition to the
  key-type guard above.
- **Timing-safe HMAC verify** — v4 compares signatures with
  `crypto.timingSafeEqual` on length-checked Buffers, removing the
  timing side-channel that was present in v3's string `===` compare.
- **`alg: 'none'` is rejected** in both `encode` and `decode`.
- **Claim validation is out of scope.** `exp`, `nbf`, `iat`, `iss`,
  `aud`, `sub` are not validated automatically. Check them in your own
  code on the decoded payload.

## Supported algorithms

`HS256`, `HS384`, `HS512`, `RS256`.

## Migrating from v3

The `{ error, value, [header] }` return shape and `getAlgorithms()` /
`JWTError` are unchanged. **Callback overloads have been removed** —
v4 is sync-only. If you used the callback form in v3:

```js
// v3
jwt.encode(secret, payload, (err, token) => { ... });

// v4 — just inline it
const { error, value: token } = jwt.encode(secret, payload);
if (error) { /* ... */ }
```

Other changes worth knowing:

| Topic | v3 | v4 |
| --- | --- | --- |
| Min Node | `>=8` | `>=18` |
| Runtime deps | 4 (`base64-url`, `is.object`, `json-parse-safe`, `xtend`) | **none** |
| Call style | callback OR result-object | **result-object only** |
| HMAC verify | string `===` (timing-leaky) | `crypto.timingSafeEqual` |
| Algorithm confusion | **vulnerable (CVE-2023-48238)** | **fixed** — key-type / alg-family guard on encode + decode |
| Algorithm allowlist | none | optional `algorithms` in `decode` options |
| Module formats | CJS only | ESM + CJS via `exports` map |
| Types | hand-written `index.d.ts` (loose `any`) | TS source, generated `.d.mts` / `.d.cts` |
| Base64url | `base64-url` package | Node native `Buffer` |
| Build | hand-edited `index.js` | tsup from TS |
| Test runner | mocha + nyc | vitest with v8 coverage |
| Linter | `standard` | `biome` |
| CI | Travis (Node 8/10/12) | GitHub Actions (Node 20/22/24) |

## Size

Zero runtime dependencies. What ships in the npm tarball:

| What                                  | Raw      | Gzipped  |
| ------------------------------------- | -------- | -------- |
| **ESM runtime** (`index.mjs`)         | 4 880 B  | 1 599 B  |
| **CJS runtime** (`index.cjs`)         | 4 941 B  | 1 609 B  |
| **Types** (`.d.mts` / `.d.cts`)       | 5 238 B  | 1 167 B  |
| Sourcemaps (debug-only, not loaded)   | 27 610 B | 4 511 B  |

Only one of the two runtime files is loaded by your bundler / Node, so
the real cost in your app is ~1.6 kB gzipped.

## License

ISC © [@joaquimserafim](https://github.com/joaquimserafim)
