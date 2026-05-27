/**
 * json-web-token — JWT encode/decode with zero runtime dependencies.
 *
 * v4 highlights:
 *   - Fixes CVE-2023-48238 (algorithm confusion). The library now
 *     rejects any token whose algorithm family does not match the
 *     key it was handed. PEM-encoded keys can only be used with the
 *     asymmetric algorithms; plain secrets can only be used with the
 *     HMAC algorithms. Optional `algorithms` allowlist on `decode`
 *     adds a second layer for safety-conscious callers.
 *   - Zero runtime deps (Node's `crypto` + `Buffer` only). Drops
 *     base64-url, is.object, json-parse-safe, xtend.
 *   - HMAC verification uses `crypto.timingSafeEqual` instead of a
 *     plain `===` compare, so an attacker can't timing-leak which
 *     prefix bytes of the signature match.
 *   - `alg: 'none'` and unknown algorithms continue to be rejected.
 *   - Synchronous result-object API only — callbacks dropped:
 *       encode(key, data, [algorithm])  →  { error, value }
 *       decode(key, token, [options])   →  { error, value, header? }
 *     Wrap in a Promise yourself if you want async ergonomics.
 */

import {
	createHmac,
	createSign,
	createVerify,
	timingSafeEqual,
} from "node:crypto";

const algorithms = {
	HS256: { hash: "sha256", type: "hmac" },
	HS384: { hash: "sha384", type: "hmac" },
	HS512: { hash: "sha512", type: "hmac" },
	RS256: { hash: "RSA-SHA256", type: "sign" },
} as const;

type AlgorithmName = keyof typeof algorithms;
type AlgorithmSpec = (typeof algorithms)[AlgorithmName];

export class JWTError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "JWTError";
	}
}

export interface JWTHeader {
	typ?: string;
	alg?: string;
	[key: string]: unknown;
}

export interface EncodeResult {
	error: JWTError | null;
	value: string | null;
}

export interface DecodeResult {
	error: JWTError | null;
	value: unknown;
	header?: JWTHeader;
}

export interface DecodeOptions {
	/**
	 * Optional whitelist of acceptable algorithms (e.g. `["RS256"]`).
	 * When provided, `decode` rejects any token whose `header.alg` is
	 * not in the list. The key-type vs algorithm-type guard runs
	 * regardless of this option.
	 */
	algorithms?: string[];
}

type Key = string | Buffer;

interface PayloadWrapper {
	payload: unknown;
	header?: Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

type KeyKind = "asymmetric" | "secret";

/**
 * Classify a key as asymmetric (PEM-encoded RSA/EC/Ed key material) or
 * a plain HMAC secret. The classifier is conservative: anything that
 * doesn't start with a PEM banner is treated as a secret.
 *
 * This is the root of the CVE-2023-48238 fix — we use the result to
 * refuse the HMAC verify path when the caller passed an asymmetric
 * key (which is what the algorithm-confusion attack exploits).
 */
function inferKeyKind(key: Key): KeyKind {
	const head = Buffer.isBuffer(key)
		? key.subarray(0, 11).toString("ascii")
		: key.trimStart().slice(0, 11);
	return head === "-----BEGIN " ? "asymmetric" : "secret";
}

function algorithmMatchesKey(alg: AlgorithmSpec, kind: KeyKind): boolean {
	return alg.type === "hmac" ? kind === "secret" : kind === "asymmetric";
}

function isWrapper(value: unknown): value is PayloadWrapper {
	return isPlainObject(value) && "payload" in value && value.payload != null;
}

function fail(message: string): EncodeResult {
	return { error: new JWTError(message), value: null };
}

function failDecode(message: string): DecodeResult {
	return { error: new JWTError(message), value: null };
}

export function getAlgorithms(): AlgorithmName[] {
	return Object.keys(algorithms) as AlgorithmName[];
}

export function encode(
	key: Key,
	data: unknown,
	algorithm: string = "HS256"
): EncodeResult {
	const defaultHeader = { typ: "JWT", alg: algorithm };
	const payload: unknown = isWrapper(data) ? data.payload : data;
	const header: Record<string, unknown> =
		isWrapper(data) && isPlainObject(data.header)
			? { ...data.header, ...defaultHeader }
			: defaultHeader;

	const validationError = encodeValidations(key, payload, algorithm);
	if (validationError) return fail(validationError);

	const algSpec = algorithms[algorithm as AlgorithmName];
	if (!algorithmMatchesKey(algSpec, inferKeyKind(key))) {
		return fail(
			algSpec.type === "hmac"
				? "Algorithm/key mismatch: HMAC algorithm requires a plain secret, not an asymmetric key."
				: "Algorithm/key mismatch: asymmetric algorithm requires a PEM-encoded key, not a plain secret."
		);
	}

	const headerPart = encodeBase64Url(JSON.stringify(header));
	const payloadPart = encodeBase64Url(JSON.stringify(payload));
	const signingInput = `${headerPart}.${payloadPart}`;
	const signature = sign(algSpec, key, signingInput);
	return { error: null, value: `${signingInput}.${signature}` };
}

export function decode(
	key: Key,
	token: string,
	options: DecodeOptions = {}
): DecodeResult {
	if (!key || !token) return failDecode("The key and token are mandatory!");

	const parts = token.split(".");
	if (parts.length !== 3) {
		return failDecode("The JWT should consist of three parts!");
	}

	const header = parseJSONOrNull(decodeBase64Url(parts[0] as string));
	const payload = parseJSONOrNull(decodeBase64Url(parts[1] as string));

	if (!isPlainObject(header)) {
		return failDecode("The algorithm is not supported!");
	}

	const algName = header.alg;
	const algorithm =
		typeof algName === "string"
			? algorithms[algName as AlgorithmName]
			: undefined;
	if (!algorithm) return failDecode("The algorithm is not supported!");

	if (options.algorithms && !options.algorithms.includes(algName as string)) {
		return failDecode("The algorithm is not in the allowlist.");
	}

	// CVE-2023-48238 fix: refuse to verify when the algorithm family
	// disagrees with the key kind. This blocks the classic RS256→HS256
	// confusion attack where an attacker re-signs a token with HMAC
	// using the server's RSA public key as the secret.
	if (!algorithmMatchesKey(algorithm, inferKeyKind(key))) {
		return failDecode(
			algorithm.type === "hmac"
				? "Algorithm/key mismatch: refusing to verify an HMAC signature with an asymmetric key."
				: "Algorithm/key mismatch: refusing to verify an asymmetric signature with a plain secret."
		);
	}

	const ok = verify(
		algorithm,
		key,
		`${parts[0]}.${parts[1]}`,
		parts[2] as string
	);
	return {
		error: ok ? null : new JWTError("Invalid key!"),
		value: payload,
		header: header as JWTHeader,
	};
}

function encodeValidations(
	key: Key,
	payload: unknown,
	algorithm: string
): string | null {
	if (!key || payload == null) return "The key and payload are mandatory!";
	if (isPlainObject(payload) && Object.keys(payload).length === 0) {
		return "The payload is an empty object!";
	}
	if (!algorithms[algorithm as AlgorithmName]) {
		return "The algorithm is not supported!";
	}
	return null;
}

function sign(alg: AlgorithmSpec, key: Key, input: string): string {
	if (alg.type === "hmac") {
		return createHmac(alg.hash, key).update(input).digest("base64url");
	}
	return createSign(alg.hash).update(input).sign(key, "base64url");
}

function verify(
	alg: AlgorithmSpec,
	key: Key,
	input: string,
	signature: string
): boolean {
	if (alg.type === "hmac") {
		const expected = sign(alg, key, input);
		const a = Buffer.from(expected, "utf8");
		const b = Buffer.from(signature, "utf8");
		if (a.length !== b.length) return false;
		return timingSafeEqual(a, b);
	}
	return createVerify(alg.hash)
		.update(input)
		.verify(key, signature, "base64url");
}

function encodeBase64Url(input: string): string {
	return Buffer.from(input, "utf8").toString("base64url");
}

function decodeBase64Url(input: string): string {
	return Buffer.from(input, "base64url").toString("utf8");
}

function parseJSONOrNull(input: string): unknown {
	try {
		return JSON.parse(input);
	} catch {
		return null;
	}
}
