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
 *   - Public API and call shapes are unchanged from v3:
 *       encode(key, data, [algorithm], [cb])
 *       decode(key, token, [options], [cb])
 *     With or without a callback. Without a callback, returns
 *     { error, value } (or { error, value, header } on decode).
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

export type EncodeCallback = (
	err: JWTError | null,
	token?: string | null
) => void;

export type DecodeCallback = (
	err: JWTError | null,
	payload?: unknown,
	header?: JWTHeader
) => void;

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

export function getAlgorithms(): AlgorithmName[] {
	return Object.keys(algorithms) as AlgorithmName[];
}

export function encode(key: Key, data: unknown): EncodeResult;
export function encode(
	key: Key,
	data: unknown,
	algorithm: string
): EncodeResult;
export function encode(key: Key, data: unknown, cb: EncodeCallback): void;
export function encode(
	key: Key,
	data: unknown,
	algorithm: string,
	cb: EncodeCallback
): void;
export function encode(
	key: Key,
	data: unknown,
	algorithm?: string | EncodeCallback,
	cb?: EncodeCallback
): EncodeResult | undefined {
	let alg: string;
	if (typeof algorithm === "function" || algorithm == null) {
		cb = algorithm as EncodeCallback | undefined;
		alg = "HS256";
	} else {
		alg = algorithm;
	}

	const defaultHeader = { typ: "JWT", alg };
	const payload: unknown = isWrapper(data) ? data.payload : data;
	const header: Record<string, unknown> =
		isWrapper(data) && isPlainObject(data.header)
			? { ...data.header, ...defaultHeader }
			: defaultHeader;

	const validationError = encodeValidations(key, payload, alg);
	if (validationError) {
		return finishEncode(validationError, null, cb);
	}

	const algSpec = algorithms[alg as AlgorithmName];
	if (!algorithmMatchesKey(algSpec, inferKeyKind(key))) {
		return finishEncode(
			algSpec.type === "hmac"
				? "Algorithm/key mismatch: HMAC algorithm requires a plain secret, not an asymmetric key."
				: "Algorithm/key mismatch: asymmetric algorithm requires a PEM-encoded key, not a plain secret.",
			null,
			cb
		);
	}

	const headerPart = encodeBase64Url(JSON.stringify(header));
	const payloadPart = encodeBase64Url(JSON.stringify(payload));
	const signingInput = `${headerPart}.${payloadPart}`;
	const signature = sign(algSpec, key, signingInput);
	return finishEncode(null, `${signingInput}.${signature}`, cb);
}

export function decode(key: Key, token: string): DecodeResult;
export function decode(key: Key, token: string, cb: DecodeCallback): void;
export function decode(
	key: Key,
	token: string,
	options: DecodeOptions
): DecodeResult;
export function decode(
	key: Key,
	token: string,
	options: DecodeOptions,
	cb: DecodeCallback
): void;
export function decode(
	key: Key,
	token: string,
	optionsOrCb?: DecodeOptions | DecodeCallback,
	cb?: DecodeCallback
): DecodeResult | undefined {
	let options: DecodeOptions = {};
	if (typeof optionsOrCb === "function") {
		cb = optionsOrCb;
	} else if (optionsOrCb) {
		options = optionsOrCb;
	}

	if (!key || !token) {
		return finishDecode(
			"The key and token are mandatory!",
			null,
			undefined,
			cb
		);
	}

	const parts = token.split(".");
	if (parts.length !== 3) {
		return finishDecode(
			"The JWT should consist of three parts!",
			null,
			undefined,
			cb
		);
	}

	const header = parseJSONOrNull(decodeBase64Url(parts[0] as string));
	const payload = parseJSONOrNull(decodeBase64Url(parts[1] as string));

	if (!isPlainObject(header)) {
		return finishDecode(
			"The algorithm is not supported!",
			null,
			undefined,
			cb
		);
	}

	const algName = header.alg;
	const algorithm =
		typeof algName === "string"
			? algorithms[algName as AlgorithmName]
			: undefined;
	if (!algorithm) {
		return finishDecode(
			"The algorithm is not supported!",
			null,
			undefined,
			cb
		);
	}

	// Optional opt-in allowlist for safety-conscious callers.
	if (options.algorithms && !options.algorithms.includes(algName as string)) {
		return finishDecode(
			"The algorithm is not in the allowlist.",
			null,
			undefined,
			cb
		);
	}

	// CVE-2023-48238 fix: refuse to verify when the algorithm family
	// disagrees with the key kind. This blocks the classic RS256→HS256
	// confusion attack where an attacker re-signs a token with HMAC
	// using the server's RSA public key as the secret.
	if (!algorithmMatchesKey(algorithm, inferKeyKind(key))) {
		return finishDecode(
			algorithm.type === "hmac"
				? "Algorithm/key mismatch: refusing to verify an HMAC signature with an asymmetric key."
				: "Algorithm/key mismatch: refusing to verify an asymmetric signature with a plain secret.",
			null,
			undefined,
			cb
		);
	}

	const ok = verify(
		algorithm,
		key,
		`${parts[0]}.${parts[1]}`,
		parts[2] as string
	);
	return finishDecode(
		ok ? null : "Invalid key!",
		payload,
		header as JWTHeader,
		cb
	);
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

function finishEncode(
	err: string | null,
	value: string | null,
	cb: EncodeCallback | undefined
): EncodeResult | undefined {
	const error = err ? new JWTError(err) : null;
	if (cb) {
		cb(error, value);
		return;
	}
	return { error, value };
}

function finishDecode(
	err: string | null,
	value: unknown,
	header: JWTHeader | undefined,
	cb: DecodeCallback | undefined
): DecodeResult | undefined {
	const error = err ? new JWTError(err) : null;
	if (cb) {
		cb(error, value, header);
		return;
	}
	return header !== undefined ? { error, value, header } : { error, value };
}
