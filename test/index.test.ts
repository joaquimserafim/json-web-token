import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	decode,
	encode,
	getAlgorithms,
	JWTError,
	type JWTHeader,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const pem = readFileSync(join(here, "fixtures/test.pem"), "ascii");
const crt = readFileSync(join(here, "fixtures/test.crt"), "ascii");

const secret = "TOPSECRETTTTT";
const payload = {
	iss: "my_issurer",
	aud: "World",
	iat: 1400062400223,
	typ: "/online/transactionstatus/v2",
	request: {
		myTransactionId: "[myTransactionId]",
		merchantTransactionId: "[merchantTransactionId]",
		status: "SUCCESS",
	},
};

describe("module surface", () => {
	it("exposes JWTError as a class producing Error instances", () => {
		expect(typeof JWTError).toBe("function");
		expect(new JWTError("x")).toBeInstanceOf(Error);
		expect(new JWTError("x").name).toBe("JWTError");
	});

	it("returns the supported algorithms list", () => {
		expect(getAlgorithms()).toEqual(["HS256", "HS384", "HS512", "RS256"]);
	});
});

describe("encode", () => {
	it("produces a 3-part HMAC token by default (HS256)", () => {
		const { error, value } = encode(secret, payload);
		expect(error).toBeNull();
		expect((value as string).split(".")).toHaveLength(3);
	});

	it("produces a 3-part token for each HMAC variant", () => {
		for (const alg of ["HS256", "HS384", "HS512"] as const) {
			const { error, value } = encode(secret, payload, alg);
			expect(error).toBeNull();
			expect((value as string).split(".")).toHaveLength(3);
		}
	});

	it("produces a 3-part RS256 token from a PEM key", () => {
		const { error, value } = encode(pem, payload, "RS256");
		expect(error).toBeNull();
		expect((value as string).split(".")).toHaveLength(3);
	});

	it("rejects unsupported algorithm", () => {
		const { error } = encode(secret, payload, "wow");
		expect(error).toBeInstanceOf(JWTError);
		expect(error?.message).toBe("The algorithm is not supported!");
	});

	it("rejects null payload", () => {
		const { error } = encode(secret, null);
		expect(error?.message).toBe("The key and payload are mandatory!");
	});

	it("rejects empty payload", () => {
		const { error } = encode(secret, {});
		expect(error?.message).toBe("The payload is an empty object!");
	});

	it("rejects null key", () => {
		const { error } = encode(null as unknown as string, payload);
		expect(error?.message).toBe("The key and payload are mandatory!");
	});

	it("merges {payload, header} wrappers (defaults still win on conflict)", () => {
		const { value } = encode(
			pem,
			{ payload, header: { kid: "K1", typ: "should-be-overridden" } },
			"RS256"
		);
		const { header } = decode(crt, value as string);
		expect(header?.kid).toBe("K1");
		expect(header?.typ).toBe("JWT");
		expect(header?.alg).toBe("RS256");
	});
});

describe("decode", () => {
	it("round-trips HMAC payload", () => {
		const { value: token } = encode(secret, payload);
		const { error, value } = decode(secret, token as string);
		expect(error).toBeNull();
		expect(value).toEqual(payload);
	});

	it("round-trips RS256 payload (decode with cert)", () => {
		const { value: token } = encode(pem, payload, "RS256");
		const { error, value } = decode(crt, token as string);
		expect(error).toBeNull();
		expect(value).toEqual(payload);
	});

	it("returns the header on successful decode", () => {
		const { value: token } = encode(
			pem,
			{ payload, header: { kid: "TestKeyId" } },
			"RS256"
		);
		const { error, value, header } = decode(crt, token as string);
		expect(error).toBeNull();
		expect(value).toEqual(payload);
		expect((header as JWTHeader).kid).toBe("TestKeyId");
	});

	it("returns the header even when the signature fails", () => {
		const { value: token } = encode(secret, payload);
		const parts = (token as string).split(".");
		const tampered = [parts[0], parts[1], "bad-sig"].join(".");
		const { error, header } = decode(secret, tampered);
		expect(error?.message).toBe("Invalid key!");
		expect(header?.alg).toBe("HS256"); // header is still surfaced for diagnostics
	});

	it("rejects bogus algorithm in header", () => {
		const { value: good } = encode(secret, payload);
		const parts = (good as string).split(".");
		const badHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: "wow" })
		).toString("base64url");
		const tampered = [badHeader, parts[1], parts[2]].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("The algorithm is not supported!");
	});

	it("rejects a tampered payload (invalid signature)", () => {
		const { value: good } = encode(secret, payload);
		const parts = (good as string).split(".");
		const tampered = [parts[0], "bad-payload-here", parts[2]].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("Invalid key!");
	});

	it("rejects a token signed with a different secret", () => {
		const { value: token } = encode(secret, payload);
		const { error } = decode("wrong-secret", token as string);
		expect(error?.message).toBe("Invalid key!");
	});

	it("rejects null key", () => {
		const { error } = decode(null as unknown as string, "a.b.c");
		expect(error?.message).toBe("The key and token are mandatory!");
	});

	it("rejects a token without three parts", () => {
		const { error } = decode(secret, "only.two");
		expect(error?.message).toBe("The JWT should consist of three parts!");
	});

	it("rejects a token whose header is not a JSON object", () => {
		const { value: good } = encode(secret, payload);
		const parts = (good as string).split(".");
		const scalarHeader =
			Buffer.from('"not an object"').toString("base64url");
		const tampered = [scalarHeader, parts[1], parts[2]].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("The algorithm is not supported!");
	});

	it("rejects a token whose header.alg is not a string", () => {
		const { value: good } = encode(secret, payload);
		const parts = (good as string).split(".");
		const numericAlgHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: 123 })
		).toString("base64url");
		const tampered = [numericAlgHeader, parts[1], parts[2]].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("The algorithm is not supported!");
	});
});

describe("alg: none vulnerability — both encode and decode reject it", () => {
	it("encode refuses to issue an alg:none token", () => {
		const { error } = encode(secret, payload, "none");
		expect(error?.message).toBe("The algorithm is not supported!");
	});

	it("decode refuses to accept a tampered alg:none token", () => {
		const { value: token } = encode(secret, payload);
		const parts = (token as string).split(".");
		const noneHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: "none" })
		).toString("base64url");
		const tampered = [noneHeader, parts[1], parts[2]].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("The algorithm is not supported!");
	});
});

describe("CVE-2023-48238 — algorithm/key-type confusion is rejected", () => {
	it("blocks the RS256→HS256 confusion attack", () => {
		// Real-world attack: attacker has the server's RSA public key
		// (the `crt` cert) and forges a token with alg:HS256 whose
		// signature is an HMAC keyed by that public key string. The
		// server, expecting RS256, calls decode(crt, attackerToken).
		const forgedHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: "HS256" })
		).toString("base64url");
		const payloadPart = Buffer.from(
			JSON.stringify({ admin: true, sub: "attacker" })
		).toString("base64url");
		const signingInput = `${forgedHeader}.${payloadPart}`;
		const forgedSig = createHmac("sha256", crt)
			.update(signingInput)
			.digest("base64url");
		const attackerToken = `${signingInput}.${forgedSig}`;

		const { error } = decode(crt, attackerToken);
		expect(error).toBeInstanceOf(JWTError);
		expect(error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("encode refuses HS256 with a PEM key", () => {
		const { error } = encode(pem, payload, "HS256");
		expect(error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("encode refuses RS256 with a plain secret", () => {
		const { error } = encode(secret, payload, "RS256");
		expect(error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("decode refuses an HS256 token when the caller passed a PEM key", () => {
		const { value: hmacToken } = encode(secret, payload, "HS256");
		const { error } = decode(crt, hmacToken as string);
		expect(error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("decode refuses an RS256 token when the caller passed a plain secret", () => {
		const { value: rsaToken } = encode(pem, payload, "RS256");
		const { error } = decode("plain-secret", rsaToken as string);
		expect(error?.message).toMatch(/Algorithm\/key mismatch/);
	});
});

describe("decode — optional `algorithms` allowlist", () => {
	it("accepts a token whose alg is in the allowlist", () => {
		const { value: token } = encode(pem, payload, "RS256");
		const { error, value } = decode(crt, token as string, {
			algorithms: ["RS256"],
		});
		expect(error).toBeNull();
		expect(value).toEqual(payload);
	});

	it("rejects a token whose alg is not in the allowlist", () => {
		const { value: token } = encode(secret, payload, "HS256");
		const { error } = decode(secret, token as string, {
			algorithms: ["RS256"],
		});
		expect(error?.message).toBe("The algorithm is not in the allowlist.");
	});
});

describe("key accepted as a Buffer (HMAC)", () => {
	it("encodes and decodes with a Buffer-typed secret", () => {
		const bufSecret = Buffer.from("a-32-byte-secret-string-here!!", "utf8");
		const { value: token } = encode(bufSecret, payload);
		const { error, value } = decode(bufSecret, token as string);
		expect(error).toBeNull();
		expect(value).toEqual(payload);
	});
});

describe("HMAC verification is timing-safe", () => {
	it("rejects a forged signature that is the wrong length", () => {
		const { value: token } = encode(secret, payload);
		const parts = (token as string).split(".");
		const shortSig = (parts[2] as string).slice(0, 10);
		const tampered = [parts[0], parts[1], shortSig].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("Invalid key!");
	});

	it("rejects a forged signature of correct length but wrong bytes", () => {
		const { value: token } = encode(secret, payload);
		const parts = (token as string).split(".");
		const sig = parts[2] as string;
		const tampered = [
			parts[0],
			parts[1],
			sig.slice(0, -2) + (sig.slice(-2) === "AA" ? "BB" : "AA"),
		].join(".");
		const { error } = decode(secret, tampered);
		expect(error?.message).toBe("Invalid key!");
	});
});
