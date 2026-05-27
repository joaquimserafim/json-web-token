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
	it("exposes JWTError as a function that produces Error instances", () => {
		expect(typeof JWTError).toBe("function");
		expect(new JWTError("x")).toBeInstanceOf(Error);
		expect(new JWTError("x").name).toBe("JWTError");
	});

	it("returns the supported algorithms list", () => {
		const algorithms = getAlgorithms();
		expect(Array.isArray(algorithms)).toBe(true);
		expect(algorithms).toEqual(["HS256", "HS384", "HS512", "RS256"]);
	});
});

describe("encode — callback API", () => {
	it("produces a 3-part HMAC token (default HS256)", () =>
		new Promise<void>((done) => {
			encode(secret, payload, (err, token) => {
				expect(err).toBeNull();
				expect(token).toBeTruthy();
				expect((token as string).split(".")).toHaveLength(3);
				done();
			});
		}));

	it("produces a 3-part RS256 token from a PEM key", () =>
		new Promise<void>((done) => {
			encode(pem, payload, "RS256", (err, token) => {
				expect(err).toBeNull();
				expect(token).toBeTruthy();
				expect((token as string).split(".")).toHaveLength(3);
				done();
			});
		}));

	it("rejects unsupported algorithm", () =>
		new Promise<void>((done) => {
			encode(secret, payload, "wow", (err) => {
				expect(err).toBeInstanceOf(JWTError);
				expect(err?.message).toBe("The algorithm is not supported!");
				done();
			});
		}));

	it("rejects null payload", () =>
		new Promise<void>((done) => {
			encode(secret, null, (err) => {
				expect(err?.message).toBe("The key and payload are mandatory!");
				done();
			});
		}));

	it("rejects empty payload", () =>
		new Promise<void>((done) => {
			encode(secret, {}, (err) => {
				expect(err?.message).toBe("The payload is an empty object!");
				done();
			});
		}));

	it("rejects null key", () =>
		new Promise<void>((done) => {
			encode(null as unknown as string, payload, (err) => {
				expect(err?.message).toBe("The key and payload are mandatory!");
				done();
			});
		}));
});

describe("encode — result API (no callback)", () => {
	it("returns { error: null, value: token } on success", () => {
		const res = encode(secret, payload);
		expect(res.error).toBeNull();
		expect(typeof res.value).toBe("string");
		expect((res.value as string).split(".")).toHaveLength(3);
	});

	it("returns an error for null payload", () => {
		const res = encode(secret, null);
		expect(res.error).toBeInstanceOf(JWTError);
		expect(res.error?.message).toBe("The key and payload are mandatory!");
	});

	it("returns an error for empty payload", () => {
		const res = encode(secret, {});
		expect(res.error?.message).toBe("The payload is an empty object!");
	});

	it("returns an error for null secret", () => {
		const res = encode(null as unknown as string, payload);
		expect(res.error?.message).toBe("The key and payload are mandatory!");
	});
});

describe("decode — callback API", () => {
	it("round-trips HMAC payload", () =>
		new Promise<void>((done) => {
			const { value: token } = encode(secret, payload);
			decode(secret, token as string, (err, decoded) => {
				expect(err).toBeNull();
				expect(decoded).toEqual(payload);
				done();
			});
		}));

	it("round-trips RS256 payload (decode with cert)", () =>
		new Promise<void>((done) => {
			const { value: token } = encode(pem, payload, "RS256");
			decode(crt, token as string, (err, decoded) => {
				expect(err).toBeNull();
				expect(decoded).toEqual(payload);
				done();
			});
		}));

	it("returns extra header to the callback when custom headers were set", () =>
		new Promise<void>((done) => {
			const { value: token } = encode(
				pem,
				{ payload, header: { kid: "TestKeyId" } },
				"RS256"
			);
			decode(crt, token as string, (err, decoded, header) => {
				expect(err).toBeNull();
				expect(decoded).toEqual(payload);
				expect((header as JWTHeader).kid).toBe("TestKeyId");
				done();
			});
		}));

	it("rejects bogus algorithm in header", () =>
		new Promise<void>((done) => {
			const { value: good } = encode(secret, payload);
			const parts = (good as string).split(".");
			const badHeader = Buffer.from(
				JSON.stringify({ typ: "JWT", alg: "wow" })
			).toString("base64url");
			const tampered = [badHeader, parts[1], parts[2]].join(".");
			decode(secret, tampered, (err) => {
				expect(err?.message).toBe("The algorithm is not supported!");
				done();
			});
		}));

	it("rejects a tampered payload (invalid signature)", () =>
		new Promise<void>((done) => {
			const { value: good } = encode(secret, payload);
			const parts = (good as string).split(".");
			const tampered = [parts[0], "bad-payload-here", parts[2]].join(".");
			decode(secret, tampered, (err) => {
				expect(err?.message).toBe("Invalid key!");
				done();
			});
		}));

	it("rejects a token signed with a different secret", () =>
		new Promise<void>((done) => {
			const { value: token } = encode(secret, payload);
			decode("wrong-secret", token as string, (err) => {
				expect(err?.message).toBe("Invalid key!");
				done();
			});
		}));

	it("rejects null key", () =>
		new Promise<void>((done) => {
			decode(null as unknown as string, "a.b.c", (err) => {
				expect(err?.message).toBe("The key and token are mandatory!");
				done();
			});
		}));

	it("rejects a token without three parts", () =>
		new Promise<void>((done) => {
			decode(secret, "only.two", (err) => {
				expect(err?.message).toBe(
					"The JWT should consist of three parts!"
				);
				done();
			});
		}));
});

describe("decode — result API (no callback)", () => {
	it("returns { error: null, value: payload }", () => {
		const { value: token } = encode(secret, payload);
		const res = decode(secret, token as string);
		expect(res.error).toBeNull();
		expect(res.value).toEqual(payload);
	});

	it("returns the header when one was attached", () => {
		const { value: token } = encode(
			pem,
			{ payload, header: { kid: "TestKeyId" } },
			"RS256"
		);
		const res = decode(crt, token as string);
		expect(res.error).toBeNull();
		expect(res.value).toEqual(payload);
		expect(res.header?.kid).toBe("TestKeyId");
	});

	it("returns an error object on malformed token", () => {
		const res = decode(secret, "garbage");
		expect(res.error?.message).toBe(
			"The JWT should consist of three parts!"
		);
	});
});

describe("alg: none vulnerability — both encode and decode reject it", () => {
	it("encode refuses to issue an alg:none token", () =>
		new Promise<void>((done) => {
			encode(secret, payload, "none", (err) => {
				expect(err?.message).toBe("The algorithm is not supported!");
				done();
			});
		}));

	it("decode refuses to accept a tampered alg:none token", () => {
		const { value: token } = encode(secret, payload);
		const parts = (token as string).split(".");
		const noneHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: "none" })
		).toString("base64url");
		const tampered = [noneHeader, parts[1], parts[2]].join(".");
		const res = decode(secret, tampered);
		expect(res.error?.message).toBe("The algorithm is not supported!");
	});
});

describe("decode — malformed header rejection (defensive parsing)", () => {
	it("rejects a token whose header is valid base64url but not a JSON object", () => {
		const goodToken = encode(secret, payload).value as string;
		const parts = goodToken.split(".");
		const scalarHeader =
			Buffer.from('"not an object"').toString("base64url");
		const tampered = [scalarHeader, parts[1], parts[2]].join(".");
		const res = decode(secret, tampered);
		expect(res.error?.message).toBe("The algorithm is not supported!");
	});

	it("rejects a token whose header.alg is not a string", () => {
		const goodToken = encode(secret, payload).value as string;
		const parts = goodToken.split(".");
		const numericAlgHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: 123 })
		).toString("base64url");
		const tampered = [numericAlgHeader, parts[1], parts[2]].join(".");
		const res = decode(secret, tampered);
		expect(res.error?.message).toBe("The algorithm is not supported!");
	});
});

describe("CVE-2023-48238 — algorithm/key-type confusion is rejected", () => {
	it("blocks the RS256→HS256 confusion attack", () => {
		// Real-world attack: attacker has the server's RSA public key
		// (the `crt` cert), and forges a token with alg:HS256 whose
		// signature is an HMAC keyed by that public key string. The
		// server, expecting RS256, calls decode(crt, attackerToken).
		const forgedHeader = Buffer.from(
			JSON.stringify({ typ: "JWT", alg: "HS256" })
		).toString("base64url");
		const payloadPart = Buffer.from(
			JSON.stringify({ admin: true, sub: "attacker" })
		).toString("base64url");
		const signingInput = `${forgedHeader}.${payloadPart}`;
		// crypto would be available globally in Node but we'll import via the
		// same path the library uses to keep the test honest.
		// eslint-disable-next-line @typescript-eslint/no-require-imports
		const { createHmac } =
			require("node:crypto") as typeof import("node:crypto");
		const forgedSig = createHmac("sha256", crt)
			.update(signingInput)
			.digest("base64url");
		const attackerToken = `${signingInput}.${forgedSig}`;

		const res = decode(crt, attackerToken);
		expect(res.error).toBeInstanceOf(JWTError);
		expect(res.error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("encode refuses HS256 with a PEM key", () => {
		const res = encode(pem, payload, "HS256");
		expect(res.error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("encode refuses RS256 with a plain secret", () => {
		const res = encode(secret, payload, "RS256");
		expect(res.error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("decode refuses an HS256 token when the caller passed a PEM key", () => {
		// A perfectly-valid HMAC token, presented to a verifier that
		// passed in a PEM. Even without the confusion-attack signature
		// the library refuses on the key-type mismatch alone.
		const { value: hmacToken } = encode(secret, payload, "HS256");
		const res = decode(crt, hmacToken as string);
		expect(res.error?.message).toMatch(/Algorithm\/key mismatch/);
	});

	it("decode refuses an RS256 token when the caller passed a plain secret", () => {
		const { value: rsaToken } = encode(pem, payload, "RS256");
		const res = decode("plain-secret", rsaToken as string);
		expect(res.error?.message).toMatch(/Algorithm\/key mismatch/);
	});
});

describe("decode — optional `algorithms` allowlist", () => {
	it("accepts a token whose alg is in the allowlist", () => {
		const { value: token } = encode(pem, payload, "RS256");
		const res = decode(crt, token as string, { algorithms: ["RS256"] });
		expect(res.error).toBeNull();
		expect(res.value).toEqual(payload);
	});

	it("rejects a token whose alg is not in the allowlist", () => {
		const { value: token } = encode(secret, payload, "HS256");
		const res = decode(secret, token as string, { algorithms: ["RS256"] });
		expect(res.error?.message).toBe(
			"The algorithm is not in the allowlist."
		);
	});

	it("supports the callback form with options", () =>
		new Promise<void>((done) => {
			const { value: token } = encode(secret, payload, "HS256");
			decode(
				secret,
				token as string,
				{ algorithms: ["RS256"] },
				(err) => {
					expect(err?.message).toBe(
						"The algorithm is not in the allowlist."
					);
					done();
				}
			);
		}));
});

describe("key accepted as a Buffer (HMAC)", () => {
	it("encodes and decodes with a Buffer-typed secret", () => {
		const bufSecret = Buffer.from("a-32-byte-secret-string-here!!", "utf8");
		const { error: e1, value: token } = encode(bufSecret, payload);
		expect(e1).toBeNull();
		const { error: e2, value: decoded } = decode(
			bufSecret,
			token as string
		);
		expect(e2).toBeNull();
		expect(decoded).toEqual(payload);
	});
});

describe("HMAC verification is timing-safe", () => {
	it("rejects a forged signature that is the wrong length", () => {
		const { value: token } = encode(secret, payload);
		const parts = (token as string).split(".");
		const shortSig = (parts[2] as string).slice(0, 10);
		const tampered = [parts[0], parts[1], shortSig].join(".");
		const res = decode(secret, tampered);
		expect(res.error?.message).toBe("Invalid key!");
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
		const res = decode(secret, tampered);
		expect(res.error?.message).toBe("Invalid key!");
	});
});
