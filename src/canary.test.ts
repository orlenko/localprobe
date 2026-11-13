import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	CANARY_CSP,
	CANARY_HTML,
	CANARY_MARKER,
	CORS_HEADERS,
	closeFrame,
	escapeField,
	formatArrival,
	formatUnparsed,
	isWebSocketKey,
	MAX_MINUTES,
	parseMinutes,
	textFrame,
	webSocketAccept,
} from "./canary.ts";

const base = {
	time: new Date("2026-01-02T03:04:05.000Z"),
	localAddress: "127.0.0.1",
	family: "IPv4",
	method: "GET",
	path: "/lp/abcd1234/cors-v4",
};

describe("parseMinutes", () => {
	it("accepts 1 to the maximum", () => {
		expect(parseMinutes("1")).toBe(1);
		expect(parseMinutes(String(MAX_MINUTES))).toBe(MAX_MINUTES);
	});

	it.each(["0", String(MAX_MINUTES + 1), "1.5", "", "ten", "-3", "1e1"])(
		"rejects %j",
		(value) => {
			expect(() => parseMinutes(value)).toThrow();
		},
	);
});

describe("webSocketAccept", () => {
	it("matches the RFC 6455 example", () => {
		expect(webSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")).toBe(
			"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
		);
	});
});

describe("isWebSocketKey", () => {
	it("accepts 16 bytes of base64", () => {
		expect(isWebSocketKey("dGhlIHNhbXBsZSBub25jZQ==")).toBe(true);
	});

	it.each([
		undefined,
		"",
		"abc",
		"dGhlIHNhbXBsZSBub25jZQ",
		"dGhlIHNhbXBsZSBub25jZQ==x",
	])("rejects %j", (key) => {
		expect(isWebSocketKey(key)).toBe(false);
	});
});

describe("frames", () => {
	it("encodes a short text frame", () => {
		expect([...textFrame("hi")]).toEqual([0x81, 2, 0x68, 0x69]);
	});

	it("encodes a normal close", () => {
		expect([...closeFrame()]).toEqual([0x88, 2, 0x03, 0xe8]);
	});

	it("refuses payloads that need an extended length", () => {
		expect(() => textFrame("x".repeat(126))).toThrow();
	});
});

describe("escapeField", () => {
	it("leaves printable ASCII alone", () => {
		expect(escapeField("https://evil.example")).toBe("https://evil.example");
	});

	it("escapes terminal control sequences", () => {
		expect(escapeField("a\u001b[31mred")).toBe("a\\u{1b}[31mred");
	});

	it("escapes newlines so one arrival stays one line", () => {
		expect(escapeField("a\r\nb")).toBe("a\\u{d}\\u{a}b");
	});

	it("escapes non-ASCII, including bidi overrides", () => {
		expect(escapeField("x‮y")).toBe("x\\u{202e}y");
	});

	it("escapes backslashes so escapes cannot be forged", () => {
		expect(escapeField("\\u{1b}")).toBe("\\\\u{1b}");
	});

	it("quotes values with spaces or quotes", () => {
		expect(escapeField('a b"c')).toBe('"a b\\"c"');
		expect(escapeField("")).toBe('""');
	});

	it("caps long values", () => {
		expect(escapeField("a".repeat(500))).toBe(`"${"a".repeat(200)}"+300`);
	});

	it("keeps IPv6 hosts readable", () => {
		expect(escapeField("[::1]:47823")).toBe("[::1]:47823");
	});

	it("cannot forge the cap marker", () => {
		expect(escapeField('x"+300')).toBe('"x\\"+300"');
	});
});

describe("formatArrival", () => {
	it("logs the named headers in a fixed order", () => {
		const line = formatArrival({
			...base,
			headers: {
				"sec-fetch-site": "cross-site",
				origin: "https://page.example",
				host: "127.0.0.1:47823",
				"sec-fetch-mode": "cors",
				"x-other": "ignored",
			},
		});
		expect(line).toBe(
			"2026-01-02T03:04:05.000Z local=127.0.0.1/IPv4 GET /lp/abcd1234/cors-v4 host=127.0.0.1:47823 origin=https://page.example sec-fetch-site=cross-site sec-fetch-mode=cors cookie=absent authorization=absent",
		);
	});

	it("records cookie and authorization presence, never their values", () => {
		const line = formatArrival({
			...base,
			headers: {
				cookie: "session=s3cr3t; theme=dark",
				authorization: "Bearer t0ken",
			},
		});
		expect(line).toContain("cookie=present(2)");
		expect(line).toContain("authorization=present");
		expect(line).not.toContain("s3cr3t");
		expect(line).not.toContain("t0ken");
	});

	it("escapes the path", () => {
		const line = formatArrival({
			...base,
			path: "/a\u001b]0;title\u0007",
			headers: {},
		});
		expect([...line].every((char) => char >= " " && char <= "~")).toBe(true);
	});
});

describe("canary page", () => {
	it("allows its own script and nothing else", () => {
		const script = /<script>(.*)<\/script>/.exec(CANARY_HTML)?.[1] ?? "";
		const hash = createHash("sha256").update(script).digest("base64");
		expect(CANARY_CSP).toContain(`'sha256-${hash}'`);
		expect(CANARY_CSP).toContain("default-src 'none'");
	});

	it("carries the marker the page looks for", () => {
		expect(CANARY_HTML).toContain(CANARY_MARKER);
	});

	it("never allows credentials", () => {
		expect(Object.keys(CORS_HEADERS)).not.toContain(
			"Access-Control-Allow-Credentials",
		);
		expect(CORS_HEADERS["Access-Control-Allow-Origin"]).toBe("*");
	});
});

describe("formatUnparsed", () => {
	it("logs a connection whose request could not be parsed", () => {
		expect(
			formatUnparsed({
				time: base.time,
				localAddress: "::1",
				family: "IPv6",
				reason: "HPE_HEADER_OVERFLOW",
			}),
		).toBe(
			"2026-01-02T03:04:05.000Z local=::1/IPv6 UNPARSED reason=HPE_HEADER_OVERFLOW",
		);
	});
});
