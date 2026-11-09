import { describe, expect, it } from "vitest";
import {
	assessPath,
	classifyBanner,
	HOSTILE_ORIGIN,
	type HttpObservation,
	httpVerdicts,
	isServiceIncomplete,
	type PathObservations,
} from "./classify.ts";

function response(
	status: number,
	headers: Record<string, string> = {},
): HttpObservation {
	return { status, headers, bodyBytes: 10, truncated: false };
}

function observations(
	overrides: Partial<PathObservations> = {},
): PathObservations {
	return {
		path: "/",
		open: response(200),
		origin: response(200),
		preflight: response(204),
		rebind: response(403),
		...overrides,
	};
}

const ALLOWS_WRITE = {
	"access-control-allow-origin": "*",
	"access-control-allow-methods": "GET, PUT",
	"access-control-allow-headers": "Content-Type",
};

describe("classifyBanner", () => {
	it.each([
		["SSH-2.0-OpenSSH_9", "ssh"],
		["* OK IMAP ready", "imap"],
		["+OK POP3 ready", "pop3"],
		["220 mail ESMTP", "smtp"],
		["220 ProFTPD Server", "ftp"],
		["hello", "unknown"],
	])("classifies %s", (banner, expected) => {
		expect(classifyBanner(banner)).toBe(expected);
	});
});

describe("assessPath", () => {
	it("treats a wildcard CORS header on a served page as readable", () => {
		const origin = response(200, { "access-control-allow-origin": "*" });
		expect(assessPath(observations({ origin })).corsReadable).toBe(true);
	});

	it("treats a reflected origin with credentials as readable with credentials", () => {
		const origin = response(200, {
			"access-control-allow-origin": HOSTILE_ORIGIN,
			"access-control-allow-credentials": "true",
		});
		const assessment = assessPath(observations({ origin }));
		expect(assessment.corsReadable).toBe(true);
		expect(assessment.corsCredentials).toBe(true);
	});

	it("does not claim credentials with a wildcard CORS header", () => {
		const origin = response(200, {
			"access-control-allow-origin": "*",
			"access-control-allow-credentials": "true",
		});
		expect(assessPath(observations({ origin })).corsCredentials).toBe(false);
	});

	it("does not count a served page with no CORS header as readable", () => {
		const assessment = assessPath(observations());
		expect(assessment.corsReadable).toBe(false);
		expect(assessment.originGuard).toBe("served");
	});

	it("counts a CORS header on an error response as readable", () => {
		const origin = response(500, { "access-control-allow-origin": "*" });
		expect(assessPath(observations({ origin })).corsReadable).toBe(true);
	});

	it("does not count a CORS header on a redirect as readable", () => {
		const origin = response(302, { "access-control-allow-origin": "*" });
		expect(assessPath(observations({ origin })).corsReadable).toBe(false);
	});

	it("does not count another origin as allowed", () => {
		const origin = response(200, {
			"access-control-allow-origin": "https://app.example",
		});
		expect(assessPath(observations({ origin })).corsReadable).toBe(false);
	});

	it("requires origin, method and header for preflight to allow writes", () => {
		expect(
			assessPath(observations({ preflight: response(204, ALLOWS_WRITE) }))
				.preflightAllowsWrite,
		).toBe(true);
		const noMethod = { ...ALLOWS_WRITE, "access-control-allow-methods": "GET" };
		expect(
			assessPath(observations({ preflight: response(204, noMethod) }))
				.preflightAllowsWrite,
		).toBe(false);
	});

	it("marks a 404 path as absent", () => {
		const assessment = assessPath(
			observations({ open: response(404), origin: null, rebind: null }),
		);
		expect(assessment.present).toBe(false);
		expect(assessment.complete).toBe(true);
	});

	it("records a rejected hostile Host", () => {
		expect(assessPath(observations()).hostGuard).toBe("rejected");
	});

	it("treats a redirect for a hostile Host as neither served nor rejected", () => {
		expect(assessPath(observations({ rebind: response(302) })).hostGuard).toBe(
			"other",
		);
	});

	it.each([
		["no GET response", { open: null }],
		["no preflight response", { preflight: null }],
		["no Origin response", { origin: null }],
		["no Host response", { rebind: null }],
		["a 400 baseline", { open: response(400) }],
		["a redirecting baseline", { open: response(302) }],
		["a 405 baseline", { open: response(405) }],
		["a 500 baseline", { open: response(500) }],
		["a redirected hostile Origin", { origin: response(302) }],
		["a redirected hostile Host", { rebind: response(302) }],
		["a redirected preflight", { preflight: response(302) }],
		["a failed preflight", { preflight: response(502) }],
		["a rate-limited preflight", { preflight: response(429) }],
	])("is incomplete with %s", (_name, overrides) => {
		expect(assessPath(observations(overrides)).complete).toBe(false);
	});

	it.each([405, 501])(
		"is complete when the preflight is refused with %d",
		(status) => {
			expect(
				assessPath(observations({ preflight: response(status) })).complete,
			).toBe(true);
		},
	);

	it("is complete when every check answered", () => {
		expect(assessPath(observations()).complete).toBe(true);
	});

	it("accepts a 400 on a path other than the root", () => {
		const assessment = assessPath(
			observations({ path: "/api", open: response(400) }),
		);
		expect(assessment.complete).toBe(true);
	});

	it("treats a 404 for a hostile Host as rejected", () => {
		const assessment = assessPath(observations({ rebind: response(404) }));
		expect(assessment.hostGuard).toBe("rejected");
		expect(assessment.complete).toBe(true);
	});

	it("replaces unprintable characters in the content type", () => {
		const open = response(200, { "content-type": "text/\u009bhtml" });
		expect(assessPath(observations({ open })).contentType).toBe("text/?html");
	});

	it("carries truncation through", () => {
		const open = { ...response(200), truncated: true };
		expect(assessPath(observations({ open })).openTruncated).toBe(true);
	});

	it("keeps size and content type without parameters", () => {
		const open = response(200, { "content-type": "text/html; charset=utf-8" });
		const assessment = assessPath(observations({ open }));
		expect(assessment.openBytes).toBe(10);
		expect(assessment.contentType).toBe("text/html");
	});
});

describe("isServiceIncomplete", () => {
	const complete = assessPath(observations());
	const absent = assessPath(
		observations({ open: response(404), origin: null, rebind: null }),
	);

	it("is false when every check on a present path answered", () => {
		expect(isServiceIncomplete([complete], null)).toBe(false);
	});

	it("is true when no tested path exists", () => {
		expect(isServiceIncomplete([absent], null)).toBe(true);
	});

	it("is true when a WebSocket upgrade got no response", () => {
		const sockets = [{ path: "/", status: null }];
		expect(isServiceIncomplete([complete], sockets)).toBe(true);
	});

	it("is true when a WebSocket upgrade hit a server error", () => {
		const sockets = [{ path: "/", status: 500 }];
		expect(isServiceIncomplete([complete], sockets)).toBe(true);
	});

	it("is true when a WebSocket upgrade was rate limited", () => {
		const sockets = [{ path: "/", status: 429 }];
		expect(isServiceIncomplete([complete], sockets)).toBe(true);
	});

	it("is false when a WebSocket upgrade was refused", () => {
		const sockets = [{ path: "/", status: 403 }];
		expect(isServiceIncomplete([complete], sockets)).toBe(false);
	});
});

describe("httpVerdicts", () => {
	it("reports nothing for a loopback service with guards", () => {
		const assessment = assessPath(observations({ origin: response(403) }));
		expect(httpVerdicts("loopback", [assessment], [])).toEqual([]);
	});

	it("reports a served hostile Host as rebindable", () => {
		const assessment = assessPath(observations({ rebind: response(200) }));
		expect(
			httpVerdicts("loopback", [assessment], []).map((v) => v.kind),
		).toEqual(["rebindable"]);
	});

	it("does not report a redirected hostile Host as rebindable", () => {
		const assessment = assessPath(observations({ rebind: response(302) }));
		expect(httpVerdicts("loopback", [assessment], [])).toEqual([]);
	});

	it("reports an open root bound beyond loopback", () => {
		const assessment = assessPath(observations());
		expect(
			httpVerdicts("all-interfaces", [assessment], []).map((v) => v.kind),
		).toEqual(["open-network"]);
	});

	it("reports an open network from any present path", () => {
		const root = assessPath(
			observations({ open: response(404), origin: null, rebind: null }),
		);
		const metrics = assessPath(observations({ path: "/metrics" }));
		const verdicts = httpVerdicts("all-interfaces", [root, metrics], []);
		expect(verdicts.map((v) => v.kind)).toEqual(["open-network"]);
		expect(verdicts[0]?.evidence).toContain("/metrics");
	});

	it("does not report an open network when the path asks for credentials", () => {
		const open = response(200, { "www-authenticate": "Basic" });
		const assessment = assessPath(observations({ open }));
		expect(httpVerdicts("all-interfaces", [assessment], [])).toEqual([]);
	});

	it("reports a 101 socket and ignores a rejected one", () => {
		const sockets = [
			{ path: "/ws", status: 101 },
			{ path: "/", status: 403 },
		];
		expect(httpVerdicts("loopback", [], sockets).map((v) => v.kind)).toEqual([
			"socket-open",
		]);
	});

	it("gives no read verdicts for absent paths", () => {
		const assessment = assessPath(
			observations({
				open: response(404),
				origin: null,
				rebind: response(200),
			}),
		);
		expect(httpVerdicts("loopback", [assessment], [])).toEqual([]);
	});

	it("reports cross-origin writes when GET returns 404", () => {
		const assessment = assessPath(
			observations({
				open: response(404),
				origin: null,
				rebind: null,
				preflight: response(204, ALLOWS_WRITE),
			}),
		);
		expect(
			httpVerdicts("loopback", [assessment], []).map((v) => v.kind),
		).toEqual(["cross-origin-writes"]);
	});
});
