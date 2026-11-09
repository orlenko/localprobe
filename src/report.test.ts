import { describe, expect, it } from "vitest";
import {
	assessPath,
	type HttpObservation,
	isServiceIncomplete,
	type PathAssessment,
} from "./classify.ts";
import type { Listener } from "./listeners.ts";
import { renderPlan, renderReport, reportLimits } from "./report.ts";
import type { ServiceResult } from "./scan.ts";

const listener: Listener = {
	port: 3000,
	pids: [1],
	processes: ["node"],
	binds: [{ address: "127.0.0.1", family: "IPv4" }],
	exposure: "loopback",
};

const context = { sawAllUsers: true, webSocketsTested: true };

function response(status: number): HttpObservation {
	return { status, headers: {}, bodyBytes: 10, truncated: false };
}

function httpResult(paths: PathAssessment[]): ServiceResult {
	return {
		listener,
		kind: "http",
		tls: false,
		paths,
		webSockets: null,
		posts: [],
		incomplete: isServiceIncomplete(paths, null),
		verdicts: [],
	};
}

const guarded = assessPath({
	path: "/",
	open: response(200),
	origin: response(403),
	preflight: response(403),
	rebind: response(403),
});

describe("renderReport", () => {
	it("names the tested paths when no exposure was found", () => {
		expect(renderReport([httpResult([guarded])], context)).toContain(
			"No exposure found on tested paths: /",
		);
	});

	it("reports incomplete when a check got no response", () => {
		const hung = assessPath({
			path: "/",
			open: response(200),
			origin: null,
			preflight: response(403),
			rebind: response(403),
		});
		const report = renderReport([httpResult([hung])], context);
		expect(report).toContain("Incomplete");
		expect(report).not.toContain("No exposure found");
	});

	it("reports incomplete when no path exists", () => {
		const absent = assessPath({
			path: "/",
			open: response(404),
			origin: null,
			preflight: response(404),
			rebind: null,
		});
		const report = renderReport([httpResult([absent])], context);
		expect(report).toContain("no tested path exists");
		expect(report).not.toContain("No exposure found");
	});

	it("shows size and content type in the details", () => {
		const open = { ...response(200), headers: { "content-type": "text/html" } };
		const path = assessPath({
			path: "/",
			open,
			origin: response(403),
			preflight: response(403),
			rebind: response(403),
		});
		expect(renderReport([httpResult([path])], context)).toContain(
			"open 200 10 bytes text/html",
		);
	});

	it("reports incomplete when a listener gave no HTTP response", () => {
		const result: ServiceResult = {
			listener,
			kind: "non-http",
			protocol: "no-response",
			incomplete: true,
			verdicts: [],
		};
		expect(renderReport([result], context)).toContain("Incomplete");
	});

	it("says why a port was not probed", () => {
		const result: ServiceResult = {
			listener,
			kind: "not-probed",
			reason: "tunnel",
			verdicts: [],
		};
		expect(renderReport([result], context)).toContain("tunnel or forward");
	});
});

describe("renderPlan", () => {
	it("lists probes and skips and states that nothing was sent", () => {
		const tunnel = { ...listener, port: 9000, processes: ["ssh"] };
		const plan = renderPlan([listener, tunnel], {
			include: new Set(),
			exclude: new Set(),
		});
		expect(plan).toMatch(/3000\s+node\s+loopback\s+probe/);
		expect(plan).toMatch(/9000\s+ssh\s+loopback\s+skip: tunnel/);
		expect(plan).toContain("Nothing was sent");
	});
});

describe("reportLimits", () => {
	it("warns when sockets of other users are hidden and WebSockets were skipped", () => {
		const limits = reportLimits({
			sawAllUsers: false,
			webSocketsTested: false,
		});
		expect(limits.join(" ")).toContain("sudo");
		expect(limits.join(" ")).toContain("--ws");
	});
});
