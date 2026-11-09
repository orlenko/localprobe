import { describe, expect, it } from "vitest";
import { parsePort, parsePortPath, pathsForPort } from "./args.ts";

describe("parsePort", () => {
	it("accepts valid ports", () => {
		expect(parsePort("8080")).toBe(8080);
	});

	it.each(["0", "65536", "80a", "", "1e3", "-1"])("rejects %j", (value) => {
		expect(() => parsePort(value)).toThrow();
	});
});

describe("parsePortPath", () => {
	it("parses a port and path", () => {
		expect(parsePortPath("8080:/api/reset?x=1")).toEqual({
			port: 8080,
			path: "/api/reset?x=1",
		});
	});

	it.each(["/api", "8080:api", "8080:/a b", "abc:/api", "8080:"])(
		"rejects %j",
		(value) => {
			expect(() => parsePortPath(value)).toThrow();
		},
	);
});

describe("pathsForPort", () => {
	it("returns only paths named for that port", () => {
		const entries = [
			{ port: 1, path: "/a" },
			{ port: 2, path: "/b" },
		];
		expect(pathsForPort(2, entries)).toEqual(["/b"]);
	});
});
