import { describe, expect, it } from "vitest";
import { browserCanConnect, skipReason } from "./policy.ts";

const none = { include: new Set<number>(), exclude: new Set<number>() };

describe("skipReason", () => {
	it("skips tunnels", () => {
		expect(skipReason({ port: 15432, processes: ["ssh"] }, none)).toBe(
			"tunnel",
		);
		expect(skipReason({ port: 8080, processes: ["kubectl"] }, none)).toBe(
			"tunnel",
		);
		expect(skipReason({ port: 8081, processes: ["sshd"] }, none)).toBe(
			"tunnel",
		);
	});

	it("recognises a process name cut short by the system", () => {
		expect(
			skipReason({ port: 8080, processes: ["session-manager"] }, none),
		).toBe("tunnel");
	});

	it("skips a port when any process on it is a tunnel", () => {
		expect(skipReason({ port: 3000, processes: ["node", "ssh"] }, none)).toBe(
			"tunnel",
		);
	});

	it("skips line-protocol services by process and by port", () => {
		expect(skipReason({ port: 7777, processes: ["redis-server"] }, none)).toBe(
			"line-protocol",
		);
		expect(
			skipReason({ port: 6379, processes: ["com.docker.backend"] }, none),
		).toBe("line-protocol");
	});

	it("probes other listeners", () => {
		expect(skipReason({ port: 3000, processes: ["node"] }, none)).toBeNull();
	});

	it("lets --include override a skip", () => {
		const overrides = { include: new Set([6379]), exclude: new Set<number>() };
		expect(
			skipReason({ port: 6379, processes: ["redis-server"] }, overrides),
		).toBeNull();
	});

	it("gives --exclude priority over --include", () => {
		const overrides = { include: new Set([3000]), exclude: new Set([3000]) };
		expect(skipReason({ port: 3000, processes: ["node"] }, overrides)).toBe(
			"excluded",
		);
	});
});

describe("browserCanConnect", () => {
	it("rejects ports on the bad-port list", () => {
		expect(browserCanConnect(25)).toBe(false);
		expect(browserCanConnect(143)).toBe(false);
	});

	it("allows common alternatives that are not on the list", () => {
		for (const port of [1025, 1143, 6379, 11211])
			expect(browserCanConnect(port)).toBe(true);
	});
});
