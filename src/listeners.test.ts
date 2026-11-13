import { describe, expect, it } from "vitest";
import { isOwnAddress, parseLsofFields, probeAddress } from "./listeners.ts";

const SAMPLE = [
	"p100",
	"cMy\\x20App",
	"f11",
	"tIPv4",
	"n*:5500",
	"f12",
	"tIPv6",
	"n*:5500",
	"p200",
	"cserver",
	"f8",
	"tIPv4",
	"n127.0.0.1:7100",
	"p300",
	"ccache",
	"f30",
	"tIPv6",
	"n[::1]:8000",
	"p400",
	"clan",
	"f3",
	"tIPv4",
	"n192.168.1.20:9000",
	"",
].join("\n");

describe("parseLsofFields", () => {
	const listeners = parseLsofFields(SAMPLE);

	it("collapses a process's IPv4 and IPv6 sockets on one port", () => {
		expect(listeners).toHaveLength(4);
		expect(listeners[0]?.binds).toEqual([
			{ address: "*", family: "IPv4" },
			{ address: "*", family: "IPv6" },
		]);
	});

	it("merges every process on a port into one listener", () => {
		const shared =
			"p1\ncnode\nf1\ntIPv4\nn*:80\np2\ncssh\nf1\ntIPv4\nn127.0.0.1:80\n";
		const [listener, ...rest] = parseLsofFields(shared);
		expect(rest).toEqual([]);
		expect(listener?.processes).toEqual(["node", "ssh"]);
		expect(listener?.pids).toEqual([1, 2]);
		expect(listener?.exposure).toBe("all-interfaces");
	});

	it("collapses worker processes that share a port", () => {
		const workers =
			"p1\ncgunicorn\nf1\ntIPv4\nn127.0.0.1:80\np2\ncgunicorn\nf1\ntIPv4\nn127.0.0.1:80\n";
		const [listener, ...rest] = parseLsofFields(workers);
		expect(rest).toEqual([]);
		expect(listener?.processes).toEqual(["gunicorn"]);
		expect(listener?.binds).toHaveLength(1);
	});

	it("decodes escaped process names", () => {
		expect(listeners[0]?.processes).toEqual(["My App"]);
	});

	it("keeps a literal space in a process name", () => {
		expect(
			parseLsofFields("p1\ncExample Sync\nf1\ntIPv6\nn[::1]:80\n")[0]
				?.processes,
		).toEqual(["Example Sync"]);
	});

	it("replaces decoded control characters", () => {
		expect(
			parseLsofFields("p1\ncbad\\x1bname\nf1\ntIPv4\nn127.0.0.1:80\n")[0]
				?.processes,
		).toEqual(["bad?name"]);
	});

	it("classifies exposure from bind addresses", () => {
		expect(listeners.map((listener) => listener.exposure)).toEqual([
			"all-interfaces",
			"loopback",
			"loopback",
			"interface-specific",
		]);
	});

	it("ignores connected sockets", () => {
		expect(
			parseLsofFields("p1\ncx\nf1\ntIPv4\nn127.0.0.1:1->127.0.0.1:2\n"),
		).toEqual([]);
	});

	it("returns nothing for empty output", () => {
		expect(parseLsofFields("")).toEqual([]);
	});
});

describe("probeAddress", () => {
	it("uses IPv4 loopback for an IPv4 wildcard", () => {
		const [listener] = parseLsofFields("p1\ncx\nf1\ntIPv4\nn*:80\n");
		expect(listener && probeAddress(listener)).toBe("127.0.0.1");
	});

	it("uses IPv6 loopback for an IPv6-only wildcard", () => {
		const [listener] = parseLsofFields("p1\ncx\nf1\ntIPv6\nn*:80\n");
		expect(listener && probeAddress(listener)).toBe("::1");
	});

	it("uses the bound address for an interface-specific listener", () => {
		const [listener] = parseLsofFields("p1\ncx\nf1\ntIPv4\nn192.168.1.20:80\n");
		expect(listener && probeAddress(listener)).toBe("192.168.1.20");
	});
});

describe("isOwnAddress", () => {
	it("accepts loopback and this machine's addresses only", () => {
		expect(isOwnAddress("127.0.0.1", [])).toBe(true);
		expect(isOwnAddress("::1", [])).toBe(true);
		expect(isOwnAddress("192.168.1.20", ["192.168.1.20"])).toBe(true);
		expect(isOwnAddress("10.0.0.9", ["192.168.1.20"])).toBe(false);
	});
});
