export type Exposure = "loopback" | "interface-specific" | "all-interfaces";
export type Family = "IPv4" | "IPv6";

export interface Bind {
	address: string;
	family: Family;
}

/** Everything listening on one port. The kernel, not the probe, picks which process answers. */
export interface Listener {
	port: number;
	pids: number[];
	processes: string[];
	binds: Bind[];
	exposure: Exposure;
}

export const LSOF_ARGS = ["+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpctn"];

const WILDCARDS = new Set(["*", "0.0.0.0", "::"]);

function isWildcard(address: string): boolean {
	return WILDCARDS.has(address);
}

export function isLoopbackAddress(address: string): boolean {
	const lower = address.toLowerCase();
	return (
		lower === "::1" ||
		lower.startsWith("127.") ||
		lower.startsWith("::ffff:127.")
	);
}

function decodeCommand(raw: string): string {
	return raw.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) => {
		const code = Number.parseInt(hex, 16);
		return code < 0x20 || code >= 0x7f ? "?" : String.fromCharCode(code);
	});
}

function parseEndpoint(name: string): { address: string; port: number } | null {
	const separator = name.lastIndexOf(":");
	if (separator <= 0) return null;
	const port = Number(name.slice(separator + 1));
	if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
	const address = name.slice(0, separator).replace(/^\[|\]$/g, "");
	return { address, port };
}

export function exposureOf(binds: Bind[]): Exposure {
	if (binds.some((bind) => isWildcard(bind.address))) return "all-interfaces";
	if (binds.some((bind) => !isLoopbackAddress(bind.address)))
		return "interface-specific";
	return "loopback";
}

function addUnique<T>(items: T[], item: T): void {
	if (!items.includes(item)) items.push(item);
}

/** Parses `lsof -F` output into one listener per port. */
export function parseLsofFields(output: string): Listener[] {
	const byPort = new Map<number, Listener>();
	let pid = 0;
	let command = "";
	let family: Family = "IPv4";

	for (const line of output.split("\n")) {
		const value = line.slice(1);
		switch (line[0]) {
			case "p":
				pid = Number(value);
				command = "";
				break;
			case "c":
				command = decodeCommand(value);
				break;
			case "t":
				family = value === "IPv6" ? "IPv6" : "IPv4";
				break;
			case "n": {
				if (value.includes("->")) break;
				const endpoint = parseEndpoint(value);
				if (endpoint === null) break;
				const listener: Listener = byPort.get(endpoint.port) ?? {
					port: endpoint.port,
					pids: [],
					processes: [],
					binds: [],
					exposure: "loopback",
				};
				addUnique(listener.pids, pid);
				addUnique(listener.processes, command);
				const isDuplicate = listener.binds.some(
					(bind) => bind.address === endpoint.address && bind.family === family,
				);
				if (!isDuplicate)
					listener.binds.push({ address: endpoint.address, family });
				listener.exposure = exposureOf(listener.binds);
				byPort.set(endpoint.port, listener);
				break;
			}
			default:
				break;
		}
	}

	return [...byPort.values()].sort((a, b) => a.port - b.port);
}

/** Picks the address to connect to, preferring loopback so that probes stay on this machine. */
export function probeAddress(listener: Listener): string | null {
	const wildcards = listener.binds.filter((bind) => isWildcard(bind.address));
	if (wildcards.some((bind) => bind.family === "IPv4")) return "127.0.0.1";
	if (wildcards.length > 0) return "::1";
	const loopback = listener.binds.find((bind) =>
		isLoopbackAddress(bind.address),
	);
	return (loopback ?? listener.binds[0])?.address ?? null;
}

export function isOwnAddress(
	address: string,
	ownAddresses: readonly string[],
): boolean {
	return isLoopbackAddress(address) || ownAddresses.includes(address);
}
