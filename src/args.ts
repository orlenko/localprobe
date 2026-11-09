export interface PortPath {
	port: number;
	path: string;
}

export function parsePort(value: string): number {
	const port = /^\d+$/.test(value) ? Number(value) : Number.NaN;
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		throw new Error(`Not a valid port: ${value}`);
	}
	return port;
}

/** Parses `PORT:/path`. The port is required so a path only ever goes to the service it names. */
export function parsePortPath(value: string): PortPath {
	const separator = value.indexOf(":");
	if (separator < 0) throw new Error(`Expected PORT:/path, got: ${value}`);
	const path = value.slice(separator + 1);
	if (!/^\/[!-~]*$/.test(path)) {
		throw new Error(`Path must start with / and contain no spaces: ${value}`);
	}
	return { port: parsePort(value.slice(0, separator)), path };
}

export function pathsForPort(
	port: number,
	entries: readonly PortPath[],
): string[] {
	return entries
		.filter((entry) => entry.port === port)
		.map((entry) => entry.path);
}
