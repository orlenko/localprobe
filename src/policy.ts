import type { Listener } from "./listeners.ts";

export type SkipReason = "excluded" | "tunnel" | "line-protocol";

export interface PortOverrides {
	include: ReadonlySet<number>;
	exclude: ReadonlySet<number>;
}

/** Processes that may carry a probe to another machine. */
const TUNNEL_PROCESSES = new Set([
	"autossh",
	"aws",
	"boundary",
	"chisel",
	"cloud-sql-proxy",
	"cloud_sql_proxy",
	"cloudflared",
	"frpc",
	"gcloud",
	"gost",
	"kubectl",
	"ngrok",
	"oc",
	"rathole",
	"session-manager-plugin",
	"socat",
	"ssh",
	"sshd",
	"sshd-session",
	"sshuttle",
	"stunnel",
	"tailscale",
	"tailscaled",
	"teleport",
	"tsh",
	"wstunnel",
]);

/** Silent services that log or misparse an HTTP request written to them. */
const LINE_PROTOCOL_PROCESSES = new Set([
	"mariadbd",
	"memcached",
	"mongod",
	"mysqld",
	"nats-server",
	"postgres",
	"redis-server",
	"valkey-server",
]);

const LINE_PROTOCOL_PORTS = new Set([
	2181, 3306, 4222, 5432, 5672, 6379, 9042, 9092, 11211, 27017,
]);

/** The Fetch standard's bad-port list. Browsers refuse to connect to these. */
const BROWSER_BLOCKED_PORTS = new Set([
	0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77,
	79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135,
	137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531,
	532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720,
	1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668,
	6669, 6679, 6697, 10080,
]);

/** Some systems cut process names to 15 or 16 characters. */
const SHORTEST_CUT_NAME = 15;

function matchesProcess(names: ReadonlySet<string>, process: string): boolean {
	if (names.has(process)) return true;
	return (
		process.length >= SHORTEST_CUT_NAME &&
		[...names].some((name) => name.startsWith(process))
	);
}

export function skipReason(
	listener: Pick<Listener, "port" | "processes">,
	overrides: PortOverrides,
): SkipReason | null {
	if (overrides.exclude.has(listener.port)) return "excluded";
	if (overrides.include.has(listener.port)) return null;
	const processes = listener.processes.map((process) => process.toLowerCase());
	if (processes.some((process) => matchesProcess(TUNNEL_PROCESSES, process))) {
		return "tunnel";
	}
	if (
		processes.some((process) =>
			matchesProcess(LINE_PROTOCOL_PROCESSES, process),
		) ||
		LINE_PROTOCOL_PORTS.has(listener.port)
	) {
		return "line-protocol";
	}
	return null;
}

export function browserCanConnect(port: number): boolean {
	return !BROWSER_BLOCKED_PORTS.has(port);
}
