import { createServer, type IncomingMessage, type Server } from "node:http";
import { connect, type Socket } from "node:net";
import {
	type Arrival,
	CANARY_CSP,
	CANARY_HTML,
	CANARY_MARKER,
	CLOSED_WITHOUT_REQUEST,
	CORS_HEADERS,
	closeFrame,
	formatArrival,
	formatUnparsed,
	isWebSocketKey,
	textFrame,
	webSocketAccept,
} from "./canary.ts";

const IPV4 = "127.0.0.1";
const IPV6 = "::1";
const HOSTS = [IPV4, IPV6] as const;
/** Large enough for a full set of localhost cookies, which every navigation here carries. */
const MAX_HEADER_BYTES = 64 * 1024;
const CONNECT_TIMEOUT_MS = 1000;

function displayHost(host: string): string {
	return host.includes(":") ? `[${host}]` : host;
}

/** Resolves true if something accepts a TCP connection. Sends no bytes. */
function accepts(host: string, port: number): Promise<boolean> {
	return new Promise((resolve) => {
		const socket = connect({ host, port });
		const finish = (result: boolean) => {
			socket.destroy();
			resolve(result);
		};
		socket.setTimeout(CONNECT_TIMEOUT_MS, () => finish(false));
		socket.once("connect", () => finish(true));
		socket.once("error", () => finish(false));
	});
}

/**
 * Hosts on which something already answers. A bind can succeed next to another
 * process's wildcard or specific-address socket, so binding alone proves nothing.
 */
export async function hostsInUse(port: number): Promise<string[]> {
	const answered = await Promise.all(HOSTS.map((host) => accepts(host, port)));
	return HOSTS.filter((_host, index) => answered[index]);
}

function arrivalOf(request: IncomingMessage): Arrival {
	return {
		time: new Date(),
		localAddress: request.socket.localAddress ?? "?",
		family: request.socket.localFamily ?? "?",
		method: request.method ?? "?",
		path: request.url ?? "?",
		headers: request.headers,
	};
}

function handleUpgrade(request: IncomingMessage, socket: Socket): void {
	socket.on("error", () => {});
	const key = request.headers["sec-websocket-key"];
	const isWebSocket =
		request.headers.upgrade?.toLowerCase() === "websocket" &&
		request.headers["sec-websocket-version"] === "13" &&
		isWebSocketKey(key);
	if (!isWebSocket) {
		socket.end(
			"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		);
		return;
	}
	socket.write(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			`Sec-WebSocket-Accept: ${webSocketAccept(key)}\r\n\r\n`,
	);
	socket.write(textFrame(CANARY_MARKER));
	socket.end(closeFrame());
	// Client frames are never read. Drop the socket if the client does not close it.
	socket.resume();
	setTimeout(() => socket.destroy(), 2000).unref();
}

interface ConnectionState {
	opened: Date;
	/** Read at accept time, because a closed socket no longer reports it. */
	localAddress: string;
	family: string;
	/** True once any line names this connection. */
	logged: boolean;
}

function createCanaryServer(log: (line: string) => void): Server {
	const connections = new WeakMap<Socket, ConnectionState>();
	const markLogged = (socket: Socket) => {
		const state = connections.get(socket);
		if (state) state.logged = true;
	};
	const logUnparsed = (socket: Socket, reason: string) => {
		const state = connections.get(socket);
		log(
			formatUnparsed({
				time: new Date(),
				opened: state?.opened ?? new Date(),
				localAddress: state?.localAddress ?? socket.localAddress ?? "?",
				family: state?.family ?? socket.localFamily ?? "?",
				reason,
			}),
		);
		markLogged(socket);
	};

	const server = createServer(
		{ maxHeaderSize: MAX_HEADER_BYTES },
		(request, response) => {
			markLogged(request.socket);
			log(formatArrival(arrivalOf(request)));
			request.resume();
			if (request.method === "OPTIONS") {
				response.writeHead(204, CORS_HEADERS);
				response.end();
				return;
			}
			response.writeHead(200, {
				...CORS_HEADERS,
				"Content-Type": "text/html; charset=utf-8",
				"Content-Security-Policy": CANARY_CSP,
				"X-Content-Type-Options": "nosniff",
			});
			response.end(request.method === "HEAD" ? undefined : CANARY_HTML);
		},
	);
	// Every TCP connection gets at least one line, so a missing line means nothing connected.
	server.on("connection", (socket: Socket) => {
		connections.set(socket, {
			opened: new Date(),
			localAddress: socket.localAddress ?? "?",
			family: socket.localFamily ?? "?",
			logged: false,
		});
		socket.once("close", () => {
			if (connections.get(socket)?.logged === false)
				logUnparsed(socket, CLOSED_WITHOUT_REQUEST);
		});
	});
	server.on("upgrade", (request: IncomingMessage, socket: Socket) => {
		markLogged(socket);
		log(formatArrival(arrivalOf(request)));
		handleUpgrade(request, socket);
	});
	server.on("clientError", (error: NodeJS.ErrnoException, socket: Socket) => {
		logUnparsed(socket, error.code ?? error.message);
		socket.destroy();
	});
	server.on("connect", (request: IncomingMessage, socket: Socket) => {
		markLogged(socket);
		log(formatArrival(arrivalOf(request)));
		socket.on("error", () => {});
		socket.end(
			"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		);
	});
	return server;
}

function listen(server: Server, host: string, port: number): Promise<void> {
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen({ host, port, exclusive: true }, () => {
			server.off("error", reject);
			resolve();
		});
	});
}

function closeAll(servers: readonly Server[]): void {
	for (const server of servers) {
		server.close();
		server.closeAllConnections();
	}
}

export interface CanaryOptions {
	port: number;
	minutes: number;
	log: (line: string) => void;
}

/** Runs until the time is up or a signal arrives, then closes the listeners. */
export async function runCanary(options: CanaryOptions): Promise<void> {
	const { port, minutes, log } = options;
	const busy = await hostsInUse(port);
	if (busy.length > 0) {
		throw new Error(
			`Something already answers on ${busy.map((host) => `${displayHost(host)}:${port}`).join(" and ")}. Stop it and rerun, so no request reaches a real service.`,
		);
	}

	const servers: Server[] = [];
	const bound: string[] = [];
	try {
		const server = createCanaryServer(log);
		servers.push(server);
		await listen(server, IPV4, port);
		bound.push(IPV4);
	} catch (error) {
		closeAll(servers);
		throw error;
	}
	// IPv6 is optional, so a host without it can still measure the other rows.
	const server6 = createCanaryServer(log);
	try {
		await listen(server6, IPV6, port);
		servers.push(server6);
		bound.push(IPV6);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		// Anything else, such as EADDRINUSE, means another process may own [::1] and would get the page's requests.
		if (code !== "EADDRNOTAVAIL" && code !== "EAFNOSUPPORT") {
			closeAll(servers);
			throw error;
		}
		log(
			`canary: no IPv6 loopback here (${code}). The [::1] rows will fail, and localhost may resolve to 127.0.0.1 only.`,
		);
	}

	const end = new Date(Date.now() + minutes * 60_000);
	log(
		`localprobe canary on ${bound.map((host) => `${displayHost(host)}:${port}`).join(" and ")} until ${end.toISOString()} (${minutes} min). It holds no data and logs to stdout only. Cookie and Authorization values are never printed.`,
	);

	await new Promise<void>((resolve) => {
		let left = minutes;
		const tick = setInterval(() => {
			left -= 1;
			if (left > 0) log(`canary: ${left} min left`);
		}, 60_000);
		const stop = (reason: string) => {
			clearInterval(tick);
			clearTimeout(timer);
			process.off("SIGINT", onSignal);
			process.off("SIGTERM", onSignal);
			closeAll(servers);
			log(`canary: stopped, ${reason}`);
			resolve();
		};
		const onSignal = (signal: NodeJS.Signals) => stop(`${signal} received`);
		const timer = setTimeout(
			() => stop(`${minutes} min are up`),
			minutes * 60_000,
		);
		process.once("SIGINT", onSignal);
		process.once("SIGTERM", onSignal);
	});
}
