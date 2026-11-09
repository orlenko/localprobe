import { randomBytes } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import {
	HOSTILE_HOST,
	HOSTILE_ORIGIN,
	type HttpObservation,
	type PathObservations,
	type WebSocketObservation,
} from "./classify.ts";

const BANNER_WAIT_MS = 1000;
const REQUEST_TIMEOUT_MS = 2000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;

const USER_AGENT = "localprobe";

const KEPT_HEADERS = [
	"access-control-allow-credentials",
	"access-control-allow-headers",
	"access-control-allow-methods",
	"access-control-allow-origin",
	"content-type",
	"location",
	"www-authenticate",
];

const CROSS_SITE_FETCH_HEADERS = {
	"Sec-Fetch-Site": "cross-site",
	"Sec-Fetch-Mode": "cors",
	"Sec-Fetch-Dest": "empty",
};

export interface Target {
	address: string;
	port: number;
	tls: boolean;
}

export type BannerResult =
	| { kind: "banner"; text: string }
	| { kind: "silent" }
	| { kind: "unreachable" };

function validHost(target: Target): string {
	const address = target.address.includes(":")
		? `[${target.address}]`
		: target.address;
	return `${address}:${target.port}`;
}

/** Connects and listens without writing anything. */
export function readBanner(
	address: string,
	port: number,
): Promise<BannerResult> {
	return new Promise((resolve) => {
		const socket = net.connect({ host: address, port });
		let connected = false;
		const finish = (result: BannerResult) => {
			clearTimeout(timer);
			socket.destroy();
			resolve(result);
		};
		const timer = setTimeout(
			() => finish(connected ? { kind: "silent" } : { kind: "unreachable" }),
			BANNER_WAIT_MS,
		);
		socket.once("connect", () => {
			connected = true;
		});
		socket.once("data", (data) =>
			finish({ kind: "banner", text: data.toString("latin1") }),
		);
		socket.once("error", () => finish({ kind: "unreachable" }));
		socket.once("close", () =>
			finish(connected ? { kind: "silent" } : { kind: "unreachable" }),
		);
	});
}

function keptHeaders(
	headers: http.IncomingHttpHeaders,
): Record<string, string> {
	const kept: Record<string, string> = {};
	for (const name of KEPT_HEADERS) {
		const value = headers[name];
		if (value !== undefined)
			kept[name] = Array.isArray(value) ? value.join(", ") : value;
	}
	return kept;
}

interface RequestSpec {
	method: "GET" | "OPTIONS" | "POST";
	path: string;
	headers: Record<string, string>;
}

function openRequest(target: Target, spec: RequestSpec): http.ClientRequest {
	const options = {
		host: target.address,
		port: target.port,
		method: spec.method,
		path: spec.path,
		agent: false,
		headers: { "User-Agent": USER_AGENT, Accept: "*/*", ...spec.headers },
	};
	// Local services commonly use self-signed certificates, and no credentials are sent.
	return target.tls
		? https.request({ ...options, rejectUnauthorized: false })
		: http.request(options);
}

function send(
	target: Target,
	spec: RequestSpec,
): Promise<HttpObservation | null> {
	return new Promise((resolve) => {
		const request = openRequest(target, spec);
		let observation: HttpObservation | null = null;
		let settled = false;
		const finish = () => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			request.destroy();
			resolve(observation);
		};
		const timer = setTimeout(() => {
			if (observation !== null) observation.truncated = true;
			finish();
		}, REQUEST_TIMEOUT_MS);
		request.on("response", (response) => {
			const current: HttpObservation = {
				status: response.statusCode ?? 0,
				headers: keptHeaders(response.headers),
				bodyBytes: 0,
				truncated: false,
			};
			observation = current;
			response.on("data", (chunk: Buffer) => {
				current.bodyBytes += chunk.length;
				if (current.bodyBytes > MAX_BODY_BYTES) {
					current.truncated = true;
					finish();
				}
			});
			response.on("end", finish);
			response.on("error", finish);
			response.on("close", finish);
		});
		request.on("upgrade", (_response, socket) => {
			socket.destroy();
			finish();
		});
		request.on("error", finish);
		request.end();
	});
}

function getOpen(
	target: Target,
	path: string,
): Promise<HttpObservation | null> {
	return send(target, {
		method: "GET",
		path,
		headers: { Host: validHost(target) },
	});
}

/** Learns whether the listener speaks HTTP. A plain 400 may be a TLS port objecting, so TLS is tried then too. */
export async function detectHttp(
	address: string,
	port: number,
): Promise<{ target: Target; root: HttpObservation } | null> {
	const plainTarget: Target = { address, port, tls: false };
	const plain = await getOpen(plainTarget, "/");
	if (plain !== null && plain.status !== 400)
		return { target: plainTarget, root: plain };

	const tlsTarget: Target = { address, port, tls: true };
	const secure = await getOpen(tlsTarget, "/");
	if (secure !== null) return { target: tlsTarget, root: secure };

	return plain === null ? null : { target: plainTarget, root: plain };
}

export async function observePath(
	target: Target,
	path: string,
	knownOpen?: HttpObservation,
): Promise<PathObservations> {
	const host = validHost(target);
	const open = knownOpen ?? (await getOpen(target, path));
	const preflight = await send(target, {
		method: "OPTIONS",
		path,
		headers: {
			Host: host,
			Origin: HOSTILE_ORIGIN,
			"Access-Control-Request-Method": "PUT",
			"Access-Control-Request-Headers": "content-type",
			...CROSS_SITE_FETCH_HEADERS,
		},
	});
	if (open === null || open.status === 404) {
		return { path, open, origin: null, preflight, rebind: null };
	}
	const origin = await send(target, {
		method: "GET",
		path,
		headers: {
			Host: host,
			Origin: HOSTILE_ORIGIN,
			...CROSS_SITE_FETCH_HEADERS,
		},
	});
	const rebind = await send(target, {
		method: "GET",
		path,
		headers: { Host: HOSTILE_HOST },
	});
	return { path, open, origin, preflight, rebind };
}

/** Opens a socket with a hostile origin and closes it without sending a frame. */
export function probeWebSocket(
	target: Target,
	path: string,
): Promise<WebSocketObservation> {
	return new Promise((resolve) => {
		const request = openRequest(target, {
			method: "GET",
			path,
			headers: {
				Host: validHost(target),
				Origin: HOSTILE_ORIGIN,
				Connection: "Upgrade",
				Upgrade: "websocket",
				"Sec-WebSocket-Version": "13",
				"Sec-WebSocket-Key": randomBytes(16).toString("base64"),
			},
		});
		let settled = false;
		const finish = (status: number | null) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			request.destroy();
			resolve({ path, status });
		};
		const timer = setTimeout(() => finish(null), REQUEST_TIMEOUT_MS);
		request.on("upgrade", (response, socket) => {
			socket.destroy();
			finish(response.statusCode ?? null);
		});
		request.on("response", (response) => {
			response.resume();
			finish(response.statusCode ?? null);
		});
		request.on("error", () => finish(null));
		request.end();
	});
}

export async function probePost(
	target: Target,
	path: string,
): Promise<number | null> {
	const observation = await send(target, {
		method: "POST",
		path,
		headers: {
			Host: validHost(target),
			Origin: HOSTILE_ORIGIN,
			"Content-Type": "text/plain",
			"Content-Length": "0",
			...CROSS_SITE_FETCH_HEADERS,
		},
	});
	return observation?.status ?? null;
}
