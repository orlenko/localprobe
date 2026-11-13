import { createHash } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";

/** Fixed so the public page needs no URL input. Off the Fetch bad-port list and below macOS's ephemeral range. */
export const CANARY_PORT = 47823;
export const DEFAULT_MINUTES = 10;
export const MAX_MINUTES = 60;
export const CANARY_MARKER = "localprobe canary";

const FIELD_LIMIT = 200;

/**
 * The canary page's only script. It reads the path into strings and posts them back,
 * so the page can tell an iframe or popup that ran from one that only fired `onload`.
 * Nothing from the request reaches the HTML.
 */
const SCRIPT =
	'(function(){var p=location.pathname.split("/");' +
	'var m={canary:"localprobe",run:String(p[2]||"").slice(0,32),test:String(p[3]||"").slice(0,32)};' +
	"var t=window.opener||(window.parent!==window?window.parent:null);" +
	'if(t){try{t.postMessage(m,"*")}catch(e){}}})();';

export const CANARY_HTML = `<!doctype html><meta charset="utf-8"><title>${CANARY_MARKER}</title><p>${CANARY_MARKER}. This page holds no data.</p><script>${SCRIPT}</script>\n`;

export const CANARY_CSP = `default-src 'none'; script-src 'sha256-${createHash("sha256").update(SCRIPT).digest("base64")}'; base-uri 'none'; form-action 'none'`;

/** Allows any origin to read, never with credentials, so the canary measures the browser and not a permissive server. */
export const CORS_HEADERS: Readonly<Record<string, string>> = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "content-type",
	"Access-Control-Max-Age": "0",
	"Cache-Control": "no-store",
};

export function parseMinutes(value: string): number {
	const minutes = /^\d+$/.test(value) ? Number(value) : Number.NaN;
	if (!Number.isInteger(minutes) || minutes < 1 || minutes > MAX_MINUTES) {
		throw new Error(`Minutes must be 1 to ${MAX_MINUTES}: ${value}`);
	}
	return minutes;
}

/** RFC 6455 accept value for a client key. */
export function webSocketAccept(key: string): string {
	return createHash("sha1")
		.update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
		.digest("base64");
}

/** A client key is 16 random bytes, base64-encoded. */
export function isWebSocketKey(key: string | undefined): key is string {
	return (
		key !== undefined &&
		/^[A-Za-z0-9+/]{22}==$/.test(key) &&
		Buffer.from(key, "base64").length === 16
	);
}

/** One unmasked server frame with a payload under 126 bytes. */
function smallFrame(opcode: number, payload: Buffer): Buffer {
	if (payload.length > 125) throw new Error("Frame payload too long");
	return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

export function textFrame(text: string): Buffer {
	return smallFrame(0x1, Buffer.from(text, "utf8"));
}

/** Close frame with status 1000 (normal). */
export function closeFrame(): Buffer {
	return smallFrame(0x8, Buffer.from([0x03, 0xe8]));
}

/**
 * Makes a request field safe to print. Everything outside printable ASCII is escaped
 * (control characters could rewrite the terminal), and a value with a space or quote is
 * quoted. A value over the cap is cut, always quoted, and followed by `+N` outside the
 * quotes. An escaped value never contains a bare quote, so that marker cannot be forged.
 */
export function escapeField(value: string): string {
	const cut = value.length > FIELD_LIMIT;
	let escaped = "";
	for (const char of cut ? value.slice(0, FIELD_LIMIT) : value) {
		const code = char.codePointAt(0) ?? 0;
		if (char === "\\") escaped += "\\\\";
		else if (char === '"') escaped += '\\"';
		else if (code >= 0x20 && code <= 0x7e) escaped += char;
		else escaped += `\\u{${code.toString(16)}}`;
	}
	if (cut) return `"${escaped}"+${value.length - FIELD_LIMIT}`;
	return /[ "]/.test(escaped) || escaped === "" ? `"${escaped}"` : escaped;
}

export interface Arrival {
	time: Date;
	localAddress: string;
	family: string;
	method: string;
	path: string;
	headers: IncomingHttpHeaders;
}

const LOGGED_HEADERS = [
	"host",
	"origin",
	"referer",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"access-control-request-method",
	"access-control-request-headers",
	"access-control-request-private-network",
	"access-control-request-local-network",
	"upgrade",
] as const;

function headerText(value: string | string[] | undefined): string | undefined {
	return Array.isArray(value) ? value.join(", ") : value;
}

function cookieCount(header: string | undefined): number {
	if (header === undefined) return 0;
	return header.split(";").filter((part) => part.trim() !== "").length;
}

/**
 * One log line per arrival. Cookie and Authorization values are never printed,
 * because other localhost services' cookies can arrive here.
 */
export function formatArrival(arrival: Arrival): string {
	const parts = [
		arrival.time.toISOString(),
		`local=${escapeField(arrival.localAddress)}/${escapeField(arrival.family)}`,
		escapeField(arrival.method),
		escapeField(arrival.path),
	];
	for (const name of LOGGED_HEADERS) {
		const value = headerText(arrival.headers[name]);
		if (value !== undefined) parts.push(`${name}=${escapeField(value)}`);
	}
	const cookies = cookieCount(headerText(arrival.headers.cookie));
	parts.push(cookies > 0 ? `cookie=present(${cookies})` : "cookie=absent");
	parts.push(
		arrival.headers.authorization === undefined
			? "authorization=absent"
			: "authorization=present",
	);
	return parts.join(" ");
}

export interface Unparsed {
	time: Date;
	localAddress: string;
	family: string;
	reason: string;
}

/** A connection whose request Node could not parse. It still gets a line, so absence stays meaningful. */
export function formatUnparsed(unparsed: Unparsed): string {
	return [
		unparsed.time.toISOString(),
		`local=${escapeField(unparsed.localAddress)}/${escapeField(unparsed.family)}`,
		"UNPARSED",
		`reason=${escapeField(unparsed.reason)}`,
	].join(" ");
}
