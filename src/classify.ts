import type { Exposure } from "./listeners.ts";

export const HOSTILE_ORIGIN = "https://evil.example";
export const HOSTILE_HOST = "evil.example";

export type BannerProtocol =
	| "smtp"
	| "imap"
	| "pop3"
	| "ftp"
	| "ssh"
	| "unknown";

export interface HttpObservation {
	status: number;
	headers: Record<string, string>;
	bodyBytes: number;
	truncated: boolean;
}

/** `null` means the server gave no HTTP response, or the request was not sent. */
export interface PathObservations {
	path: string;
	open: HttpObservation | null;
	origin: HttpObservation | null;
	preflight: HttpObservation | null;
	rebind: HttpObservation | null;
}

export type GuardResult = "rejected" | "served" | "other" | "no-response";

export interface PathAssessment {
	path: string;
	present: boolean;
	complete: boolean;
	openStatus: number | null;
	openBytes: number | null;
	openTruncated: boolean;
	contentType: string | null;
	asksForCredentials: boolean;
	originGuard: GuardResult;
	originStatus: number | null;
	corsReadable: boolean;
	corsCredentials: boolean;
	preflightAllowsWrite: boolean;
	hostGuard: GuardResult;
	hostStatus: number | null;
}

export interface WebSocketObservation {
	path: string;
	status: number | null;
}

export type VerdictKind =
	| "readable"
	| "cross-origin-writes"
	| "socket-open"
	| "rebindable"
	| "open-network"
	| "byte-delivery";

export interface Verdict {
	kind: VerdictKind;
	evidence: string;
}

export function classifyBanner(banner: string): BannerProtocol {
	if (banner.startsWith("SSH-")) return "ssh";
	if (banner.startsWith("* OK") || banner.startsWith("* PREAUTH"))
		return "imap";
	if (banner.startsWith("+OK")) return "pop3";
	if (/^220[ -].*ftp/i.test(banner)) return "ftp";
	if (/^220[ -]/.test(banner)) return "smtp";
	return "unknown";
}

const REJECTING_STATUSES = new Set([400, 401, 403, 404, 421]);

function isSuccess(status: number): boolean {
	return status >= 200 && status < 300;
}

function isRedirect(status: number): boolean {
	return status >= 300 && status < 400;
}

function guardResult(observation: HttpObservation | null): GuardResult {
	if (observation === null) return "no-response";
	if (isSuccess(observation.status)) return "served";
	if (REJECTING_STATUSES.has(observation.status)) return "rejected";
	return "other";
}

function allowsHostileOrigin(observation: HttpObservation): boolean {
	const allowed = observation.headers["access-control-allow-origin"];
	return allowed === "*" || allowed === HOSTILE_ORIGIN;
}

function listIncludes(value: string | undefined, wanted: string): boolean {
	if (value === undefined) return false;
	const items = value.split(",").map((item) => item.trim().toLowerCase());
	return items.includes(wanted) || items.includes("*");
}

function isConclusiveBaseline(path: string, status: number): boolean {
	if (isSuccess(status) || status === 401 || status === 403 || status === 404) {
		return true;
	}
	// A 400 on / can mean the probe spoke the wrong protocol.
	return status === 400 && path !== "/";
}

function isConclusiveGuard(observation: HttpObservation | null): boolean {
	const result = guardResult(observation);
	return result === "served" || result === "rejected";
}

function isUnavailable(status: number): boolean {
	if (status === 408 || status === 429) return true;
	// 501 is how simple servers refuse a method they don't implement.
	return status >= 500 && status !== 501;
}

function isConclusivePreflight(status: number): boolean {
	return !isRedirect(status) && !isUnavailable(status);
}

function isComplete(observations: PathObservations): boolean {
	const { path, open, origin, preflight, rebind } = observations;
	if (open === null || preflight === null) return false;
	if (!isConclusivePreflight(preflight.status)) return false;
	if (!isConclusiveBaseline(path, open.status)) return false;
	return (
		open.status === 404 ||
		(isConclusiveGuard(origin) && isConclusiveGuard(rebind))
	);
}

export function isServiceIncomplete(
	paths: readonly PathAssessment[],
	webSockets: readonly WebSocketObservation[] | null,
): boolean {
	return (
		paths.some((path) => !path.complete) ||
		!paths.some((path) => path.present) ||
		(webSockets ?? []).some(
			(socket) => socket.status === null || isUnavailable(socket.status),
		)
	);
}

export function assessPath(observations: PathObservations): PathAssessment {
	const { path, open, origin, preflight, rebind } = observations;
	const corsReadable =
		origin !== null &&
		!isRedirect(origin.status) &&
		allowsHostileOrigin(origin);
	const preflightAllowsWrite =
		preflight !== null &&
		isSuccess(preflight.status) &&
		allowsHostileOrigin(preflight) &&
		listIncludes(preflight.headers["access-control-allow-methods"], "put") &&
		listIncludes(
			preflight.headers["access-control-allow-headers"],
			"content-type",
		);

	return {
		path,
		present: open !== null && open.status !== 404,
		complete: isComplete(observations),
		openStatus: open?.status ?? null,
		openBytes: open?.bodyBytes ?? null,
		openTruncated: open?.truncated ?? false,
		contentType:
			open?.headers["content-type"]
				?.split(";")[0]
				?.trim()
				.replace(/[^ -~]/g, "?") ?? null,
		asksForCredentials: open?.headers["www-authenticate"] !== undefined,
		originGuard: guardResult(origin),
		originStatus: origin?.status ?? null,
		corsReadable,
		corsCredentials:
			corsReadable &&
			origin?.headers["access-control-allow-origin"] === HOSTILE_ORIGIN &&
			origin.headers["access-control-allow-credentials"] === "true",
		preflightAllowsWrite,
		hostGuard: guardResult(rebind),
		hostStatus: rebind?.status ?? null,
	};
}

export function httpVerdicts(
	exposure: Exposure,
	paths: readonly PathAssessment[],
	webSockets: readonly WebSocketObservation[],
): Verdict[] {
	const verdicts: Verdict[] = [];

	for (const path of paths) {
		if (path.preflightAllowsWrite) {
			verdicts.push({
				kind: "cross-origin-writes",
				evidence: `OPTIONS ${path.path} allows PUT with a JSON content type from ${HOSTILE_ORIGIN}`,
			});
		}
		if (!path.present) continue;
		if (path.corsReadable) {
			const credentials = path.corsCredentials ? " and allows credentials" : "";
			verdicts.push({
				kind: "readable",
				evidence: `GET ${path.path} returned ${path.originStatus} with a CORS header that allows ${HOSTILE_ORIGIN}${credentials}`,
			});
		}
		if (path.hostGuard === "served") {
			verdicts.push({
				kind: "rebindable",
				evidence: `GET ${path.path} returned ${path.hostStatus} with Host: ${HOSTILE_HOST}`,
			});
		}
	}

	for (const socket of webSockets) {
		if (socket.status === 101) {
			verdicts.push({
				kind: "socket-open",
				evidence: `WebSocket upgrade on ${socket.path} returned 101 with Origin: ${HOSTILE_ORIGIN}`,
			});
		}
	}

	const openPaths = paths.filter(
		(path) =>
			path.present &&
			path.openStatus !== null &&
			isSuccess(path.openStatus) &&
			!path.asksForCredentials,
	);
	if (exposure !== "loopback" && openPaths.length > 0) {
		const names = openPaths.map((path) => path.path).join(", ");
		verdicts.push({
			kind: "open-network",
			evidence: `Bound to ${exposure} and GET ${names} succeeded with no credentials`,
		});
	}

	return verdicts;
}
