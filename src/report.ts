import type { GuardResult, PathAssessment, VerdictKind } from "./classify.ts";
import type { Listener } from "./listeners.ts";
import { type PortOverrides, type SkipReason, skipReason } from "./policy.ts";
import type { ServiceResult } from "./scan.ts";

const VERDICT_LABELS: Record<VerdictKind, string> = {
	readable: "Readable by any website",
	"cross-origin-writes": "Cross-origin writes allowed",
	"socket-open": "Socket open to any website",
	rebindable: "Rebindable",
	"open-network": "Open to the network",
	"byte-delivery": "Browser can deliver bytes",
};

const SKIP_LABELS: Record<SkipReason | "not-own-address", string> = {
	excluded: "excluded by you",
	tunnel: "tunnel or forward, may reach another machine",
	"line-protocol": "line-protocol service, HTTP would be misread",
	"not-own-address": "address not recognised as this machine",
};

const INCOMPLETE_LABEL = "Incomplete";

export interface ReportContext {
	sawAllUsers: boolean;
	webSocketsTested: boolean;
}

function processNames(listener: Listener): string {
	return listener.processes.join(",");
}

function kindLabel(result: ServiceResult): string {
	switch (result.kind) {
		case "http":
			return result.tls ? "https" : "http";
		case "non-http":
			return result.protocol;
		case "not-probed":
			return "not probed";
		case "unreachable":
			return "unreachable";
	}
}

function presentPaths(result: ServiceResult): PathAssessment[] {
	return result.kind === "http"
		? result.paths.filter((path) => path.present)
		: [];
}

function incompletePaths(result: ServiceResult): PathAssessment[] {
	return result.kind === "http"
		? result.paths.filter((path) => !path.complete)
		: [];
}

function findingsLabel(result: ServiceResult): string {
	const labels = [
		...new Set(result.verdicts.map((verdict) => VERDICT_LABELS[verdict.kind])),
	];
	if (
		(result.kind === "http" || result.kind === "non-http") &&
		result.incomplete
	) {
		labels.push(INCOMPLETE_LABEL);
	}
	if (labels.length > 0) return labels.join("; ");
	if (result.kind === "not-probed") return SKIP_LABELS[result.reason];
	if (result.kind === "http") {
		const tested = presentPaths(result)
			.map((path) => path.path)
			.join(", ");
		return `No exposure found on tested paths: ${tested}`;
	}
	return "-";
}

function table(rows: string[][]): string[] {
	const widths: number[] = [];
	for (const row of rows) {
		row.forEach((cell, index) => {
			widths[index] = Math.max(widths[index] ?? 0, cell.length);
		});
	}
	return rows.map((row) =>
		row
			.map((cell, index) => cell.padEnd(widths[index] ?? 0))
			.join("  ")
			.trimEnd(),
	);
}

function guardLabel(result: GuardResult, status: number | null): string {
	return status === null ? result : `${result} (${status})`;
}

function pathLine(path: PathAssessment): string {
	const over = path.openTruncated ? " or more" : "";
	const size = path.openBytes === null ? "" : ` ${path.openBytes}${over} bytes`;
	const type = path.contentType === null ? "" : ` ${path.contentType}`;
	return [
		`${path.path}: open ${path.openStatus}${size}${type}`,
		`origin ${guardLabel(path.originGuard, path.originStatus)}`,
		`cors ${path.corsReadable ? "yes" : "no"}`,
		`preflight ${path.preflightAllowsWrite ? "yes" : "no"}`,
		`host ${guardLabel(path.hostGuard, path.hostStatus)}`,
	].join(" | ");
}

function details(result: ServiceResult): string[] {
	const lines: string[] = [];
	for (const verdict of result.verdicts) {
		lines.push(`    ${VERDICT_LABELS[verdict.kind]}: ${verdict.evidence}`);
	}
	if (result.kind === "http") {
		if (presentPaths(result).length === 0) {
			lines.push(
				`    ${INCOMPLETE_LABEL}: no tested path exists on this service`,
			);
		}
		for (const path of incompletePaths(result)) {
			lines.push(
				`    ${INCOMPLETE_LABEL}: ${path.path} had a check with no conclusive response`,
			);
		}
		for (const path of presentPaths(result))
			lines.push(`    ${pathLine(path)}`);
		for (const socket of result.webSockets ?? []) {
			lines.push(
				`    WebSocket ${socket.path}: ${socket.status ?? "no response"}`,
			);
		}
		for (const post of result.posts) {
			lines.push(
				`    Cross-site POST ${post.path}: ${post.status ?? "no response"}`,
			);
		}
	}
	return lines.length > 0
		? [`  ${result.listener.port} ${processNames(result.listener)}`, ...lines]
		: [];
}

export function reportLimits(context: ReportContext): string[] {
	const lines = [
		"Origin results apply only to requests that carry Origin. A no-cors GET carries none.",
		"Probes carry no cookies, so this cannot show what a logged-in session would add.",
		"These results describe the services. Browser policy is measured separately.",
	];
	if (!context.sawAllUsers) {
		lines.unshift(
			"Only your own user's sockets are listed. Run with sudo to see the rest.",
		);
	}
	if (!context.webSocketsTested) {
		lines.unshift(
			"WebSockets were tested only on paths you named. Add --ws to test / too.",
		);
	}
	return lines;
}

/** Shows what a scan would do without connecting to anything. */
export function renderPlan(
	listeners: readonly Listener[],
	overrides: PortOverrides,
): string {
	const rows = [
		["PORT", "PROCESS", "BIND", "PLAN"],
		...listeners.map((listener) => {
			const reason = skipReason(listener, overrides);
			return [
				String(listener.port),
				processNames(listener),
				listener.exposure,
				reason === null ? "probe" : `skip: ${SKIP_LABELS[reason]}`,
			];
		}),
	];
	return [
		...table(rows),
		"",
		"Nothing was sent. Use --exclude PORT to skip anything else.",
	].join("\n");
}

export function renderReport(
	results: readonly ServiceResult[],
	context: ReportContext,
): string {
	const rows = [
		["PORT", "PROCESS", "BIND", "KIND", "FINDINGS"],
		...results.map((result) => [
			String(result.listener.port),
			processNames(result.listener),
			result.listener.exposure,
			kindLabel(result),
			findingsLabel(result),
		]),
	];
	const detailLines = results.flatMap(details);
	return [
		...table(rows),
		...(detailLines.length > 0 ? ["", "Details", ...detailLines] : []),
		"",
		"Limits",
		...reportLimits(context).map((line) => `  ${line}`),
	].join("\n");
}
