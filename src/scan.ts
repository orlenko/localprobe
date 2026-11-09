import { execFile } from "node:child_process";
import os from "node:os";
import { type PortPath, pathsForPort } from "./args.ts";
import {
	assessPath,
	type BannerProtocol,
	classifyBanner,
	httpVerdicts,
	isServiceIncomplete,
	type PathAssessment,
	type Verdict,
	type WebSocketObservation,
} from "./classify.ts";
import {
	isOwnAddress,
	type Listener,
	LSOF_ARGS,
	parseLsofFields,
	probeAddress,
} from "./listeners.ts";
import { browserCanConnect, type SkipReason, skipReason } from "./policy.ts";
import {
	detectHttp,
	observePath,
	probePost,
	probeWebSocket,
	readBanner,
} from "./probe.ts";

const FIXED_PATHS = ["/", "/api", "/health", "/metrics", "/openapi.json"];

export interface ScanOptions {
	include: ReadonlySet<number>;
	exclude: ReadonlySet<number>;
	paths: readonly PortPath[];
	webSockets: boolean;
	webSocketPaths: readonly PortPath[];
	postPaths: readonly PortPath[];
}

export interface PostObservation {
	path: string;
	status: number | null;
}

export type ServiceResult = { listener: Listener } & (
	| {
			kind: "not-probed";
			reason: SkipReason | "not-own-address";
			verdicts: Verdict[];
	  }
	| { kind: "unreachable"; verdicts: Verdict[] }
	| {
			kind: "non-http";
			protocol: BannerProtocol | "no-response";
			incomplete: boolean;
			verdicts: Verdict[];
	  }
	| {
			kind: "http";
			tls: boolean;
			paths: PathAssessment[];
			webSockets: WebSocketObservation[] | null;
			posts: PostObservation[];
			incomplete: boolean;
			verdicts: Verdict[];
	  }
);

export function listListeners(): Promise<Listener[]> {
	return new Promise((resolve, reject) => {
		execFile(
			"lsof",
			LSOF_ARGS,
			{ maxBuffer: 8 * 1024 * 1024 },
			(error, stdout, stderr) => {
				// lsof exits with 1 when nothing matches, and also on real errors.
				const isEmptyResult =
					error?.code === 1 &&
					(stdout.length > 0 || stderr.trim().length === 0);
				if (error === null || isEmptyResult) resolve(parseLsofFields(stdout));
				else
					reject(new Error(`lsof failed: ${stderr.trim() || error.message}`));
			},
		);
	});
}

function ownAddresses(): string[] {
	return Object.values(os.networkInterfaces())
		.flatMap((addresses) => addresses ?? [])
		.map((entry) => entry.address);
}

function byteDeliveryVerdicts(port: number, description: string): Verdict[] {
	if (!browserCanConnect(port)) return [];
	return [
		{
			kind: "byte-delivery",
			evidence: `${description} on a port browsers do not block`,
		},
	];
}

function uniquePaths(paths: readonly string[]): string[] {
	return [...new Set(paths)];
}

async function scanListener(
	listener: Listener,
	options: ScanOptions,
): Promise<ServiceResult> {
	const { port } = listener;
	const reason = skipReason(listener, options);
	if (reason !== null) {
		const verdicts =
			reason === "line-protocol"
				? byteDeliveryVerdicts(port, "Line-protocol service")
				: [];
		return { listener, kind: "not-probed", reason, verdicts };
	}

	const address = probeAddress(listener);
	if (address === null || !isOwnAddress(address, ownAddresses())) {
		return {
			listener,
			kind: "not-probed",
			reason: "not-own-address",
			verdicts: [],
		};
	}

	const banner = await readBanner(address, port);
	if (banner.kind === "unreachable")
		return { listener, kind: "unreachable", verdicts: [] };
	if (banner.kind === "banner") {
		const protocol = classifyBanner(banner.text);
		return {
			listener,
			kind: "non-http",
			protocol,
			incomplete: false,
			verdicts: byteDeliveryVerdicts(port, `Non-HTTP service (${protocol})`),
		};
	}

	const detected = await detectHttp(address, port);
	if (detected === null) {
		return {
			listener,
			kind: "non-http",
			protocol: "no-response",
			incomplete: true,
			verdicts: byteDeliveryVerdicts(port, "Service with no HTTP response"),
		};
	}

	const { target, root } = detected;
	const assessments: PathAssessment[] = [];
	for (const path of uniquePaths([
		...FIXED_PATHS,
		...pathsForPort(port, options.paths),
	])) {
		const observations = await observePath(
			target,
			path,
			path === "/" ? root : undefined,
		);
		assessments.push(assessPath(observations));
	}

	const socketPaths = uniquePaths([
		...(options.webSockets ? ["/"] : []),
		...pathsForPort(port, options.webSocketPaths),
	]);
	let webSockets: WebSocketObservation[] | null = null;
	if (socketPaths.length > 0) {
		webSockets = [];
		for (const path of socketPaths)
			webSockets.push(await probeWebSocket(target, path));
	}

	const posts: PostObservation[] = [];
	for (const path of uniquePaths(pathsForPort(port, options.postPaths))) {
		posts.push({ path, status: await probePost(target, path) });
	}

	return {
		listener,
		kind: "http",
		tls: target.tls,
		paths: assessments,
		webSockets,
		posts,
		incomplete: isServiceIncomplete(assessments, webSockets),
		verdicts: httpVerdicts(listener.exposure, assessments, webSockets ?? []),
	};
}

export async function scanListeners(
	listeners: readonly Listener[],
	options: ScanOptions,
): Promise<ServiceResult[]> {
	const results: ServiceResult[] = [];
	for (const listener of listeners)
		results.push(await scanListener(listener, options));
	return results;
}
