#!/usr/bin/env node
import { open, rm } from "node:fs/promises";
import { parseArgs } from "node:util";
import { type PortPath, parsePort, parsePortPath } from "./args.ts";
import {
	CANARY_PORT,
	DEFAULT_MINUTES,
	MAX_MINUTES,
	parseMinutes,
} from "./canary.ts";
import { runCanary } from "./canaryServer.ts";
import { renderPlan, renderReport, reportLimits } from "./report.ts";
import { listListeners, type ScanOptions, scanListeners } from "./scan.ts";

const USAGE = `Usage: localprobe scan [options]
       localprobe canary [--minutes N]

Tests what a hostile web page could reach on this machine's local servers.

  --list                 Show what would be probed and send nothing. Run this first
  --path PORT:/path      Also test this GET path on one service (repeatable)
  --ws                   Test a WebSocket upgrade on / of every HTTP service
  --ws-path PORT:/path   Test a WebSocket upgrade on one service (repeatable)
  --post-path PORT:/path Send a cross-site POST to one service. You assert it is safe (repeatable)
  --include PORT         Probe this port even if it would be skipped (repeatable)
  --exclude PORT         Never touch this port (repeatable)
  --json                 Print JSON instead of a table
  --out FILE             Write JSON to a new FILE. Results describe your machine, so keep it private
  --help                 Show this help

localprobe canary listens on 127.0.0.1 and [::1] port ${CANARY_PORT} for the browser page,
logs each request it receives, holds no data, and exits after ${DEFAULT_MINUTES} minutes.

  --minutes N            Stop after N minutes, up to ${MAX_MINUTES}
`;

function warnAboutUnknownPorts(
	named: readonly number[],
	known: ReadonlySet<number>,
): void {
	for (const port of new Set(named)) {
		if (!known.has(port))
			process.stderr.write(
				`No listener found on port ${port}. Other users' sockets need sudo.\n`,
			);
	}
}

async function canaryMain(args: string[]): Promise<void> {
	const { values } = parseArgs({
		args,
		options: {
			minutes: { type: "string", default: String(DEFAULT_MINUTES) },
			help: { type: "boolean", default: false },
		},
	});
	if (values.help) {
		process.stdout.write(USAGE);
		return;
	}
	await runCanary({
		port: CANARY_PORT,
		minutes: parseMinutes(values.minutes),
		log: (line) => process.stdout.write(`${line}\n`),
	});
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	if (args[0] === "canary") return canaryMain(args.slice(1));
	const { values, positionals } = parseArgs({
		args,
		allowPositionals: true,
		options: {
			list: { type: "boolean", default: false },
			path: { type: "string", multiple: true, default: [] },
			ws: { type: "boolean", default: false },
			"ws-path": { type: "string", multiple: true, default: [] },
			"post-path": { type: "string", multiple: true, default: [] },
			include: { type: "string", multiple: true, default: [] },
			exclude: { type: "string", multiple: true, default: [] },
			json: { type: "boolean", default: false },
			out: { type: "string" },
			help: { type: "boolean", default: false },
		},
	});

	if (values.help) {
		process.stdout.write(USAGE);
		return;
	}
	if (positionals.length !== 1 || positionals[0] !== "scan") {
		process.stderr.write(USAGE);
		process.exitCode = 2;
		return;
	}

	const options: ScanOptions = {
		include: new Set(values.include.map(parsePort)),
		exclude: new Set(values.exclude.map(parsePort)),
		paths: values.path.map(parsePortPath),
		webSockets: values.ws,
		webSocketPaths: values["ws-path"].map(parsePortPath),
		postPaths: values["post-path"].map(parsePortPath),
	};

	const listeners = await listListeners();
	if (values.list) {
		process.stdout.write(`${renderPlan(listeners, options)}\n`);
		return;
	}

	const pathEntries: PortPath[] = [
		...options.paths,
		...options.webSocketPaths,
		...options.postPaths,
	];
	warnAboutUnknownPorts(
		[
			...pathEntries.map((entry) => entry.port),
			...options.include,
			...options.exclude,
		],
		new Set(listeners.map((listener) => listener.port)),
	);

	// Opened first so that a bad path fails before any probe is sent.
	const outFile =
		values.out === undefined ? null : await open(values.out, "wx", 0o600);
	let saved = false;
	try {
		const results = await scanListeners(listeners, options);
		const context = {
			sawAllUsers: process.getuid?.() === 0,
			webSocketsTested: options.webSockets,
		};
		const json = JSON.stringify(
			{ limits: reportLimits(context), results },
			null,
			2,
		);
		process.stdout.write(
			values.json ? `${json}\n` : `${renderReport(results, context)}\n`,
		);
		await outFile?.writeFile(`${json}\n`);
		saved = true;
	} finally {
		await outFile?.close();
		if (values.out !== undefined && !saved)
			await rm(values.out, { force: true });
	}
}

// A reader such as `less` may quit early, and the --out file must still be written.
process.stdout.on("error", (error: NodeJS.ErrnoException) => {
	if (error.code !== "EPIPE") throw error;
});

main().catch((error: unknown) => {
	process.stderr.write(
		`localprobe: ${error instanceof Error ? error.message : String(error)}\n`,
	);
	process.exitCode = 1;
});
