# localprobe design

## Goal

Answer one question for the machine you are sitting at: if I visit a hostile website, what can that page reach on my local servers?

A hostile page needs no XSS. It runs its own JavaScript and sends requests to `127.0.0.1`. The same-origin policy limits what it can read, but the request can still arrive.

Two separate things decide the outcome, and the tool measures them separately:

- **Browser policy** depends on browser, version, page scheme, target address, and request type. The page and the canary measure this.
- **Service behaviour** depends on headers and bind address. The CLI measures this.

## Non-goals

- Scanning other people's machines. The CLI only talks to loopback and this machine's own interface addresses.
- Port-range sweeps. The CLI asks the OS what is listening.
- Exploiting anything.
- Linux and Windows, for now. macOS first.
- Phone and LAN runs from the page, for now. The CLI reports bind address, which covers LAN exposure.

## Parts

### 1. `localprobe scan`

Node 22, TypeScript, no runtime dependencies. It uses `node:http`, `node:https` and `node:net` because `fetch` will not send an arbitrary `Host` header.

**Find listeners.** Parse `lsof +c 0 -nP -iTCP -sTCP:LISTEN`. Record port, process, and bind address. Exposure is `loopback`, `interface-specific`, or `all-interfaces`. Without sudo this shows only the current user's sockets, and the report says so.

**Decide what not to touch.** These are listed as "not probed" with the reason:

- Tunnels and forwards, which can carry a probe to a remote system: `ssh`, `kubectl`, `cloud-sql-proxy`, `aws`, `gcloud`, `socat`, and similar. The list cannot be complete, so the report prints every process it will probe before probing, and `--exclude PORT` is available.
- Silent line-protocol services, identified by process name or port: Redis, Memcached, Postgres, MySQL, MongoDB. An HTTP request written into these is logged as an attack or misparsed.

`--include PORT` overrides both for a named port.

**Classify before writing.** Connect and wait briefly for a banner. A listener that speaks first (SMTP, IMAP, SSH) is recorded as `non-HTTP` and nothing is written to it. Other listeners get one HTTP request, then one TLS attempt if plain HTTP fails.

**Report byte delivery.** Any non-HTTP listener on a port outside the Fetch bad-port list is reported as "a browser can deliver bytes here", since a page can send a controlled body to a line protocol.

**Probe HTTP listeners.** No cookies or credentials. Fixed paths only: `/`, `/api`, `/health`, `/metrics`, `/openapi.json`, plus any `--path /foo`. All of these are GET or OPTIONS.

| Check | Request | Finding |
| --- | --- | --- |
| Open data | `GET`, valid `Host`, no `Origin` | Status, size, content type. This is what a `no-cors` request looks like. |
| Origin guard (CORS mode) | `GET`, `Origin: https://evil.example`, `Sec-Fetch-Site: cross-site` | Rejected or served. Applies only to requests that carry `Origin`. |
| CORS read | Same request | `Access-Control-Allow-Origin` is `*` or reflects the origin; credentials allowed |
| Preflight | `OPTIONS`, asks for `PUT` and `content-type: application/json` | Write calls permitted cross-origin |
| Rebinding | `GET`, `Host: evil.example` | Rejected or served |

Probes carry no cookies, so the report states that it cannot see what an ambient session cookie would add.

**Opt-in checks.**

- `--ws`: WebSocket upgrade with a hostile `Origin` on `/` and on each `--ws-path`, then close with no frames. A 101 is reported as "a hostile origin can open this socket". It is opt-in because connect handlers can run. When it is off, the report says WebSockets were not tested.
- `--post-path /foo`: a cross-site `POST` with `text/plain` and an empty body to a path you name. You are asserting that path is safe to call.

**Report.** Terminal table by default, `--json` for machine use. Nothing is written to disk unless `--out FILE` is given.

### 2. `localprobe canary`

A throwaway listener on a fixed loopback port. It logs each arrival (method, path, `Origin`, `Host`, `Sec-Fetch-*`), serves a CORS-enabled response and a WebSocket, holds no data, and exits after 10 minutes.

The canary separates "the request arrived" from "the page could read it". A `TypeError` in the browser covers refused connections, mixed content, a denied permission, and bad ports, and bytes may have arrived in some of those cases.

### 3. Browser page (GitHub Pages)

One static HTML file with inline JS. No framework, no analytics, no third-party requests, no backend. Results are shown on the page and never sent anywhere.

**Policy matrix.** Fixed targets against the canary port, across `127.0.0.1`, `localhost`, `[::1]`, and `0.0.0.0`:

- `fetch` in `no-cors` and `cors` modes
- WebSocket
- iframe navigation
- top-level form `POST` in a popup

Each result is joined with what the canary logged, using a run ID, by pasting the page output and canary log side by side.

**Your own services.** A text box accepts up to 20 ports, typed on the page, loopback only, `GET /` only. It reports status and body size in `cors` mode, or reachable in `no-cors` mode. Bodies are not rendered or stored.

**No URL input.** The page reads nothing from the query or fragment, so a crafted link cannot change what it does. It refuses to run when framed, using a `window.top` check, because GitHub Pages cannot send `frame-ancestors`.

**Permissions.** A Local Network Access grant may persist for the whole `<user>.github.io` origin. The page tells the user how to revoke it after testing.

**Runs.** Chrome with the prompt allowed and denied, Firefox with the same two, Safari.

**Limit of HTTPS.** A hostile page can use plain HTTP, and GitHub Pages without a custom domain is HTTPS only. WebKit has treated the two differently. Until an HTTP harness exists, results for plain-HTTP pages are marked "not measured" in every browser, and Safari's column carries that warning.

## Verdicts

- **Readable by any website**: a CORS read succeeds from a hostile origin.
- **Socket open to any website**: 101 with a hostile `Origin` (`--ws` only).
- **Rebindable**: serves a hostile `Host`.
- **Open to the network**: bound beyond loopback and serving `/` without credentials. Anyone on the network can connect, with no browser involved.
- **Browser can deliver bytes**: non-HTTP listener on a port browsers do not block.
- **No exposure found on the tested paths** lists those paths. The tool never says "safe".

A browser that blocks a `fetch` is reported as blocking that request type on that date and version. It is not reported as protecting the service.

Browser behaviour changes between releases, so the published matrix carries dates and versions.

## Safety and privacy

- Results describe what runs on your machine. `.gitignore` covers `results/` and `*.localprobe.json`. The public repo and page hold no scan data.
- The CLI keeps status, named headers, size, and content type. It does not store response bodies.

## Build order

1. Listener parsing, the not-probed filter, banner classifier. Pure classifiers get unit tests on recorded responses.
2. HTTP probes and report.
3. Canary and policy matrix page. Run the matrix before building more of the page.
4. Own-services box, GitHub Pages deploy, published dated matrix.

## Stack

TypeScript `strict`, Node 22, pnpm, Vitest, Biome. Page is plain HTML and JS with no build step. MIT license.

## Design review outcome

Accepted: skip tunnels; banner-first classification; canary; Origin check relabelled as CORS-mode and `Sec-Fetch-Site` added; blind-write probe and "writable" verdict removed in favour of `--post-path`; script scraping removed; WebSocket probe made opt-in; no URL input on the page; plain-HTTP results marked not measured; Firefox added; top-level navigation added; no automated join between CLI and page.

Not accepted, with reasons:

- **Do not write to any silent unknown listener without a flag.** Every HTTP server is silent until spoken to, so this would skip the tool's main target. Named silent protocols are skipped by process and port instead.
- **Remove the service-specific page check entirely.** The tool exists to show what a browser can reach on this machine, so a typed, capped, loopback-only box stays. It takes no link input, which removes the abuse path the review raised.
