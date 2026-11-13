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

- Tunnels and forwards, which can carry a probe to a remote system: `ssh`, `kubectl`, `cloud-sql-proxy`, `aws`, `gcloud`, `socat`, and similar. The list cannot be complete, so `--list` shows the plan and sends nothing, and `--exclude PORT` is available. The kernel picks which socket answers, so if any process on a port is skipped, the whole port is.
- Silent line-protocol services, identified by process name or port: Redis, Memcached, Postgres, MySQL, MongoDB. An HTTP request written into these is logged as an attack or misparsed.

`--include PORT` overrides both for a named port.

**Classify before writing.** Connect and wait briefly for a banner. A listener that speaks first (SMTP, IMAP, SSH) is recorded as `non-HTTP` and nothing is written to it. Other listeners get one HTTP request, then one TLS attempt if plain HTTP fails or returns 400.

**Report byte delivery.** Any non-HTTP listener on a port outside the Fetch bad-port list is reported as "a browser can deliver bytes here", since a page can send a controlled body to a line protocol.

**Probe HTTP listeners.** No cookies or credentials. Fixed paths only: `/`, `/api`, `/health`, `/metrics`, `/openapi.json`, plus any `--path PORT:/foo`. All of these are GET or OPTIONS. The preflight is sent even when `GET` returns 404.

| Check                    | Request                                                             | Finding                                                                          |
| ------------------------ | ------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Open data                | `GET`, valid `Host`, no `Origin`                                    | Status, size, content type. This is what a `no-cors` request looks like.         |
| Origin guard (CORS mode) | `GET`, `Origin: https://evil.example`, `Sec-Fetch-Site: cross-site` | Rejected or served. Applies only to requests that carry `Origin`.                |
| CORS read                | Same request                                                        | `Access-Control-Allow-Origin` is `*` or reflects the origin; credentials allowed |
| Preflight                | `OPTIONS`, asks for `PUT` and `content-type: application/json`      | Write calls permitted cross-origin                                               |
| Rebinding                | `GET`, `Host: evil.example`                                         | Rejected or served                                                               |

Probes carry no cookies, so the report states that it cannot see what an ambient session cookie would add.

**Opt-in checks.**

- `--ws`: WebSocket upgrade with a hostile `Origin` on `/` of every HTTP service, then close with no frames. `--ws-path PORT:/foo` does the same on one path of one service. A 101 is reported as "a hostile origin can open this socket". It is opt-in because connect handlers can run. When `--ws` is off, the report says so.
- `--post-path PORT:/foo`: a cross-site `POST` with `text/plain` and an empty body to one path of one service. You are asserting that path is safe to call.

**Report.** Terminal table by default, `--json` for machine use. Nothing is written to disk unless `--out FILE` is given.

### 2. `localprobe canary`

A throwaway listener on a fixed loopback port, 47823. It logs each arrival (method, path, `Origin`, `Host`, `Sec-Fetch-*`), serves a CORS-enabled response and a WebSocket, holds no data, and exits after 10 minutes (`--minutes` changes this, up to 60).

The canary separates "the request arrived" from "the page could read it". A `TypeError` in the browser covers refused connections, mixed content, a denied permission, and bad ports, and bytes may have arrived in some of those cases.

- **Port ownership.** Before binding, it connects to `127.0.0.1` and `[::1]` on the port and refuses to start if anything answers. A successful bind alone does not prove ownership, because a specific-address bind can share a port with a wildcard one. The connect check also sees other users' sockets, which `lsof` without sudo does not. It then binds `127.0.0.1`, and `::1` if the host has IPv6. Any other failure to bind `::1`, such as the address being in use, stops the canary. On macOS, `0.0.0.0` reaches the `127.0.0.1` bind.
- **Log.** One line per arrival, on stdout only: time, local address and family (so a `localhost` row shows whether IPv4 or IPv6 was used), method, path, `Host`, `Origin`, `Referer`, `Sec-Fetch-Site`, `-Mode`, `-Dest`, `Access-Control-Request-*`, `Upgrade`, and whether `Cookie` or `Authorization` was present. A connection whose request Node cannot parse, such as one with oversized headers, still gets an `UNPARSED` line, so a missing line always means nothing arrived. Headers up to 64 KB are accepted, because navigations carry every localhost cookie. Values of `Cookie` and `Authorization` are never logged, because other localhost services' cookies can arrive here. Control characters in every field are escaped, and each field is capped in length. It prints a start line and a minute-by-minute time-left line, so an expired canary is not mistaken for a block.
- **Responses.** Every path gets the same fixed bytes: a small HTML page with `Access-Control-Allow-Origin: *`, never `Allow-Credentials`, and a CSP that allows only the page's own hashed script. Nothing from the request is reflected into the response, because cookies are not port-scoped and a reflection would be an XSS against every other local service. The page's script reads `location.pathname` into a string and posts `{canary, run, test}` to its parent or opener. `OPTIONS` gets a 204 with the CORS headers. A WebSocket upgrade on any path gets a 101, one text frame, and a close.

### 3. Browser page (GitHub Pages)

One static HTML file with inline JS. No framework, no analytics, no third-party requests, no backend. Results are shown on the page and never sent anywhere.

**Policy matrix.** Fixed targets against the canary port, across `127.0.0.1`, `localhost`, `[::1]`, and `0.0.0.0`:

- `fetch` in `no-cors` and `cors` modes
- WebSocket
- iframe navigation
- top-level form `POST` in a popup

Each result is joined with what the canary logged, using a run ID, by pasting the page output and canary log side by side.

- **Click to run.** Nothing is sent on load. A popup needs a user gesture, and a Local Network Access prompt should not appear before the page has explained itself.
- **Header.** Each run prints the date, user agent, page origin, and the state of the `loopback-network`, `local-network`, and `local-network-access` permissions. Querying a permission does not prompt. Without this, an allowed run, a denied run, and an unanswered prompt look the same.
- **Expected list.** The page prints every expected `test-host` ID, so a missing canary line is visible. In the deny cases, absence is the main evidence. To check that the canary is up, open `http://127.0.0.1:47823/` in a tab: a typed navigation always arrives.
- **Iframe and popup.** The page cannot see into either, and `onload` also fires for error pages. A result counts only when the canary's page posts back a message whose origin is the target and whose run ID matches. Otherwise the page reports "no signal; see canary log". It never reports success from `onload`.
- **Results.** The page reports what it saw (`TypeError`, opaque response, status and size, socket opened) and does not guess the cause. `0.0.0.0` from an HTTPS page is likely blocked as mixed content before any local-network rule applies. The canary log shows whether bytes arrived.
- **Referrer.** `<meta name="referrer" content="no-referrer">`.

**Your own services.** A text box accepts up to 20 ports, typed on the page, loopback only, `GET /` only. It reports status and body size in `cors` mode, or reachable in `no-cors` mode. Bodies are not rendered or stored.

**No URL input.** The page reads nothing from the query or fragment, so a crafted link cannot change what it does. It refuses to run when framed, using a `window.top` check, because GitHub Pages cannot send `frame-ancestors`.

**Permissions.** A Local Network Access grant may persist for the whole `<user>.github.io` origin. The page tells the user how to revoke it after testing.

**Runs.** Chrome with the prompt allowed and denied, Firefox with the same two, Safari. A row driven by Playwright is labelled with its exact binary, version, headless or headed, and permission state, for example "Chromium N under Playwright, loopback-network: prompt". It is never labelled "Chrome allow" or "Chrome deny", and an unanswered prompt is not a denial.

The matrix is published in `docs/matrix.md`, dated, with only measured rows. Every other cell reads "not measured".

**Limit of HTTPS.** A hostile page can use plain HTTP, and GitHub Pages without a custom domain is HTTPS only. Browsers treat the two differently, and not always in the same direction: Chrome's Local Network Access guide says the permission is denied automatically in insecure contexts, so plain HTTP may be stricter there. WebKit is unknown. Until an HTTP harness exists, results for plain-HTTP pages are marked "not measured" in every browser, and Safari's column carries that warning.

## Verdicts

- **Readable by any website**: a CORS read succeeds from a hostile origin.
- **Cross-origin writes allowed**: a preflight permits `PUT` with a JSON content type from a hostile origin.
- **Socket open to any website**: 101 with a hostile `Origin` (`--ws` only).
- **Rebindable**: serves a hostile `Host`.
- **Open to the network**: bound beyond loopback and serving any tested path without credentials. Anyone on the network can connect, with no browser involved.
- **Browser can deliver bytes**: non-HTTP listener on a port browsers do not block.
- **Incomplete**: a check got no response or an inconclusive one, the listener gave no HTTP response, or no tested path exists. The tool does not report a clean result from this.
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

## Known gaps

- Ctrl-C during a scan with `--out` leaves an empty file, and a rerun with that name reports that it exists. Delete it and rerun. The file is reserved first so that a bad path fails before any probe is sent.
- A server that answers a hostile `Host` with 404 but still sends the full page is reported as rejecting it. Telling these apart would mean comparing response bodies.
- A `Readable by any website` finding can come from a 401, 403, or 5xx response, because CORS does not depend on status. The evidence line gives the status.
- The tunnel list cannot be complete. Tools that run under an interpreter, such as `gcloud`, may appear as `Python`. Check `--list` first.
- A Local Network Access grant to the page is a grant to every page on `orlenko.github.io`, and any page on that origin can script this one. The `window.top` check does not stop that. A dedicated origin would need a custom domain. The page explains how to revoke the grant.
- Playwright Chromium is not Chrome. Launch flags, field trials, and the absence of a prompt UI all differ, so its rows say exactly what ran and are not used for Chrome's columns.
- The canary's ownership check connects to the port. A listener that accepts only some connections, or starts after the check, is not caught.
- The own-services box cannot stop redirects in its no-cors retry, because browsers allow only `redirect: "follow"` in that mode. A service that redirects elsewhere sends the browser there. The cors attempt uses `redirect: "manual"`.
- The Playwright run is joined to the canary log by hand. Automating it would add a runtime dependency.

## Design review outcome

Accepted: skip tunnels; banner-first classification; canary; Origin check relabelled as CORS-mode and `Sec-Fetch-Site` added; blind-write probe and its "writable blind" verdict removed in favour of `--post-path`; script scraping removed; WebSocket probe made opt-in; no URL input on the page; plain-HTTP results marked not measured; Firefox added; top-level navigation added; no automated join between CLI and page.

Not accepted, with reasons:

- **Do not write to any silent unknown listener without a flag.** Every HTTP server is silent until spoken to, so this would skip the tool's main target. Named silent protocols are skipped by process and port instead.
- **Remove the service-specific page check entirely.** The tool exists to show what a browser can reach on this machine, so a typed, capped, loopback-only box stays. It takes no link input, which removes the abuse path the review raised.

### Steps 3 and 4

A second design review covered the canary and the page before any of that code was written.

Accepted: record the permission state in each run; click to run, nothing on load; postMessage from the canary's page for iframe and popup results, never `onload`; fixed response bytes with no reflection; never log cookie or authorization values, escape control characters; prove the canary owns its port; an expected-ID list, a liveness line, and `--minutes`; log the local address and family; label Playwright rows exactly; version every row, WebSocket especially; `Access-Control-Allow-Origin: *` with no credentials and no invented `Local-Network` header; report `0.0.0.0` results without naming a cause; correct the claim that plain HTTP is the looser case; no-referrer; build the own-services box last and keep it small.

Not accepted, with reasons:

- **Move the page to a dedicated origin.** The approved host is `orlenko.github.io/localprobe`. The shared origin is listed under Known gaps and the page explains how to revoke a grant.
- **Port check with `listListeners()`.** A connect check is used instead. It sees other users' sockets without sudo.
- **A control row that always arrives.** No request type from the page is certain to arrive in every browser. The control is a typed navigation to the canary, which the page tells you to do.
- **Join the Playwright run automatically.** It would add Playwright as a dependency. The join is by run ID, by hand.
- **A meta CSP limiting `connect-src` to the loopback hosts.** IPv6 literals are not valid CSP host sources, so the `[::1]` rows would be blocked by the page's own policy and look like a browser block. The page makes no third-party requests, and review checks that.
