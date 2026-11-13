# Browser policy matrix

What an ordinary HTTPS page could send to the canary on loopback port 47823, by browser, version and date. Each cell shows what the page saw, whether the canary logged the HTTP request, and whether a TCP connection arrived without one. Only measured cells are filled. Everything else reads "not measured".

A browser that blocks a request type on this date and version does not make any service safe. Browser rules change between releases.

Page: <https://orlenko.github.io/localprobe/> (HTTPS). Results for plain-HTTP pages are not measured in any browser. WebKit has treated the two differently, so read the Safari column with that in mind.

## Columns

| Column       | Browser and state                                                                                                                                                                                                                                                                                    | Date         |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| P1           | Google Chrome 157.0.8103.78 on macOS 27.2.1, headed, launched by the Playwright MCP server with its defaults, among them `--disable-field-trial-config`, `--disable-popup-blocking` and `--disable-background-networking`. Local network permissions at `prompt`, and the prompt was never answered. | 2026-11-13   |
| P2           | Same browser. `loopback-network`, `local-network` and `local-network-access` set to `granted` through the DevTools protocol (`Browser.setPermission`). No prompt was shown.                                                                                                                          | 2026-11-13   |
| P3           | Same browser. The same three permissions set to `denied` through the DevTools protocol.                                                                                                                                                                                                              | 2026-11-13   |
| Chrome allow | Google Chrome 157.0.8103.52 on macOS 27.2.1, used by a person, no automation. `loopback-network` allowed at Chrome's prompt before the run. The page read `loopback-network=granted`, `local-network=prompt`, `local-network-access=granted`. Idle TCP connections were not recorded.                | 2026-11-13   |
| Chrome deny  | Chrome, prompt answered "block" by a person                                                                                                                                                                                                                                                          | not measured |
| Safari       | Safari 27.2                                                                                                                                                                                                                                                                                          | not measured |
| Firefox      | Firefox, allow and deny                                                                                                                                                                                                                                                                              | not measured |

P1 to P3 do not show what Chrome does for a person using it. Nobody saw or answered a prompt, the permission in P2 and P3 was set by automation, and field trials were disabled.

## Results

"Arrived" means the canary logged the HTTP request with the run's ID. "TCP only" means a connection opened at that row's time and sent no request. "TCP, grouped" means connections that sent no request opened during a group of rows, but not one per row (see below). Rows to `0.0.0.0` reach the canary's `127.0.0.1` listener.

| Test               | Target    | P1 prompt, unanswered                 | P2 granted                             | P3 denied                             | Chrome allow                                                                                   | Chrome deny  | Safari       | Firefox      |
| ------------------ | --------- | ------------------------------------- | -------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------ | ------------ | ------------ |
| fetch no-cors      | 127.0.0.1 | timed out after 20 s; TCP only        | arrived, opaque                        | TypeError; TCP, grouped               | arrived, opaque                                                                                | not measured | not measured | not measured |
| fetch no-cors      | localhost | timed out after 20 s; TCP only (IPv6) | arrived (IPv6), opaque                 | TypeError; TCP, grouped               | arrived (IPv6), opaque                                                                         | not measured | not measured | not measured |
| fetch no-cors      | [::1]     | timed out after 20 s; TCP only        | arrived, opaque                        | TypeError; TCP, grouped               | arrived, opaque                                                                                | not measured | not measured | not measured |
| fetch no-cors      | 0.0.0.0   | timed out after 20 s; TCP only        | arrived, opaque                        | TypeError; TCP, grouped               | arrived, opaque                                                                                | not measured | not measured | not measured |
| fetch cors         | 127.0.0.1 | timed out after 20 s; TCP only        | arrived, body read                     | TypeError; TCP, grouped               | arrived, body read                                                                             | not measured | not measured | not measured |
| fetch cors         | localhost | timed out after 20 s; TCP only (IPv6) | arrived (IPv6), body read              | TypeError; TCP, grouped               | arrived (IPv6), body read                                                                      | not measured | not measured | not measured |
| fetch cors         | [::1]     | timed out after 20 s; TCP only        | arrived, body read                     | TypeError; TCP, grouped               | arrived, body read                                                                             | not measured | not measured | not measured |
| fetch cors         | 0.0.0.0   | timed out after 20 s; TCP only        | arrived, body read                     | TypeError; TCP, grouped               | arrived, body read                                                                             | not measured | not measured | not measured |
| WebSocket          | 127.0.0.1 | not opened in 20 s; TCP only          | arrived, opened, frame received        | closed 1006; TCP, grouped             | arrived, opened, frame received                                                                | not measured | not measured | not measured |
| WebSocket          | localhost | not opened in 20 s; TCP only (IPv6)   | arrived (IPv6), opened, frame received | closed 1006; TCP, grouped             | arrived (IPv6), opened, frame received                                                         | not measured | not measured | not measured |
| WebSocket          | [::1]     | not opened in 20 s; TCP only          | arrived, opened, frame received        | closed 1006; TCP, grouped             | arrived, opened, frame received                                                                | not measured | not measured | not measured |
| WebSocket          | 0.0.0.0   | not opened in 20 s; TCP only          | arrived, opened, frame received        | closed 1006; TCP, grouped             | arrived, opened, frame received                                                                | not measured | not measured | not measured |
| iframe navigation  | 127.0.0.1 | no signal; TCP only                   | arrived, canary script ran             | no signal; TCP only                   | arrived, canary script ran                                                                     | not measured | not measured | not measured |
| iframe navigation  | localhost | no signal; TCP only (IPv6)            | arrived (IPv6), canary script ran      | no signal; TCP only (IPv6)            | arrived (IPv6), canary script ran                                                              | not measured | not measured | not measured |
| iframe navigation  | [::1]     | no signal; TCP only                   | arrived, canary script ran             | no signal; TCP only                   | arrived, canary script ran                                                                     | not measured | not measured | not measured |
| iframe navigation  | 0.0.0.0   | no signal; TCP only                   | arrived, canary script ran             | no signal; TCP only                   | arrived, canary script ran                                                                     | not measured | not measured | not measured |
| form POST in popup | 127.0.0.1 | **arrived**, canary script ran        | arrived, canary script ran             | **arrived**, canary script ran        | arrived, canary script ran                                                                     | not measured | not measured | not measured |
| form POST in popup | localhost | **arrived** (IPv6), canary script ran | arrived (IPv6), canary script ran      | **arrived** (IPv6), canary script ran | arrived (IPv6), canary script ran                                                              | not measured | not measured | not measured |
| form POST in popup | [::1]     | **arrived**, canary script ran        | arrived, canary script ran             | **arrived**, canary script ran        | arrived, canary script ran                                                                     | not measured | not measured | not measured |
| form POST in popup | 0.0.0.0   | no signal; TCP only                   | "Form is not secure" page; TCP only    | no signal; TCP only                   | arrived after the person clicked through Chrome's "Form is not secure" page, canary script ran | not measured | not measured | not measured |

In P3 the twelve fetch and WebSocket rows and the iframe row to 127.0.0.1 ran within 40 ms and produced 9 TCP connections, so some fetch rows had no connection of their own. The counts fit one connection per host shared by the two fetch modes, one per WebSocket, and one for the iframe, but that mapping is inferred. In P1 each row had its own connection, matched by its open time. The form rows also opened extra connections that sent nothing, probably preconnects.

## What the measured columns show

- **The top-level form POST to 127.0.0.1, localhost and [::1] arrived in all three states, denied included.** In this browser setup, the local network permission did not gate it. This was measured for a popup opened by a click. A page navigating its own window was not measured. In P1 to P3 the form to `0.0.0.0` never sent a request.
- **TCP connections reached the canary in every state, for every request type, even where no HTTP request followed.** With the permission at prompt or denied, Chrome connected to the port and then sent nothing. Whether a page can tell an open port from a closed one this way, for example by timing, was not measured.
- With the permission granted (P2 and Chrome allow), every request type reached all four addresses, `0.0.0.0` included, except the `0.0.0.0` form in P2. In P2, Chrome logged the `0.0.0.0` fetch, WebSocket and iframe requests as mixed content but sent them.
- The `0.0.0.0` form stopped at Chrome's "Form is not secure" page in P2, where nobody clicked. In the Chrome allow run, a person clicked through it to send, and the POST arrived. That page is a warning a user can click past, not a block.
- The Chrome allow column, from a person's Chrome with loopback access allowed, matches P2 in every row except that `0.0.0.0` form.
- `localhost` connected over `::1` in every row where the canary saw the hostname. The canary listened on both addresses, so whether Chrome falls back to `127.0.0.1` was not measured.
- The form POSTs carried `Origin: null`, because the page sets a no-referrer policy. A hostile page would usually send its own origin. There was no control run without the policy.
- Requests to `0.0.0.0` carried no `Sec-Fetch-*` headers: fetch and iframe in P2, and fetch, iframe and form in the Chrome allow run. The other targets did.

## Running a column yourself

1. Start the canary: `node src/cli.ts canary`. Open `http://127.0.0.1:47823/` in a tab and check that the canary logs a line.
2. Reset the site's permission first, so the browser asks. In Chrome, paste `chrome://settings/content/siteDetails?site=https%3A%2F%2Forlenko.github.io` into the address bar and click Reset permissions.
3. Open the page, click Run, and answer the prompt the way the column says. Leave the small window open.
4. Open "Details for pasting" on the page and copy it, and the canary lines that carry the run ID.
5. Wait 90 seconds after the run ends. Then copy every `IDLE`, `EMPTY`, `UNPARSED` and `DROPPED` line whose `opened=` time falls inside the run. An `IDLE` line appears 60 to 90 seconds after its connection opened. Leave at least 90 seconds between runs.
6. For each row, note the page result, whether the canary logged the path, and whether a connection opened at that row's time. Record the browser version from the output header, and the date.
7. Reset the permission again when done.

Paste only those lines. Other canary lines can show requests from other pages you have open.

### Checklist for the unmeasured columns

- [x] Chrome, allow: measured 2026-11-13, Chrome 157.0.8103.52.
- [ ] Chrome, deny: reset the permission, run, click Block on the prompt.
- [ ] Chrome, ignore: reset, run, leave the prompt unanswered, to compare with P1.
- [x] Chrome, `0.0.0.0` form: the "Form is not secure" page lets a person send anyway, and doing so delivers the POST.
- [ ] Safari 27.2: run. Note any prompt and your answer.
- [ ] Firefox, if installed: run with allow and with deny, if it asks.
