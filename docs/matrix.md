# Browser policy matrix

What an ordinary HTTPS page could send to the canary on loopback port 47823, by browser, version and date. Each cell shows what the page saw and whether the canary logged an arrival. Only measured cells are filled. Everything else reads "not measured".

A browser that blocks a request type on this date and version does not make any service safe. Browser rules change between releases.

Page: <https://orlenko.github.io/localprobe/> (HTTPS). Results for plain-HTTP pages are not measured in any browser, and WebKit has treated the two differently, so read the Safari column with that in mind.

## Columns

| Column        | Browser and state                    | Date         |
| ------------- | ------------------------------------ | ------------ |
| A             | not measured yet                     |              |
| Chrome allow  | Chrome, permission prompt allowed    | not measured |
| Chrome deny   | Chrome, permission prompt denied     | not measured |
| Safari        | Safari                               | not measured |
| Firefox allow | Firefox, prompt allowed (if it asks) | not measured |
| Firefox deny  | Firefox, prompt denied (if it asks)  | not measured |

## Results

| Test               | Target    | A            | Chrome allow | Chrome deny  | Safari       | Firefox allow | Firefox deny |
| ------------------ | --------- | ------------ | ------------ | ------------ | ------------ | ------------- | ------------ |
| fetch no-cors      | 127.0.0.1 | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch no-cors      | localhost | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch no-cors      | [::1]     | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch no-cors      | 0.0.0.0   | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch cors         | 127.0.0.1 | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch cors         | localhost | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch cors         | [::1]     | not measured | not measured | not measured | not measured | not measured  | not measured |
| fetch cors         | 0.0.0.0   | not measured | not measured | not measured | not measured | not measured  | not measured |
| WebSocket          | 127.0.0.1 | not measured | not measured | not measured | not measured | not measured  | not measured |
| WebSocket          | localhost | not measured | not measured | not measured | not measured | not measured  | not measured |
| WebSocket          | [::1]     | not measured | not measured | not measured | not measured | not measured  | not measured |
| WebSocket          | 0.0.0.0   | not measured | not measured | not measured | not measured | not measured  | not measured |
| iframe navigation  | 127.0.0.1 | not measured | not measured | not measured | not measured | not measured  | not measured |
| iframe navigation  | localhost | not measured | not measured | not measured | not measured | not measured  | not measured |
| iframe navigation  | [::1]     | not measured | not measured | not measured | not measured | not measured  | not measured |
| iframe navigation  | 0.0.0.0   | not measured | not measured | not measured | not measured | not measured  | not measured |
| form POST in popup | 127.0.0.1 | not measured | not measured | not measured | not measured | not measured  | not measured |
| form POST in popup | localhost | not measured | not measured | not measured | not measured | not measured  | not measured |
| form POST in popup | [::1]     | not measured | not measured | not measured | not measured | not measured  | not measured |
| form POST in popup | 0.0.0.0   | not measured | not measured | not measured | not measured | not measured  | not measured |

## Running a column yourself

1. Start the canary: `node src/cli.ts canary`. Open `http://127.0.0.1:47823/` in a tab and check that the canary logs a line.
2. Reset the site's permission first, so the browser asks. In Chrome, paste `chrome://settings/content/siteDetails?site=https%3A%2F%2Forlenko.github.io` into the address bar and click Reset permissions.
3. Open the page, click Run, and answer the prompt the way the column says. Leave the small window open.
4. Copy the page output. Copy the canary lines that carry the run ID, and any `UNPARSED` lines logged during the run. Those are requests the canary could not read, such as ones with oversized headers.
5. For each row, note the page result and whether the canary logged the path. Record the browser version from the output header, and the date.
6. Reset the permission again when done.

Paste only those lines. Other canary lines can show requests from other pages you have open.
