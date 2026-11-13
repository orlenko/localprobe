# localprobe

If you visit a hostile website, what can that page reach on your local servers? localprobe tests this on your own machine.

Only run it on machines you own or are allowed to test. Results describe what runs on your machine, so don't commit or publish them.

Requires macOS, Node 22.18 or later, and pnpm.

```sh
git clone https://github.com/orlenko/localprobe.git
cd localprobe
pnpm install
pnpm test
```

Check what would be touched. This sends nothing:

```sh
node src/cli.ts scan --list
```

Exclude anything you don't want contacted, then scan:

```sh
node src/cli.ts scan --ws --exclude 9000
```

See `node src/cli.ts scan --help` for testing specific paths.

## What your browser lets through

The scan tests your services. The browser page tests your browser: which request types an ordinary HTTPS page can send to `127.0.0.1`, `localhost`, `[::1]` and `0.0.0.0`.

Start the canary, a throwaway listener on port 47823 that logs each request, holds no data, and exits after 10 minutes:

```sh
node src/cli.ts canary
```

Then open <https://orlenko.github.io/localprobe/> and click Run. Open "Details for pasting" on the page and paste it next to the canary log. The run ID in each request path lines them up.

Measured results, with dates and browser versions, are in [docs/matrix.md](docs/matrix.md). The design is in [docs/design.md](docs/design.md).
