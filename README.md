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

See `node src/cli.ts scan --help` for testing specific paths. The design is in [docs/design.md](docs/design.md).
