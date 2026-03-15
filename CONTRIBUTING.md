# Contributing to Subjack

Thanks for your interest in contributing to Subjack! This guide will help you get started.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/subjack.git
   cd subjack
   ```
3. Create a feature branch:
   ```bash
   git checkout -b my-feature
   ```

## Development Setup

Subjack requires the Go version specified in `go.mod` or later. Verify your installation:

```bash
go version
```

Build the project:

```bash
go build .
```

Run the linter:

```bash
go vet ./...
```

Run tests:

```bash
go test ./...
```

## Project Structure

```
subjack/
├── main.go              # CLI entry point and flag parsing
├── subjack/
│   ├── subjack.go       # Core orchestration logic
│   ├── dns.go           # DNS resolution and NXDOMAIN checking
│   ├── fingerprint.go   # Fingerprint matching logic
│   ├── http.go          # HTTP client (fasthttp)
│   ├── output.go        # Result formatting and file I/O
│   └── fingerprints.json # Embedded service fingerprints
├── .github/workflows/   # CI and release pipelines
├── go.mod
└── go.sum
```

## Adding a New Fingerprint

To add detection for a new vulnerable service, add an entry to `subjack/fingerprints.json`:

```json
{
  "service": "Example Service",
  "cname": ["example.com"],
  "fingerprint": ["The unique error string shown on unclaimed pages"],
  "nxdomain": false
}
```

- **service** — Name of the service.
- **cname** — CNAME patterns that identify the service.
- **fingerprint** — Strings found in the HTTP response body when the subdomain is claimable.
- **nxdomain** — Set to `true` if the takeover relies on the CNAME target being unregistered rather than an HTTP fingerprint.

You can use [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz) as a starting point, but always verify the vulnerability independently through your own testing.

## Making Changes

- Follow standard Go conventions and format your code with `gofmt`.
- Keep changes focused — one feature or fix per pull request.
- Ensure `go build ./...` and `go vet ./...` pass before submitting.
- Add or update tests where applicable.

## Submitting a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin my-feature
   ```
2. Open a pull request against the `master` branch.
3. Describe what your change does and why.
4. CI will run `go build`, `go vet`, and `go test` automatically — make sure all checks pass.

## Reporting Issues

Open an issue on GitHub with:

- A clear description of the problem or suggestion.
- Steps to reproduce (for bugs).
- Expected vs. actual behavior.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
