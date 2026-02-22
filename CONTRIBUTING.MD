# Contributing to shenan

Thanks for your interest in contributing. Shenan is a small, focused project and we want to keep it that way. Before contributing, please read the design philosophy in the README — especially the section on what the relay never knows. Pull requests that compromise those properties will not be merged regardless of other merits.

---

## Getting started

```bash
git clone https://github.com/jhnlsn/shenan
cd shenan

# relay
cd relay && go build ./...

# cli
cd cli && go build ./...
```

Go 1.22+ is required.

---

## Project structure

```
relay/        relay server (AGPL v3)
cli/          command-line client (MIT)
spec/         protocol specifications (CC0)
```

The relay and CLI are deliberately separate modules with separate licenses. Keep them separate. Do not introduce dependencies from `relay/` into `cli/` or vice versa.

---

## Security issues

**Do not open a public GitHub issue for security vulnerabilities.**

Email `security@shenan.dev` with a description of the issue. We will acknowledge within 48 hours and coordinate disclosure. If you want to encrypt your report, use the GPG key at `https://shenan.dev/.well-known/security.txt`.

---

## Pull requests

- Open an issue first for significant changes. For small fixes, a PR is fine.
- One concern per PR. Do not bundle unrelated changes.
- Tests are required for any change to the relay or CLI core logic.
- The relay has a strict no-log policy. Any PR that adds logging of identity-linked events will be rejected.
- Do not add external dependencies to the relay without prior discussion. The relay should remain a single compilable binary with minimal dependencies.

---

## Code style

Follow standard Go conventions (`gofmt`, `golint`, `go vet`). We use `golangci-lint` in CI. Run it locally before submitting:

```bash
golangci-lint run ./...
```

---

## Spec changes

The protocol specification in `spec/` is separately versioned. Changes to the spec require:

1. An issue describing the proposed change and its rationale
2. Discussion and rough consensus before a PR is opened
3. A corresponding implementation or test demonstrating the change

Spec changes that break compatibility with the current protocol require a version bump.

---

## License

By contributing, you agree that your contributions to `relay/` will be licensed under AGPL v3, contributions to `cli/` under MIT, and contributions to `spec/` under CC0.