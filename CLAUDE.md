# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-hdb is a native Go database driver for SAP HANA that implements Go's `database/sql` interface. It provides a pure Go implementation of the SAP HANA SQL command network protocol (no CGO, no C dependencies).

## Build and Development Commands

### Running Tests

Unit tests (no database required):
```bash
go test --tags unit ./...
go test --tags unit ./... -race
```

Integration tests (requires SAP HANA):
```bash
export GOHDBDSN="hdb://user:password@host:port"
go test ./...
```

### Linting and Verification

```bash
go vet ./...
golangci-lint run ./...
```

### Code Generation

Enum string representations are generated using stringer:
```bash
go generate ./...
```

### Full Build Pipeline

```bash
make all       # deps, build, vet, lint, test (multiple Go versions), license check
make tools     # install stringer, golint, staticcheck, golangci-lint
make generate  # run go generate
```

## Architecture

### Package Structure

- **`driver/`** - Main database driver package implementing `database/sql` interfaces
- **`driver/internal/protocol/`** - Binary protocol implementation (54 files)
  - `auth/` - Authentication (PBKDF2/SCRAM, X.509, JWT, session cookies)
  - `encoding/` - Binary encoding/decoding for protocol messages
- **`driver/unicode/cesu8/`** - CESU-8 encoding support (HANA's Unicode variant)
- **`driver/spatial/`** - Spatial/geographic data type support
- **`prometheus/`** - Separate module for Prometheus metrics collectors

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Driver registration | `driver/driver.go` | Singleton `hdbDriver`, registered as "hdb" |
| Connection management | `driver/connector.go`, `conn.go`, `session.go` | DSN parsing, connection lifecycle |
| Protocol layer | `driver/internal/protocol/protocol.go` | Binary protocol communication |
| Type conversion | `driver/convert.go`, `decimal.go` | Go ↔ HANA type mapping |
| LOB handling | `driver/lob.go` | Large object streaming |
| Metrics | `driver/metrics.go`, `stats.go` | Connection statistics |

### Driver Flow

```
hdbDriver (singleton)
  └── Connector (DSN config, TLS, auth)
       └── session (protocol reader/writer)
            └── dbConn (network connection)
                 └── Protocol (internal/protocol)
```

## Version Compatibility

- **Minimum Go:** 1.24.0
- **Toolchain:** go1.25.5
- Version-specific code in `driver/wgroup/` and `driver/internal/protocol/parts1.24.go`/`parts1.25.go`
- Multi-platform: Linux (amd64, arm, arm64, s390x), macOS, Windows

## Dependencies

Main module has minimal dependencies (only `golang.org/x/text`). The `prometheus/` module is a separate Go module with additional dependencies.
