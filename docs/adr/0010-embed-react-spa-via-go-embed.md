---
status: accepted
date: 2026-02-18
---

# Embed the React SPA in the Go Binary via go:embed

## Context and Problem Statement

Portal's relay server includes a web-based management UI built with React 19, Vite 7, TypeScript, Tailwind CSS v4, and shadcn/ui. This frontend displays active leases, provides admin controls (bans, BPS limits, approval mode), and supports subdomain-based portal proxying with Open Graph metadata injection.

The frontend must be served to users. The question is how: deploy it separately (CDN, static file server, S3 bucket) or bundle it inside the Go binary. Portal is designed as a self-hosted tool where operators deploy a single artifact. A separately deployed frontend adds infrastructure requirements, CORS configuration, and version synchronization challenges.

## Decision Drivers

- **Single-artifact deployment** -- Operators ship one binary or one Docker image. No additional infrastructure for static file hosting.
- **Version consistency** -- The frontend and backend must always be the same version. A stale frontend calling a newer backend API (or vice versa) causes subtle, hard-to-debug failures.
- **Zero frontend infrastructure** -- No CDN, S3 bucket, nginx static server, or CORS headers to configure for cross-origin API calls.
- **Docker image simplicity** -- One Dockerfile, one image, one container. No sidecar for static files.
- **Server-side data injection** -- The relay server injects SSR data (lease rows, OG metadata) into the HTML at serve time. This requires the server to read and modify the HTML template, which is simpler when the template is embedded in the same binary.

## Considered Options

### Option 1: Embed the built React app via go:embed in the Go binary

Build the React app with Vite during the build process. The output goes to `cmd/relay-server/dist/app/`. The Go compiler embeds this directory into the binary using `//go:embed dist/*`. At runtime, the embedded filesystem serves the SPA, and the server injects SSR data into the HTML before serving it.

**Pros:**

- Single binary contains the entire application: Go relay server + React management UI.
- Frontend version always matches backend version -- they are literally the same build artifact.
- No CDN, S3, or static file server infrastructure needed.
- No CORS configuration required: frontend and API are same-origin.
- The Docker image is self-contained: one `COPY` from the builder stage.
- Server can read and modify embedded HTML at runtime for SSR data injection (lease rows as JSON, Open Graph metadata for subdomain pages).

**Cons:**

- Binary size increases by the size of the built React app (typically 2-5 MB for production Vite builds with tree-shaking and minification).
- Any frontend change requires rebuilding the entire Go binary, even if no Go code changed.
- No CDN edge caching for static assets. All asset requests go to the relay server. Mitigated by `Cache-Control: public, max-age=3600` headers on static assets and `max-age=604800` on large media files.
- Development workflow requires building the frontend before testing backend changes that involve the UI. Mitigated by running Vite's dev server separately during development with API proxy to the Go backend.

### Option 2: Separate frontend deployment (CDN/S3/nginx)

Build the React app and deploy it to a CDN, S3 bucket, or dedicated nginx instance. The Go relay server serves only the API and relay endpoints.

**Pros:**

- CDN edge caching for static assets, reducing latency for geographically distributed users.
- Frontend deploys independently of backend: faster iteration cycles for UI changes.
- Binary size is smaller (Go code only).

**Cons:**

- Requires additional infrastructure: CDN/S3 bucket + deployment pipeline, or nginx container.
- CORS headers must be configured on the API server to allow cross-origin requests from the CDN domain.
- Version synchronization is manual: deploying a new backend API without updating the frontend (or vice versa) causes breakage.
- SSR data injection (lease rows, OG metadata) requires a separate mechanism: either an API call from the client (adding latency to initial render) or a server-side rendering service.
- Contradicts Portal's single-binary, self-hosted deployment model.
- Operators must configure and maintain two deployment targets instead of one.

### Option 3: Server-side rendering with Go templates

Replace the React SPA with Go `html/template` rendered pages. The server generates complete HTML on each request.

**Pros:**

- No JavaScript build pipeline at all.
- Every page load gets fresh data without client-side fetching.
- Smallest possible client payload (HTML + minimal CSS).

**Cons:**

- Abandons the rich, interactive UI that React provides (real-time lease updates, admin controls, view transitions).
- Go templates are difficult to maintain for complex UIs (component composition, state management, routing).
- Requires full page reloads for every interaction, degrading user experience.
- The existing React codebase (React 19 + shadcn/ui + Tailwind) would be discarded, losing significant development investment.
- No ecosystem for Go-template-based interactive UIs (no component libraries, no state management).

### Option 4: Separate static file server container in same pod

Run the Go relay server and an nginx container in the same Kubernetes pod (or Docker Compose service). Nginx serves static files; the Go server serves the API and relay.

**Pros:**

- CDN-grade static file serving via nginx (sendfile, gzip, brotli).
- Same pod means shared network namespace: no CORS issues.
- Frontend and backend deploy together (same pod spec), maintaining version consistency.

**Cons:**

- Requires two containers per deployment: doubles the container count.
- Docker Compose or Kubernetes manifest complexity increases.
- Non-Kubernetes deployments (bare systemd, single Docker container) lose this option entirely.
- Nginx configuration must be maintained, versioned, and tested.
- SSR data injection still requires coordination between the two containers.
- Contradicts Portal's single-binary deployment model.

## Decision Outcome

**Chosen option: Option 1 -- Embed the built React app via `go:embed` in the Go binary.**

This option aligns perfectly with Portal's single-binary, self-hosted deployment model. Operators get one artifact that contains everything. Version consistency is guaranteed by construction. SSR data injection is trivial because the server reads the embedded HTML template from memory.

The binary size increase (2-5 MB) is negligible for a server-side application. The lack of CDN edge caching is acceptable because Portal is self-hosted, typically accessed by a small number of administrators on the same network as the relay server.

## Consequences

### Good

- Single binary contains the complete application. `docker run ghcr.io/gosuda/portal:latest` serves both the management UI and the relay with zero configuration.
- Frontend version always matches backend version. There is no version skew because they are the same binary.
- No CDN, S3, nginx, or static file hosting infrastructure to provision, configure, monitor, or pay for.
- No CORS configuration: the frontend and API share the same origin.
- The Docker image uses a multi-stage build: Node.js builds the frontend, Go embeds the output, and the final image is `distroless/static` with a single binary.
- SSR data injection works by reading the embedded `portal.html`, replacing placeholders (`[%OG_TITLE%]`, `[%OG_DESCRIPTION%]`, `[%OG_IMAGE_URL%]`), and injecting a `<script id="__SSR_DATA__">` tag with JSON-serialized lease rows before `</head>`.

### Bad

- The Go binary is 2-5 MB larger than it would be without the embedded frontend assets.
- Frontend changes require a full rebuild: `npm run build` (Vite) then `go build` (Go). During development, this is mitigated by running Vite's dev server with an API proxy.
- No CDN edge caching for static assets. All requests hit the relay server directly. Cache-Control headers (`max-age=3600` for JS/CSS, `max-age=604800` for media) provide browser-level caching.

### Neutral

- The Vite build output goes to `cmd/relay-server/dist/app/`. The Go embed directive in `cmd/relay-server/serve.go` is `//go:embed dist/*`, which captures the entire build output.
- The embedded filesystem is exposed as an `embed.FS` value (`distFS`), wrapped by `Frontend` methods that serve assets with appropriate content types, cache headers, and fallback behavior (unknown paths fall back to `portal.html` for client-side SPA routing).
- During development, `cd cmd/relay-server/frontend && npm run dev` starts Vite's dev server independently. The Go server does not need to be rebuilt for frontend-only changes during development.

## Confirmation

**Embed directive -- `cmd/relay-server/serve.go` (line 22-23):**

```go
//go:embed dist/*
var distFS embed.FS
```

**Frontend struct -- `cmd/relay-server/frontend.go` (line 28-36):**

The `Frontend` struct wraps the embedded `distFS` and provides methods for serving assets, injecting SSR data, and handling SPA fallback routing.

**Serving methods -- `cmd/relay-server/frontend.go`:**

- `ServeAppStatic()` (line 338) serves React app files from `/app/`, falling back to `portal.html` with SSR data for SPA routing.
- `ServePortalHTMLWithSSR()` (line 104) serves `portal.html` for subdomain requests with OG metadata extracted from the matching lease.
- `servePortalHTMLWithSSR()` (line 74) serves `portal.html` for the main app with SSR data injection (lease rows as JSON in a `<script>` tag).
- `injectOGMetadata()` (line 151) replaces `[%OG_TITLE%]`, `[%OG_DESCRIPTION%]`, `[%OG_IMAGE_URL%]` placeholders.
- `injectServerData()` (line 176) marshals lease rows to JSON and injects a `<script id="__SSR_DATA__">` tag.

**Build pipeline -- `Dockerfile` (lines 14-15):**

```dockerfile
RUN cd cmd/relay-server/frontend && npm ci && npm run build
```

The frontend is built first, producing output in `cmd/relay-server/dist/app/`. The subsequent `go build` step embeds this output via `//go:embed dist/*`.

**Makefile targets:**

- `make build-frontend` runs `cd cmd/relay-server/frontend && npm run build`.
- `make frontend` runs lint then build.
- `make build` runs `go build ./...`, which embeds the pre-built frontend.
