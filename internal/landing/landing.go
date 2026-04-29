// Package landing serves a minimal HTML landing page for humans who
// browse the public URL. The interchange is content-blind transit
// infrastructure; the landing page exists so a passing browser doesn't
// see Go's default 404 (which leaks framework identity) and so a human
// who finds the URL can tell what it is.
//
// Intentionally reveals nothing operational: no interchange_id, no
// version, no internal endpoints beyond what /.well-known/nexus-interchange
// already publishes.
package landing

import (
	"net/http"
	"strings"
)

// Handler returns the landing page handler. Only matches the exact
// path "/"; any other path falls through to the next mux entry (or
// 404 from the default mux). MethodNotAllowed for non-GET.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only match the literal root. Without this, "/" in a ServeMux
		// would also catch unmatched paths like "/foo" because Go's
		// default mux treats "/" as a prefix.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		// Strict CSP — inline styles only (the placeholder needs them);
		// no scripts, no remote resources, no framing.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write([]byte(pageHTML))
	}
}

// pageHTML is the static landing page. Single file, no external
// resources, dark theme. The placeholder hero is a CSS+SVG diagram of
// two paired endpoints linked through a content-blind relay; swap the
// <svg> block for a maren-authored asset when delivered.
var pageHTML = strings.TrimLeft(`
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Interchange</title>
<style>
  :root {
    --bg: #0c1014;
    --fg: #d8dee4;
    --dim: #6b7280;
    --accent: #6ec1ff;
    --node: #b9c4d0;
    --line: #2a3540;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--fg);
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 8vh 1.5rem 4vh;
  }
  main { max-width: 720px; width: 100%; }
  h1 {
    font-weight: 200;
    font-size: clamp(2.5rem, 6vw, 4rem);
    letter-spacing: 0.02em;
    margin: 0 0 0.5rem;
  }
  .tagline {
    color: var(--dim);
    font-size: 1rem;
    margin: 0 0 3rem;
  }
  .hero {
    width: 100%;
    aspect-ratio: 12 / 5;
    margin: 0 0 3rem;
    background: linear-gradient(180deg, #0e141a 0%, #0a0e12 100%);
    border: 1px solid var(--line);
    border-radius: 6px;
    overflow: hidden;
  }
  .hero svg { width: 100%; height: 100%; display: block; }
  .links {
    border-top: 1px solid var(--line);
    padding-top: 1.5rem;
    color: var(--dim);
    font-size: 0.9rem;
  }
  .links a {
    color: var(--accent);
    text-decoration: none;
  }
  .links a:hover { text-decoration: underline; }
  .footer {
    margin-top: auto;
    padding-top: 4rem;
    color: var(--dim);
    font-size: 0.8rem;
    text-align: center;
  }
</style>
</head>
<body>
<main>
  <h1>Interchange</h1>
  <p class="tagline">Content-blind relay between paired Nexuses.</p>

  <div class="hero" aria-label="Two paired Nexuses linked through a content-blind relay">
    <svg viewBox="0 0 1200 500" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
      <!-- The line: encrypted channel passing through the relay -->
      <line x1="180" y1="250" x2="600" y2="250" stroke="#2a3540" stroke-width="1.5" stroke-dasharray="4 6"/>
      <line x1="600" y1="250" x2="1020" y2="250" stroke="#2a3540" stroke-width="1.5" stroke-dasharray="4 6"/>

      <!-- Endpoint A -->
      <circle cx="180" cy="250" r="48" fill="none" stroke="#b9c4d0" stroke-width="1.5"/>
      <circle cx="180" cy="250" r="3" fill="#b9c4d0"/>

      <!-- Relay (centre, smaller, hollow — content-blind) -->
      <circle cx="600" cy="250" r="20" fill="none" stroke="#6ec1ff" stroke-width="1.5"/>
      <line x1="588" y1="250" x2="612" y2="250" stroke="#6ec1ff" stroke-width="1.2"/>

      <!-- Endpoint B -->
      <circle cx="1020" cy="250" r="48" fill="none" stroke="#b9c4d0" stroke-width="1.5"/>
      <circle cx="1020" cy="250" r="3" fill="#b9c4d0"/>

      <!-- Faint grid for texture -->
      <g stroke="#141a21" stroke-width="0.6" opacity="0.7">
        <line x1="0" y1="100" x2="1200" y2="100"/>
        <line x1="0" y1="400" x2="1200" y2="400"/>
        <line x1="300" y1="0" x2="300" y2="500"/>
        <line x1="900" y1="0" x2="900" y2="500"/>
      </g>
    </svg>
  </div>

  <p class="links">
    Source &amp; protocol: <a href="https://github.com/nexus-cw/interchange">github.com/nexus-cw/interchange</a><br>
    Discovery: <a href="/.well-known/nexus-interchange">/.well-known/nexus-interchange</a>
  </p>
</main>

<footer class="footer">
  This relay sees ciphertext only. It cannot read messages it carries.
</footer>
</body>
</html>
`, "\n")
