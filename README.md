# Quiet Portal Proxy

A class-approved web proxy that keeps the browser address bar anchored to your host while presenting a sleek, post-modern interface. It rewrites navigation to flow through `/proxy?url=…`, neutralizes frame-busting headers, and presents a customizable floating toolbar for quick actions. Always make sure you have written permission from staff before using or deploying this project.

## Quick start

```bash
npm install
npm start
```

The server listens on port `8080` by default. Visit `http://localhost:8080/` in a modern browser.

### Development mode

For a reload-friendly workflow on Node.js 18+, you can run:

```bash
npm run dev
```

This uses Node's built-in `--watch` flag.

### Optional access control

Set `PROXY_USER` and `PROXY_PASS` to require HTTP Basic Auth:

```bash
PROXY_USER=student PROXY_PASS=classpass npm start
```

To enable a hostname allowlist, provide a comma-separated list via `PROXY_ALLOWLIST`. Accepts exact hosts, wildcard subdomains (prefix with a dot), or `*`:

```bash
PROXY_ALLOWLIST="k12guru.nl,.yandex.com" npm start
```

Requests targeting hosts outside the allowlist return `403`.

## How it works

* **Express proxy endpoint** – `/proxy` forwards HTTP(S) requests with streaming support for non-HTML content. `/raw` keeps assets untouched.
* **HTML rewriting** – Anchor tags, forms, scripts, images, media posters, `srcset`, inline CSS `url()`, and `<base>` tags all point back through `/proxy`. Client-side patches also reroute `fetch`, `XMLHttpRequest`, history APIs, `window.open`, WebSockets, and EventSource calls.
* **Header sanitation** – Server responses drop `X-Frame-Options`, CSP, and frame-ancestor headers so the iframe can render. `Set-Cookie` is skipped for safety.
* **WebSocket passthrough** – `/ws?url=…` upgrades tunnel real-time connections.
* **Floating UI shell** – The front-end keeps the primary iframe on your origin, provides a toggle-able screen cover, and drives curated links through neutral `about:blank` tabs that embed the proxied destination.

## Customizing the interface

* **Home destination** – Update `HOME_URL` near the top of `index.html` to change the default landing page.
* **Toolbar art** – The CSS variables `--hide-art`, `--home-art`, `--menu-art`, and `--overlay-art` point to your Cloudinary-hosted assets. Swap them with your preferred artwork (animated GIFs, PNGs, etc.).
* **Menu links** – Edit the `curatedLinks` array in `index.html` to tailor the quick menu labels and URLs. Each button opens an `about:blank` shell containing a proxied iframe so the browser address bar never reveals the external site.
* **Allowlist** – Use `PROXY_ALLOWLIST` (see above) if an administrator wants to restrict outbound hosts during a demo.

## Troubleshooting

* **Blank or partially loaded pages** – Some destinations rely on strict CSP, DRM, or service workers that resist HTML rewriting. Try refreshing with cache disabled or use `/raw` for assets that do not require modification.
* **Sign-in or cookie issues** – Cross-origin cookies with strict flags are not forwarded by default. This is intentional to avoid leaking credentials across domains.
* **Pop-up warning** – Browsers may prevent `about:blank` tabs from opening. Allow pop-ups from your proxy host so the quick menu can spawn neutral windows.
* **WebSocket hiccups** – Confirm the target supports ws/wss and, if using an allowlist, that the host is included.

## Ethics & safety

Operate this proxy only with explicit authorization. Do not use it to bypass school policies outside of supervised demonstrations. Keep administrators informed, document consent, and disable the service when class projects conclude.
