/**
 * server.js
 * Run: npm install
 * then: PROXY_USER=student PROXY_PASS=classpass node server.js
 *
 * Features:
 * - / -> static frontend (public/index.html)
 * - /proxy?url=<encodedURL> for GET/POST/etc (server-side fetch & HTML rewriting)
 * - /raw?url=... for raw passthrough (no HTML rewriting)
 * - WebSocket proxy support via upgrade handling for /ws?url=ws://...
 * - Basic auth (optional via PROXY_USER / PROXY_PASS)
 * - Rate limiting
 *
 * NOTE: Use this only for a teacher-approved class project. Log/document school permission.
 */

const express = require('express');
const fetch = require('node-fetch'); // v2
const cheerio = require('cheerio');
const httpProxy = require('http-proxy');
const rateLimit = require('express-rate-limit');
const basicAuth = require('basic-auth');
const morgan = require('morgan');
const url = require('url');
const { pipeline } = require('stream');
const { createServer } = require('http');
const path = require('path');

const PORT = process.env.PORT || 8080;
const AUTH_USER = process.env.PROXY_USER || null; // set to enable basic auth
const AUTH_PASS = process.env.PROXY_PASS || null;

const app = express();
const server = createServer(app);
const proxy = httpProxy.createProxyServer({
  ws: true,
  xfwd: true,
});

// Logging
app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // per IP per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.set('trust proxy', 1);

// Simple auth middleware (if credentials set)
function authMiddleware(req, res, next) {
  if (!AUTH_USER || !AUTH_PASS) return next();
  const creds = basicAuth(req);
  if (!creds || creds.name !== AUTH_USER || creds.pass !== AUTH_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Proxy Demo"');
    return res.status(401).send('Access denied');
  }
  return next();
}
app.use(authMiddleware);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const ALLOWLIST = (process.env.PROXY_ALLOWLIST || '')
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean);

function hostAllowed(hostname) {
  if (!ALLOWLIST.length) return true;
  return ALLOWLIST.some((entry) => {
    if (entry === '*') return true;
    if (entry.startsWith('.')) {
      const suffix = entry.slice(1);
      return hostname === suffix || hostname.endsWith(`.${suffix}`);
    }
    return hostname === entry;
  });
}

// Utility: build proxy URL for links
function proxyFor(targetUrl) {
  return `/proxy?url=${encodeURIComponent(targetUrl)}`;
}

// Rewrite HTML so all links/resources point back through our proxy
async function rewriteHtmlBody(htmlText, baseUrl) {
  const $ = cheerio.load(htmlText, { decodeEntities: false });

  // elements & attributes to rewrite
  const attrs = [
    ['a', 'href'],
    ['link', 'href'],
    ['img', 'src'],
    ['img', 'srcset'],
    ['script', 'src'],
    ['iframe', 'src'],
    ['form', 'action'],
    ['source', 'src'],
    ['source', 'srcset'],
    ['video', 'src'],
    ['audio', 'src'],
    ['video', 'poster'],
    ['audio', 'poster'],
    ['object', 'data']
  ];

  // helper to resolve and rewrite
  function rewriteAttr(elem, attr) {
    const orig = $(elem).attr(attr);
    if (!orig) return;
    if (attr === 'srcset') {
      const rewrittenSrcset = orig
        .split(',')
        .map((segment) => {
          const trimmed = segment.trim();
          if (!trimmed) return trimmed;
          const parts = trimmed.split(/\s+/);
          const urlPart = parts.shift();
          if (!urlPart) return trimmed;
          try {
            const resolved = new url.URL(urlPart, baseUrl).toString();
            const proxied = proxyFor(resolved);
            return [proxied, ...parts].join(' ');
          } catch (e) {
            return trimmed;
          }
        })
        .join(', ');
      $(elem).attr(attr, rewrittenSrcset);
      return;
    }
    try {
      const resolved = new url.URL(orig, baseUrl).toString();
      $(elem).attr(attr, proxyFor(resolved));
    } catch (e) {
      // ignore invalid urls (like javascript: or mailto:)
    }
  }

  attrs.forEach(([tag, attribute]) => {
    $(tag).each((i, el) => rewriteAttr(el, attribute));
  });

  // rewrite inline CSS url(...) occurrences in style attributes or style tags
  $('[style]').each((i, el) => {
    let s = $(el).attr('style');
    s = s.replace(/url\(['"]?([^'")]+)['"]?\)/g, (m, p1) => {
      try {
        const r = new url.URL(p1, baseUrl).toString();
        return `url(${proxyFor(r)})`;
      } catch (e) {
        return m;
      }
    });
    $(el).attr('style', s);
  });

  $('style').each((i, el) => {
    let text = $(el).html();
    text = text.replace(/url\(['"]?([^'")]+)['"]?\)/g, (m, p1) => {
      try {
        const r = new url.URL(p1, baseUrl).toString();
        return `url(${proxyFor(r)})`;
      } catch (e) {
        return m;
      }
    });
    $(el).html(text);
  });

  // Remove integrity attributes that will fail after rewriting
  $('[integrity]').removeAttr('integrity');

  // Rewrite <base> tags to ensure they keep routing through the proxy
  $('base[href]').each((i, el) => {
    const href = $(el).attr('href');
    try {
      const resolved = new url.URL(href, baseUrl).toString();
      $(el).attr('href', proxyFor(resolved));
    } catch (e) {
      $(el).remove();
    }
  });

  // Strip client-side CSP or frame blocking meta tags
  $('meta[http-equiv]').each((i, el) => {
    const value = ($(el).attr('http-equiv') || '').toLowerCase();
    if (['content-security-policy', 'x-frame-options', 'frame-ancestors'].includes(value)) {
      $(el).remove();
      return;
    }
    if (value === 'refresh') {
      const content = $(el).attr('content');
      if (!content) return;
      const match = content.match(/^(\s*\d+\s*;\s*url=)(.+)$/i);
      if (match) {
        try {
          const resolved = new url.URL(match[2], baseUrl).toString();
          $(el).attr('content', `${match[1]}${proxyFor(resolved)}`);
        } catch (e) {
          // leave content as-is when invalid
        }
      }
    }
  });

  // inject a small script to rewrite XHR/fetch requests to go through proxy if needed
  const xhrPatch = `
  <script>
    (function(){
      const rewriteAbsolute = (inputUrl) => {
        if (!inputUrl) return inputUrl;
        if (inputUrl.startsWith('/proxy?url=') || inputUrl.startsWith('/ws?url=')) return inputUrl;
        if (/^https?:/i.test(inputUrl) && !inputUrl.startsWith(window.location.origin)) {
          return '/proxy?url=' + encodeURIComponent(inputUrl);
        }
        if (/^wss?:/i.test(inputUrl) && !inputUrl.startsWith(window.location.origin)) {
          return '/ws?url=' + encodeURIComponent(inputUrl);
        }
        return inputUrl;
      };

      const origFetch = window.fetch;
      window.fetch = function(input, init){
        try{
          let u = (typeof input === 'string') ? input : input.url;
          if (u) {
            const prox = rewriteAbsolute(u);
            if (prox !== u) {
              if (typeof input === 'string') return origFetch(prox, init);
              input = new Request(prox, input);
            }
          }
        } catch(e){}
        return origFetch(input, init);
      };

      // override XMLHttpRequest open to rewrite absolute URLs
      const origOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, urlArg){
        try{
          if (typeof urlArg === 'string') {
            const prox = rewriteAbsolute(urlArg);
            if (prox !== urlArg) arguments[1] = prox;
          }
        }catch(e){}
        return origOpen.apply(this, arguments);
      };

      const origOpenWindow = window.open;
      window.open = function(target, name, specs){
        if (typeof target === 'string') {
          const prox = rewriteAbsolute(target);
          if (prox !== target) target = prox;
        }
        return origOpenWindow ? origOpenWindow.call(this, target, name, specs) : null;
      };

      const assignLike = (fn) => function(url){
        const original = String(url);
        const prox = rewriteAbsolute(original);
        return fn.call(this, prox === original ? url : prox);
      };
      const loc = window.location;
      if (loc) {
        if (typeof loc.assign === 'function') loc.assign = assignLike(loc.assign);
        if (typeof loc.replace === 'function') loc.replace = assignLike(loc.replace);
        const hrefDescriptor = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
        if (hrefDescriptor && typeof hrefDescriptor.set === 'function') {
          Object.defineProperty(loc, 'href', {
            configurable: false,
            enumerable: false,
            set(value){
              const original = String(value);
              const prox = rewriteAbsolute(original);
              return hrefDescriptor.set.call(loc, prox === original ? value : prox);
            },
            get(){
              return hrefDescriptor.get.call(loc);
            }
          });
        }
      }

      const origPushState = history.pushState;
      history.pushState = function(state, title, urlArg){
        if (urlArg != null) {
          const original = String(urlArg);
          const prox = rewriteAbsolute(original);
          if (prox !== original) urlArg = prox;
        }
        return origPushState.call(this, state, title, urlArg);
      };

      const origReplaceState = history.replaceState;
      history.replaceState = function(state, title, urlArg){
        if (urlArg != null) {
          const original = String(urlArg);
          const prox = rewriteAbsolute(original);
          if (prox !== original) urlArg = prox;
        }
        return origReplaceState.call(this, state, title, urlArg);
      };

      const NativeWebSocket = window.WebSocket;
      if (NativeWebSocket) {
        const WrappedWebSocket = function(target, protocols){
          if (typeof target === 'string') {
            const prox = rewriteAbsolute(target);
            if (prox !== target) target = prox;
          }
          return new NativeWebSocket(target, protocols);
        };
        WrappedWebSocket.prototype = NativeWebSocket.prototype;
        window.WebSocket = WrappedWebSocket;
      }

      const NativeEventSource = window.EventSource;
      if (NativeEventSource) {
        const WrappedEventSource = function(target, init){
          if (typeof target === 'string') {
            const prox = rewriteAbsolute(target);
            if (prox !== target) target = prox;
          }
          return new NativeEventSource(target, init);
        };
        WrappedEventSource.prototype = NativeEventSource.prototype;
        window.EventSource = WrappedEventSource;
      }
    })();
  </script>
  `;
  $('head').prepend(xhrPatch);

  return $.html();
}

// Helper: copy response headers but remove unsafe/frame-blocking ones
function sanitizeHeaders(originalHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(originalHeaders)) {
    const key = k.toLowerCase();
    if (['x-frame-options', 'content-security-policy', 'frame-ancestors'].includes(key)) continue;
    // Do not forward set-cookie as-is to avoid domain mismatch issues (you may forward carefully if needed)
    if (key === 'set-cookie') continue;
    out[k] = v;
  }
  // Ensure the content is served from our server origin
  out['x-proxied-by'] = 'school-proxy-project';
  return out;
}

// Universal proxy handler that supports all methods
app.all('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('Missing url param');

  let parsed;
  try {
    parsed = new url.URL(target);
  } catch (e) {
    return res.status(400).send('Invalid target URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).send('Only http and https protocols are supported');
  }

  if (!hostAllowed(parsed.hostname)) {
    return res.status(403).send('Target host is not permitted');
  }

  // Build fetch options from incoming request
  const outgoingHeaders = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lower = key.toLowerCase();
    if (['host', 'content-length', 'connection'].includes(lower)) continue;
    if (lower === 'accept-encoding') continue;
    outgoingHeaders[key] = value;
  }
  outgoingHeaders['referer'] = parsed.toString();
  outgoingHeaders['origin'] = parsed.origin;

  const fetchOptions = {
    method: req.method,
    headers: outgoingHeaders,
    redirect: 'follow',
    compress: true,
  };

  // For POST/PUT, pipe body
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'DELETE') {
    // pipe body into fetch. node-fetch v2 can't stream request body from req directly easily
    // so we'll accumulate small bodies (suitable for forms/APIs). For larger uploads you'd need more code.
    try {
      const body = await new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
      });
      if (body && body.length) fetchOptions.body = body;
    } catch (err) {
      console.error('Error reading request body', err);
    }
  }

  // Fetch target
  let upstream;
  try {
    upstream = await fetch(target, fetchOptions);
  } catch (err) {
    console.error('Fetch error', err);
    return res.status(502).send('Bad gateway: ' + err.message);
  }

  // Sanitize and set headers
  const headers = sanitizeHeaders(Object.fromEntries(upstream.headers.entries()));
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);

  const contentType = upstream.headers.get('content-type') || '';
  if (contentType.includes('text/html')) {
    // rewrite HTML
    const text = await upstream.text();
    const rewritten = await rewriteHtmlBody(text, target);
    res.setHeader('content-type', 'text/html; charset=utf-8');
    return res.status(upstream.status).send(rewritten);
  } else {
    // Stream other content (images, CSS, JS, video, etc.)
    res.status(upstream.status);
    // proxy headers already set
    const bodyStream = upstream.body;
    if (!bodyStream) return res.end();
    return pipeline(bodyStream, res, (err) => {
      if (err) {
        console.error('Stream pipeline error:', err);
      }
    });
  }
});

// Raw passthrough (no rewriting) for cases you want direct streaming
app.get('/raw', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('Missing url param');
  let parsed;
  try {
    parsed = new url.URL(target);
  } catch (e) {
    return res.status(400).send('Invalid target URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).send('Only http and https protocols are supported');
  }

  if (!hostAllowed(parsed.hostname)) {
    return res.status(403).send('Target host is not permitted');
  }

  try {
    const r = await fetch(parsed.toString());
    const headers = sanitizeHeaders(Object.fromEntries(r.headers.entries()));
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.status(r.status);
    const bodyStream = r.body;
    if (!bodyStream) return res.end();
    return pipeline(bodyStream, res, (err) => {
      if (err) console.error('raw pipeline err', err);
    });
  } catch (e) {
    console.error(e);
    return res.status(502).send('Bad gateway: ' + e.message);
  }
});

// WebSocket proxying: clients connect to ws://yourproxy/ws?url=ws://target/...
// We'll proxy the upgrade to the remote websocket target
server.on('upgrade', (req, socket, head) => {
  const pathname = new url.URL(req.url, `http://${req.headers.host}`).pathname;
  if (!req.url) return socket.destroy();
  const u = new url.URL(req.url, `http://${req.headers.host}`);
  if (u.pathname !== '/ws') {
    // ignore other upgrades
    socket.destroy();
    return;
  }
  const targetUrl = u.searchParams.get('url');
  if (!targetUrl) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  let parsed;
  try {
    parsed = new url.URL(targetUrl);
  } catch (e) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  if (!['ws:', 'wss:'].includes(parsed.protocol)) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  if (!hostAllowed(parsed.hostname)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }

  // Build a fake request for proxying; http-proxy can use the original req
  try {
    proxy.ws(req, socket, head, { target: parsed.toString(), changeOrigin: true }, (err) => {
      if (err) {
        console.error('ws proxy err', err);
        try { socket.end(); } catch (e) {}
      }
    });
  } catch (err) {
    console.error('upgrade error', err);
    try { socket.destroy(); } catch (e) {}
  }
});

// Basic endpoint for demo status
app.get('/status', (req, res) => {
  res.json({ ok: true, pid: process.pid, env: { auth: !!AUTH_USER } });
});

// Fallback
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// Start server
server.listen(PORT, () => {
  console.log(`Proxy server listening on http://0.0.0.0:${PORT} (PID ${process.pid})`);
  if (AUTH_USER) console.log(`Basic auth is ON. User=${AUTH_USER}`);
});
