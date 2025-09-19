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

// Static frontend files
app.use(express.static('public'));

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
    ['script', 'src'],
    ['iframe', 'src'],
    ['form', 'action'],
    ['source', 'src'],
    ['video', 'src'],
    ['audio', 'src']
  ];

  // helper to resolve and rewrite
  function rewriteAttr(elem, attr) {
    const orig = $(elem).attr(attr);
    if (!orig) return;
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

  // inject a small script to rewrite XHR/fetch requests to go through proxy if needed
  const xhrPatch = `
  <script>
    (function(){
      const origFetch = window.fetch;
      window.fetch = function(input, init){
        try{
          let u = (typeof input === 'string') ? input : input.url;
          if (u && (u.startsWith('http:') || u.startsWith('https:')) && !u.startsWith(location.origin)) {
            // route through proxy endpoint
            const prox = '/proxy?url=' + encodeURIComponent(u);
            if (typeof input === 'string') return origFetch(prox, init);
            input = new Request(prox, input);
          }
        } catch(e){}
        return origFetch(input, init);
      };

      // override XMLHttpRequest open to rewrite absolute URLs
      const origOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, urlArg){
        try{
          if (typeof urlArg === 'string' && (urlArg.startsWith('http:') || urlArg.startsWith('https:')) && !urlArg.startsWith(location.origin)) {
            arguments[1] = '/proxy?url=' + encodeURIComponent(urlArg);
          }
        }catch(e){}
        return origOpen.apply(this, arguments);
      };
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

  // Build fetch options from incoming request
  const fetchOptions = {
    method: req.method,
    headers: Object.assign({}, req.headers),
    redirect: 'follow',
    compress: true,
  };

  // Remove host header to prevent issues
  delete fetchOptions.headers.host;
  // Remove our own cookies when forwarding unless you have a reason
  // delete fetchOptions.headers.cookie;

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
  try {
    const r = await fetch(target);
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

  // Build a fake request for proxying; http-proxy can use the original req
  try {
    proxy.ws(req, socket, head, { target: targetUrl, changeOrigin: true }, (err) => {
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
