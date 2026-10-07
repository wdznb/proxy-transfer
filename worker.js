/**
 * Cloudflare Worker：分段代理下载 + 流式写入硬盘 + 断点续传
 */

const CHUNK_SIZE = 2 * 1024 * 1024;              // 2MB 分片
const DB_NAME = 'cf-downloader-db';
const DB_VERSION = 3;
const STORE_META = 'meta';
const CHUNK_TIMEOUT_MS = 60000;
const PROBE_TIMEOUT_MS = 30000;
const MAX_RETRIES = 3;
const STALE_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const META_FLUSH_INTERVAL_MS = 3000;
const META_FLUSH_CHUNK_COUNT = 5;
const MAX_REDIRECTS = 3;

// ==================== Worker 入口 ====================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/index.html') {
      return new Response(getHTML(), {
        headers: {
          'Content-Type': 'text/html;charset=utf-8',
          'Cache-Control': 'no-store',
          'Referrer-Policy': 'same-origin',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    if (url.pathname === '/proxy') {
      return handleProxy(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};

// ==================== SSRF 防护 ====================
function extractMappedIPv4(ipv6) {
  let lower = ipv6.toLowerCase().replace(/^\[|\]$/g, '');

  var m1 = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (m1) return m1[1];

  var m2 = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (m2) {
    var hi = parseInt(m2[1], 16);
    var lo = parseInt(m2[2], 16);
    return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff].join('.');
  }

  var m3 = lower.match(/^0:0:0:0:0:ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (m3) {
    var hi3 = parseInt(m3[1], 16);
    var lo3 = parseInt(m3[2], 16);
    return [(hi3 >> 8) & 0xff, hi3 & 0xff, (lo3 >> 8) & 0xff, lo3 & 0xff].join('.');
  }

  return null;
}

function isPrivateIPv4(ip) {
  var parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(function (p) { return isNaN(p) || p < 0 || p > 255; })) return true;
  var a = parts[0], b = parts[1], c = parts[2];

  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;

  return false;
}

function isPrivateHostname(hostname) {
  let lower = hostname.toLowerCase();
  if (lower.endsWith('.')) lower = lower.slice(0, -1);
  if (!lower) return true;

  if (lower === 'localhost' || lower === 'localhost.localdomain') return true;
  if (/\.(local|internal|lan|corp|home|localdomain)$/i.test(lower)) return true;
  if (lower === 'metadata.google.internal' || lower === 'metadata') return true;

  if (/^\d+$/.test(lower)) return true;
  if (/^0x[0-9a-f]+$/i.test(lower)) return true;

  var v4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) return isPrivateIPv4(lower);

  var v6 = lower.replace(/^\[|\]$/g, '');
  var mapped = extractMappedIPv4(v6);
  if (mapped) return isPrivateIPv4(mapped);

  if (v6 === '::' || v6 === '::1') return true;
  if (/^fe[89ab][0-9a-f]:/i.test(v6)) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(v6)) return true;

  return false;
}

async function resolveAndValidateDNS(hostname) {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
  if (hostname.includes(':') || hostname.includes('[')) return true;

  var dohUrl = 'https://cloudflare-dns.com/dns-query?name=' +
    encodeURIComponent(hostname) + '&type=A';

  try {
    var resp = await fetch(dohUrl, {
      headers: { 'Accept': 'application/dns-json' },
      cf: { cacheTtl: 300 },
    });
    if (!resp.ok) return true;

    var data = await resp.json();
    if (!data.Answer || !Array.isArray(data.Answer)) return true;

    for (var i = 0; i < data.Answer.length; i++) {
      var answer = data.Answer[i];
      if (answer.type === 1 && answer.data) {
        if (isPrivateIPv4(answer.data)) {
          return false;
        }
      }
    }
    return true;
  } catch (e) {
    return true;
  }
}

async function validateTargetUrl(targetUrl) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (e) {
    throw new Error('无效的目标 URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('仅允许 http/https 协议');
  }
  if (!parsed.hostname) {
    throw new Error('目标 URL 缺少主机名');
  }
  if (isPrivateHostname(parsed.hostname)) {
    throw new Error('禁止访问内网或保留地址');
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    throw new Error('仅允许 80/443 端口');
  }

  var dnsOk = await resolveAndValidateDNS(parsed.hostname);
  if (!dnsOk) {
    throw new Error('域名解析到内网地址，已拦截');
  }

  return parsed;
}

// ==================== 认证与 CORS ====================
function getAllowedOrigins(env) {
  if (env && env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  }
  return [];
}

function checkAuth(request, env) {
  if (env && env.DISABLE_AUTH === 'true') return true;

  var expectedToken = env && env.AUTH_TOKEN;
  if (!expectedToken) return false;

  var authValue = request.headers.get('X-Downloader-Auth');
  if (authValue !== expectedToken) return false;

  try {
    var expectedOrigins = getAllowedOrigins(env);
    var workerOrigin = new URL(request.url).origin;
    expectedOrigins.push(workerOrigin);

    var origin = request.headers.get('Origin');
    var referer = request.headers.get('Referer');

    if (origin) {
      return expectedOrigins.indexOf(origin) !== -1;
    }
    if (referer) {
      var refOrigin = new URL(referer).origin;
      return expectedOrigins.indexOf(refOrigin) !== -1;
    }
    return false;
  } catch (e) {
    return false;
  }
}

function corsHeaders(request, env) {
  var origin = request.headers.get('Origin') || '';
  var allowed = getAllowedOrigins(env);
  var workerOrigin = new URL(request.url).origin;
  allowed.push(workerOrigin);

  var allowOrigin = allowed.indexOf(origin) !== -1 ? origin : workerOrigin;

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, If-Range, X-Downloader-Auth',
    'Access-Control-Expose-Headers':
      'Content-Range, Content-Length, Accept-Ranges, ETag, Last-Modified, Content-Disposition',
    'Cache-Control': 'no-store',
    'Vary': 'Origin',
  };
}

// ==================== 手动重定向处理 ====================
async function fetchWithManualRedirect(targetUrl, options, maxRedirects, env) {
  var currentUrl = targetUrl;
  var redirectCount = 0;

  while (redirectCount <= maxRedirects) {
    if (redirectCount > 0) {
      try {
        await validateTargetUrl(currentUrl);
      } catch (e) {
        throw new Error('重定向目标被 SSRF 拦截: ' + e.message);
      }
    }

    var resp = await fetch(currentUrl, Object.assign({}, options, {
      redirect: 'manual',
    }));

    if (resp.status < 300 || resp.status >= 400) {
      return resp;
    }

    var location = resp.headers.get('Location');
    if (!location) {
      return resp;
    }

    try {
      currentUrl = new URL(location, currentUrl).toString();
    } catch (e) {
      throw new Error('无效的重定向 Location: ' + location);
    }

    redirectCount++;

    if (redirectCount > maxRedirects) {
      throw new Error('重定向次数超过上限 (' + maxRedirects + ')');
    }
  }

  throw new Error('重定向处理异常');
}

// ==================== 后端代理逻辑 ====================
async function handleProxy(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  if (!checkAuth(request, env)) {
    return new Response('未授权访问', { status: 403, headers: corsHeaders(request, env) });
  }

  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  if (!targetUrl) {
    return new Response('缺少 url 参数', { status: 400, headers: corsHeaders(request, env) });
  }

  try {
    await validateTargetUrl(targetUrl);
  } catch (e) {
    return new Response(e.message, { status: 400, headers: corsHeaders(request, env) });
  }

  const forwardHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    const lower = key.toLowerCase();
    if (lower === 'range' || lower === 'if-range') {
      forwardHeaders.set(key, value);
    }
  }
  forwardHeaders.set('Accept-Encoding', 'identity');

  try {
    const upstream = await fetchWithManualRedirect(targetUrl, {
      method: 'GET',
      headers: forwardHeaders,
      cf: { cacheEverything: false, cacheTtl: 0 },
    }, MAX_REDIRECTS, env);

    const responseHeaders = new Headers();
    const passthrough = [
      'content-type',
      'content-range',
      'accept-ranges',
      'etag',
      'last-modified',
      'content-disposition',
    ];
    for (const name of passthrough) {
      const val = upstream.headers.get(name);
      if (val) responseHeaders.set(name, val);
    }

    responseHeaders.delete('content-encoding');
    responseHeaders.delete('transfer-encoding');
    responseHeaders.delete('content-length');

    for (const [k, v] of Object.entries(corsHeaders(request, env))) {
      responseHeaders.set(k, v);
    }

    let expectedLength = null;
    const contentRange = upstream.headers.get('content-range');
    if (contentRange) {
      const m = contentRange.match(/bytes\s+(\d+)-(\d+)\/(\d+|\*)/);
      if (m) {
        const start = parseInt(m[1], 10);
        const end = parseInt(m[2], 10);
        expectedLength = end - start + 1;
      }
    }
    if (!expectedLength) {
      const cl = upstream.headers.get('content-length');
      if (cl) {
        const parsedCl = parseInt(cl, 10);
        if (!isNaN(parsedCl) && parsedCl > 0) expectedLength = parsedCl;
      }
    }

    if (expectedLength && expectedLength > 0) {
      const { readable, writable } = new FixedLengthStream(expectedLength);
      upstream.body.pipeTo(writable).catch(() => {});
      return new Response(readable, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders,
      });
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch (e) {
    return new Response('代理请求失败: ' + e.message, { status: 502, headers: corsHeaders(request, env) });
  }
}

// ==================== 前端 HTML ====================
function getHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>分段代理下载器（流式写盘）</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 20px; color: #1a1a2e; background: #f8f9fa; }
  h1 { font-size: 1.4rem; margin-bottom: 24px; }
  .card { background: #fff; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 20px; }
  label { display: block; font-size: .85rem; color: #555; margin-bottom: 6px; font-weight: 500; }
  input[type="text"] { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: .95rem; outline: none; }
  input[type="text"]:focus { border-color: #4a6cf7; box-shadow: 0 0 0 3px rgba(74,108,247,.12); }
  .row { display: flex; gap: 10px; margin-top: 14px; }
  button { flex: 1; padding: 11px 18px; border: none; border-radius: 8px; font-size: .95rem; font-weight: 600; cursor: pointer; transition: all .15s; }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .btn-primary { background: #4a6cf7; color: #fff; }
  .btn-primary:hover:not(:disabled) { background: #3b5de7; }
  .btn-danger { background: #ef4444; color: #fff; flex: 0 0 auto; padding: 11px 20px; }
  .btn-danger:hover:not(:disabled) { background: #dc2626; }
  .progress-wrap { margin-top: 18px; display: none; }
  .progress-wrap.active { display: block; }
  .progress-bar-bg { height: 10px; background: #e9ecef; border-radius: 5px; overflow: hidden; }
  .progress-bar-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #4a6cf7, #7c8cf8); border-radius: 5px; transition: width .25s ease; }
  .progress-text { display: flex; justify-content: space-between; font-size: .82rem; color: #666; margin-top: 8px; }
  .status { font-size: .85rem; margin-top: 10px; min-height: 1.2em; }
  .status.ok { color: #16a34a; }
  .status.err { color: #dc2626; }
  .status.info { color: #4a6cf7; }
  .hint { font-size: .78rem; color: #888; margin-top: 8px; line-height: 1.5; }
</style>
</head>
<body>

<h1>🔽 分段代理下载器（流式写盘）</h1>

<div class="card">
  <label for="urlInput">文件直链地址</label>
  <input type="text" id="urlInput" placeholder="https://example.com/large-file.zip" autocomplete="off">

  <div class="row">
    <button class="btn-primary" id="startBtn" onclick="startDownload()">开始下载</button>
    <button class="btn-danger" id="cancelBtn" onclick="cancelDownload()" disabled>取消</button>
  </div>

  <div class="progress-wrap" id="progressWrap">
    <div class="progress-bar-bg">
      <div class="progress-bar-fill" id="progressFill"></div>
    </div>
    <div class="progress-text">
      <span id="progressLabel">等待中…</span>
      <span id="progressPct">0%</span>
    </div>
  </div>

  <div class="status" id="statusMsg"></div>
  <div class="hint">
    提示：每下载完一片会立即写入你选择的文件。刷新页面后重新输入同一地址，会自动续传。
    需 Chrome / Edge 等支持 File System Access API 的浏览器。<br>
    安全提示：本页面会将文件句柄保存在浏览器 IndexedDB 中以实现自动续传。若在公用设备使用，请及时清理浏览器数据。
  </div>
</div>

<script>
// ==================== 常量（由 Worker 注入） ====================
var CHUNK_SIZE = ${CHUNK_SIZE};
var DB_NAME = '${DB_NAME}';
var DB_VERSION = ${DB_VERSION};
var STORE_META = '${STORE_META}';
var CHUNK_TIMEOUT_MS = ${CHUNK_TIMEOUT_MS};
var PROBE_TIMEOUT_MS = ${PROBE_TIMEOUT_MS};
var MAX_RETRIES = ${MAX_RETRIES};
var STALE_AGE_MS = ${STALE_AGE_MS};
var META_FLUSH_INTERVAL_MS = ${META_FLUSH_INTERVAL_MS};
var META_FLUSH_CHUNK_COUNT = ${META_FLUSH_CHUNK_COUNT};
var AUTH_HEADER_NAME = 'X-Downloader-Auth';

var AUTH_TOKEN = '__AUTH_TOKEN_PLACEHOLDER__';

var abortController = null;
var isDownloading = false;

// ==================== IndexedDB ====================
function openDB() {
  return new Promise(function (resolve, reject) {
    var req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = function (e) {
      var db = e.target.result;
      if (db.objectStoreNames.contains('chunks')) {
        db.deleteObjectStore('chunks');
      }
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: 'url' });
      }
    };
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error); };
  });
}

async function idbGet(storeName, key) {
  var db = await openDB();
  return new Promise(function (resolve, reject) {
    var tx = db.transaction(storeName, 'readonly');
    var req = tx.objectStore(storeName).get(key);
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error); };
  });
}

async function idbPut(storeName, key, value) {
  var db = await openDB();
  return new Promise(function (resolve, reject) {
    var tx = db.transaction(storeName, 'readwrite');
    var store = tx.objectStore(storeName);
    var req;
    if (store.keyPath) {
      req = store.put(value);
    } else {
      req = store.put(value, key);
    }
    req.onsuccess = function () { resolve(); };
    req.onerror = function () { reject(req.error); };
  });
}

async function idbDelete(storeName, key) {
  var db = await openDB();
  return new Promise(function (resolve, reject) {
    var tx = db.transaction(storeName, 'readwrite');
    var req = tx.objectStore(storeName).delete(key);
    req.onsuccess = function () { resolve(); };
    req.onerror = function () { reject(req.error); };
  });
}

async function idbGetAll(storeName) {
  var db = await openDB();
  return new Promise(function (resolve, reject) {
    var tx = db.transaction(storeName, 'readonly');
    var req = tx.objectStore(storeName).getAll();
    req.onsuccess = function () { resolve(req.result || []); };
    req.onerror = function () { reject(req.error); };
  });
}

async function idbCleanupStale(maxAgeMs) {
  var db = await openDB();
  return new Promise(function (resolve, reject) {
    var tx = db.transaction(STORE_META, 'readwrite');
    var store = tx.objectStore(STORE_META);
    var req = store.openCursor();
    req.onsuccess = function (e) {
      var cursor = e.target.result;
      if (cursor) {
        var meta = cursor.value;
        if (meta && meta.updatedAt && (Date.now() - meta.updatedAt > maxAgeMs)) {
          cursor.delete();
        }
        cursor.continue();
      } else {
        resolve();
      }
    };
    req.onerror = function () { reject(req.error); };
  });
}

// ==================== UI ====================
function $(id) { return document.getElementById(id); }

function setStatus(msg, type) {
  var el = $('statusMsg');
  el.textContent = msg;
  el.className = 'status ' + (type || 'info');
}

function updateProgress(downloaded, total) {
  var pct = total > 0 ? Math.floor((downloaded / total) * 100) : 0;
  $('progressFill').style.width = pct + '%';
  $('progressPct').textContent = pct + '%';
  $('progressLabel').textContent = formatBytes(downloaded) + ' / ' + formatBytes(total);
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  var k = 1024;
  var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  var i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

function guessFileName(url) {
  try {
    var p = new URL(url).pathname;
    var parts = p.split('/').filter(Boolean);
    var last = parts[parts.length - 1];
    return last ? decodeURIComponent(last) : 'download';
  } catch (e) {
    return 'download';
  }
}

function authHeaders(extra) {
  var h = {};
  h[AUTH_HEADER_NAME] = AUTH_TOKEN;
  if (extra) {
    for (var k in extra) {
      if (Object.prototype.hasOwnProperty.call(extra, k)) h[k] = extra[k];
    }
  }
  return h;
}

// ==================== 探测文件元信息 ====================
async function probeFile(proxyUrl, outerSignal) {
  var ctrl = new AbortController();
  var timedOut = false;
  var timer = setTimeout(function () {
    timedOut = true;
    ctrl.abort();
  }, PROBE_TIMEOUT_MS);

  var onOuterAbort = function () { ctrl.abort(); };
  if (outerSignal) {
    if (outerSignal.aborted) {
      clearTimeout(timer);
      throw new Error('ABORTED');
    }
    outerSignal.addEventListener('abort', onOuterAbort, { once: true });
  }

  try {
    var resp = await fetch(proxyUrl, {
      headers: authHeaders({ Range: 'bytes=0-0' }),
      signal: ctrl.signal,
      cache: 'no-store',
    });

    if (!resp.ok) {
      var errText = '';
      try { errText = await resp.text(); } catch (_) {}
      throw new Error('无法获取文件信息：' + (errText || ('HTTP ' + resp.status)));
    }

    if (resp.status !== 206) {
      throw new Error('服务器未响应 206 Partial Content，可能不支持分段下载');
    }

    var contentRange = resp.headers.get('Content-Range');
    if (!contentRange) {
      throw new Error('响应缺少 Content-Range 头');
    }
    // ★ 已双重转义
    var m = contentRange.match(/bytes\\s+(\\d+)-(\\d+)\\/(\\d+|\\*)/);
    if (!m) {
      throw new Error('Content-Range 格式无法解析：' + contentRange);
    }
    if (m[3] === '*') {
      throw new Error('服务器未返回文件总大小，无法分段下载');
    }
    var fileSize = parseInt(m[3], 10);
    if (!fileSize || fileSize <= 0) {
      throw new Error('服务器返回的文件大小无效');
    }

    var contentType = resp.headers.get('Content-Type') || 'application/octet-stream';
    var etag = resp.headers.get('ETag') || '';
    var lastModified = resp.headers.get('Last-Modified') || '';

    var fileName = 'download';
    try {
      var u = new URL(proxyUrl, location.origin);
      var targetUrl = u.searchParams.get('url');
      if (targetUrl) {
        var pathname = new URL(targetUrl).pathname;
        var parts = pathname.split('/').filter(Boolean);
        var last = parts[parts.length - 1];
        if (last) fileName = decodeURIComponent(last);
      }
    } catch (e) {}

    var cd = resp.headers.get('Content-Disposition');
    if (cd) {
      // ★ 已双重转义
      var fn = cd.match(/filename\\*?=(?:UTF-8'')?["']?([^"'\\s;]+)/i);
      if (fn) {
        try { fileName = decodeURIComponent(fn[1]); } catch (e) {}
      }
    }

    return {
      fileSize: fileSize,
      totalChunks: Math.ceil(fileSize / CHUNK_SIZE),
      contentType: contentType,
      etag: etag,
      lastModified: lastModified,
      fileName: fileName
    };
  } catch (e) {
    if (timedOut) {
      throw new Error('探测文件信息超时（' + (PROBE_TIMEOUT_MS / 1000) + ' 秒），请检查目标地址是否可访问');
    }
    throw e;
  } finally {
    clearTimeout(timer);
    if (outerSignal) {
      outerSignal.removeEventListener('abort', onOuterAbort);
    }
  }
}

// ==================== 下载单片 ====================
async function downloadChunk(proxyUrl, index, start, end, outerSignal) {
  var expectedLen = end - start + 1;
  var attempt = 0;

  while (true) {
    var ctrl = new AbortController();
    var timedOut = false;
    var timer = setTimeout(function () {
      timedOut = true;
      ctrl.abort();
    }, CHUNK_TIMEOUT_MS);

    var onOuterAbort = function () { ctrl.abort(); };
    outerSignal.addEventListener('abort', onOuterAbort, { once: true });

    try {
      var resp = await fetch(proxyUrl, {
        headers: authHeaders({ Range: 'bytes=' + start + '-' + end }),
        signal: ctrl.signal,
        cache: 'no-store',
      });

      if (!resp.ok) {
        var errText = '';
        try { errText = await resp.text(); } catch (_) {}
        throw new Error(errText || ('HTTP ' + resp.status));
      }

      var buf = await resp.arrayBuffer();
      if (buf.byteLength === 0) {
        throw new Error('空响应');
      }
      if (buf.byteLength !== expectedLen) {
        throw new Error('分片长度不匹配：期望 ' + expectedLen + '，实际 ' + buf.byteLength);
      }
      return buf;
    } catch (e) {
      if (outerSignal.aborted) throw e;
      attempt++;
      if (attempt >= MAX_RETRIES) {
        var reason = timedOut ? '超时' : (e && e.message ? e.message : String(e));
        throw new Error('第 ' + (index + 1) + ' 片下载失败：' + reason);
      }
      setStatus('第 ' + (index + 1) + ' 片' + (timedOut ? '超时' : '失败') + '，重试 ' + attempt + '/' + MAX_RETRIES + '…', 'info');
      await new Promise(function (r) { setTimeout(r, 1000 * attempt); });
    } finally {
      clearTimeout(timer);
      outerSignal.removeEventListener('abort', onOuterAbort);
    }
  }
}

// ==================== 开始下载 ====================
async function startDownload() {
  if (isDownloading) {
    setStatus('已有下载任务进行中', 'err');
    return;
  }

  var rawUrl = $('urlInput').value.trim();
  if (!rawUrl) { setStatus('请输入文件地址', 'err'); return; }
  try { new URL(rawUrl); } catch (e) {
    setStatus('URL 格式不正确', 'err'); return;
  }

  if (!window.showSaveFilePicker) {
    setStatus('当前浏览器不支持 File System Access API，请使用 Chrome 或 Edge', 'err');
    return;
  }

  isDownloading = true;
  $('startBtn').disabled = true;
  $('cancelBtn').disabled = false;
  $('progressWrap').classList.add('active');

  abortController = new AbortController();
  var proxyUrl = location.origin + '/proxy?url=' + encodeURIComponent(rawUrl);
  var writable = null;
  var writableClosed = false;
  var metaRecord = null;
  var chunksSinceFlush = 0;
  var lastFlushTime = Date.now();
  var lastWrittenChunk = -1;

  try {
    try { await idbCleanupStale(STALE_AGE_MS); } catch (_) {}

    var existingMeta = await idbGet(STORE_META, rawUrl);
    var fileHandle = null;

    if (existingMeta && existingMeta.fileHandle) {
      var recovered = false;
      try {
        var perm = await existingMeta.fileHandle.queryPermission({ mode: 'readwrite' });
        if (perm !== 'granted') {
          perm = await existingMeta.fileHandle.requestPermission({ mode: 'readwrite' });
        }
        if (perm === 'granted') {
          await existingMeta.fileHandle.getFile();
          fileHandle = existingMeta.fileHandle;
          recovered = true;
          setStatus('已恢复之前的文件句柄，准备续传…', 'info');
        }
      } catch (e) {
        console.warn('恢复文件句柄失败，文件可能已被删除或移动', e);
      }
      if (!recovered) {
        await idbDelete(STORE_META, rawUrl);
        existingMeta = null;
        setStatus('之前的文件已失效或无法访问，请重新选择保存位置', 'info');
      }
    }

    if (!fileHandle) {
      setStatus('请选择保存位置…', 'info');
      try {
        fileHandle = await window.showSaveFilePicker({
          suggestedName: guessFileName(rawUrl),
        });
      } catch (e) {
        if (e && e.name === 'AbortError') {
          setStatus('已取消选择保存位置', 'err');
          return;
        }
        throw e;
      }
      existingMeta = null;
    }

    setStatus('正在探测文件信息…', 'info');
    var meta = await probeFile(proxyUrl, abortController.signal);

    var resumeFrom = 0;
    if (existingMeta) {
      var sameSize = existingMeta.fileSize === meta.fileSize;
      var hasValidator = (meta.etag || meta.lastModified);
      var sameEtag = meta.etag && existingMeta.etag
        ? existingMeta.etag === meta.etag
        : (!meta.etag && !existingMeta.etag);
      var sameLm = meta.lastModified && existingMeta.lastModified
        ? existingMeta.lastModified === meta.lastModified
        : (!meta.lastModified && !existingMeta.lastModified);

      if (!hasValidator && !existingMeta.etag && !existingMeta.lastModified && sameSize) {
        setStatus('服务器未提供 ETag/Last-Modified，无法安全续传，将从头上传', 'info');
        resumeFrom = 0;
      } else if (sameSize && sameEtag && sameLm) {
        resumeFrom = existingMeta.nextChunk || 0;
        if (resumeFrom > 0) {
          setStatus('续传：从第 ' + (resumeFrom + 1) + '/' + meta.totalChunks + ' 片开始（已写入 '
            + formatBytes(resumeFrom * CHUNK_SIZE) + '）', 'info');
        }
      } else {
        setStatus('文件已变化，从头开始下载', 'info');
        resumeFrom = 0;
      }
    }

    writable = await fileHandle.createWritable({ keepExistingData: true });

    metaRecord = {
      url: rawUrl,
      fileSize: meta.fileSize,
      totalChunks: meta.totalChunks,
      etag: meta.etag,
      lastModified: meta.lastModified,
      fileName: meta.fileName,
      contentType: meta.contentType,
      nextChunk: resumeFrom,
      fileHandle: fileHandle,
      updatedAt: Date.now(),
    };
    await idbPut(STORE_META, rawUrl, metaRecord);

    for (var i = resumeFrom; i < meta.totalChunks; i++) {
      if (abortController.signal.aborted) throw new Error('ABORTED');

      var start = i * CHUNK_SIZE;
      var end = Math.min(start + CHUNK_SIZE - 1, meta.fileSize - 1);

      setStatus('正在下载第 ' + (i + 1) + '/' + meta.totalChunks + ' 片…', 'info');

      var buf = await downloadChunk(proxyUrl, i, start, end, abortController.signal);

      await writable.seek(start);
      await writable.write(buf);
      lastWrittenChunk = i;

      metaRecord.nextChunk = i + 1;
      chunksSinceFlush++;

      var now = Date.now();
      var shouldFlush =
        chunksSinceFlush >= META_FLUSH_CHUNK_COUNT ||
        (now - lastFlushTime) >= META_FLUSH_INTERVAL_MS ||
        i === meta.totalChunks - 1;

      if (shouldFlush) {
        metaRecord.updatedAt = now;
        await idbPut(STORE_META, rawUrl, metaRecord);
        chunksSinceFlush = 0;
        lastFlushTime = now;
      }

      var downloaded = Math.min((i + 1) * CHUNK_SIZE, meta.fileSize);
      updateProgress(downloaded, meta.fileSize);
    }

    await writable.close();
    writableClosed = true;

    await idbDelete(STORE_META, rawUrl);
    metaRecord = null;

    setStatus('✅ 下载完成：' + meta.fileName + '（' + formatBytes(meta.fileSize) + '）', 'ok');
    updateProgress(meta.fileSize, meta.fileSize);
    $('progressLabel').textContent = '完成';
  } catch (e) {
    if (metaRecord) {
      if (lastWrittenChunk >= 0 && metaRecord.nextChunk > lastWrittenChunk + 1) {
        metaRecord.nextChunk = lastWrittenChunk + 1;
      }
      try {
        metaRecord.updatedAt = Date.now();
        await idbPut(STORE_META, rawUrl, metaRecord);
      } catch (_) {}
    }

    if (abortController && abortController.signal.aborted) {
      setStatus('下载已取消（进度已保存，可续传）', 'err');
    } else if (e && e.message === 'ABORTED') {
      setStatus('下载已取消（进度已保存，可续传）', 'err');
    } else {
      setStatus('❌ ' + (e && e.message ? e.message : String(e)), 'err');
    }
  } finally {
    if (writable && !writableClosed) {
      try { await writable.close(); } catch (_) {}
    }
    isDownloading = false;
    $('startBtn').disabled = false;
    $('cancelBtn').disabled = true;
    abortController = null;
  }
}

// ==================== 取消下载 ====================
function cancelDownload() {
  if (abortController) abortController.abort();
}

// ==================== 页面加载 ====================
window.addEventListener('DOMContentLoaded', async function () {
  var hashToken = null;
  if (location.hash && location.hash.indexOf('#token=') === 0) {
    hashToken = location.hash.slice(7);
    history.replaceState(null, '', location.pathname + location.search);
  }
  var storedToken = sessionStorage.getItem('cf_dl_auth_token');
  if (hashToken) {
    AUTH_TOKEN = hashToken;
    sessionStorage.setItem('cf_dl_auth_token', hashToken);
  } else if (storedToken) {
    AUTH_TOKEN = storedToken;
  }

  try {
    try { await idbCleanupStale(STALE_AGE_MS); } catch (_) {}

    var metas = await idbGetAll(STORE_META);
    var pending = metas.filter(function (m) {
      return m && typeof m.nextChunk === 'number' && m.nextChunk < m.totalChunks;
    });
    if (pending.length > 0) {
      pending.sort(function (a, b) {
        return (b.updatedAt || 0) - (a.updatedAt || 0);
      });
      var latest = pending[0];
      $('urlInput').value = latest.url;
      setStatus('检测到未完成的下载（' + latest.fileName + '，已下载 '
        + latest.nextChunk + '/' + latest.totalChunks + ' 片），点击"开始下载"继续', 'info');
    }
  } catch (e) {
    console.warn('页面加载初始化失败', e);
  }
});

$('urlInput').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') startDownload();
});
</script>
</body>
</html>`;
}