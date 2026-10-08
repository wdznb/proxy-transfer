/**
 * Cloudflare Worker：分段代理下载 + 流式写入硬盘 + 断点续传
 * 
 * 本轮修复：
 *   - 单请求流式模式取消 "数据长度不匹配" 校验
 *     （很多服务器 Content-Length 不准确：动态生成、被压缩、分块等）
 *   - 仅保留无限流硬上限防御，不阻塞正常下载
 */

const CHUNK_SIZE = 64 * 1024;
const DB_NAME = 'cf-downloader-db';
const DB_VERSION = 3;
const STORE_META = 'meta';
const CHUNK_TIMEOUT_MS = 60000;
const PROBE_TIMEOUT_MS = 30000;
const MAX_RETRIES = 3;
const STALE_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const META_FLUSH_INTERVAL_MS = 5000;
const META_FLUSH_CHUNK_COUNT = 20;
const MAX_REDIRECTS = 3;
const DNS_CACHE_TTL_SEC = 15;
const MAX_CNAME_DEPTH = 5;
const DOH_TIMEOUT_MS = 5000;
const DOH_MAX_RESPONSE_BYTES = 10 * 1024;
const DOH_DECODE_THRESHOLD = 1024;
const CONCURRENCY = 1;

const MAX_PENDING_CHUNKS = 15;
const MAX_PENDING_BYTES = 40 * 1024 * 1024;

const PER_IP_FETCH_TIMEOUT_MS = 12000;
const TOTAL_FETCH_TIMEOUT_MS = 25000;
const MAX_IPS_TO_TRY = 3;

const DNS_INFLIGHT_TIMEOUT_MS = 10000;

const IDB_BATCH_SIZE = 8;

const MAX_SINGLE_REQUEST_BYTES = 4 * 1024 * 1024 * 1024;  // 4GB 硬上限，防无限流
const SINGLE_REQUEST_SIZE_BUFFER = 4 * 1024 * 1024;

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const dnsInflight = new Map();

// ==================== Worker 入口 ====================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/' || url.pathname === '/index.html') return handlePage(request, env);
    if (url.pathname === '/proxy') return handleProxy(request, env, ctx);
    return new Response('Not Found', { status: 404 });
  },
};

// ==================== 页面处理 ====================
async function handlePage(request, env) {
  if (!env.AUTH_TOKEN) return new Response('服务未配置 AUTH_TOKEN', { status: 500 });
  if (!/^[A-Za-z0-9_-]+$/.test(env.AUTH_TOKEN)) {
    return new Response('AUTH_TOKEN 必须为字母、数字、下划线或短横线', { status: 500 });
  }
  const headers = new Headers({
    'Content-Type': 'text/html;charset=utf-8',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  headers.set('Set-Cookie',
    'cf_dl_auth=' + env.AUTH_TOKEN +
    '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400');
  return new Response(getHTML(), { headers });
}

// ==================== SSRF 防护 ====================
function extractMappedIPv4(ipv6) {
  let lower = ipv6.toLowerCase().replace(/^\[|\]$/g, '');
  var m1 = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (m1) return m1[1];
  var m2 = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (m2) {
    var hi = parseInt(m2[1], 16), lo = parseInt(m2[2], 16);
    return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff].join('.');
  }
  var m3 = lower.match(/^0:0:0:0:0:ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (m3) {
    var hi3 = parseInt(m3[1], 16), lo3 = parseInt(m3[2], 16);
    return [(hi3 >> 8) & 0xff, hi3 & 0xff, (lo3 >> 8) & 0xff, lo3 & 0xff].join('.');
  }
  return null;
}

function isPrivateIPv4(ip) {
  var parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(function (p) { return isNaN(p) || p < 0 || p > 255; })) return true;
  var a = parts[0], b = parts[1], c = parts[2];
  if (a === 0 || a === 10 || a === 127) return true;
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

function isPrivateIPv6(ipv6) {
  let lower = ipv6.toLowerCase().replace(/^\[|\]$/g, '');
  var mapped = extractMappedIPv4(lower);
  if (mapped) return isPrivateIPv4(mapped);
  if (lower === '::' || lower === '::1') return true;
  if (/^fe[89ab][0-9a-f]:/i.test(lower)) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(lower)) return true;
  if (/^ff[0-9a-f]{2}:/i.test(lower)) return true;
  if (/^64:ff9b::/i.test(lower)) return true;
  if (/^2002:/i.test(lower)) {
    var hex = lower.replace(/^2002:/, '').split(':').slice(0, 2).join('');
    if (hex.length === 8) {
      var ipv4 = [
        parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16),
        parseInt(hex.slice(4, 6), 16), parseInt(hex.slice(6, 8), 16),
      ].join('.');
      if (isPrivateIPv4(ipv4)) return true;
    }
  }
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
  if (v6 === '::' || v6 === '::1') return true;
  if (/^fe[89ab][0-9a-f]:/i.test(v6)) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(v6)) return true;
  return false;
}

// ==================== DoH 查询 ====================
function concatUint8(chunks, totalLen) {
  var merged = new Uint8Array(totalLen);
  var offset = 0;
  for (var i = 0; i < chunks.length; i++) {
    merged.set(chunks[i], offset);
    offset += chunks[i].byteLength;
  }
  return merged;
}

async function dohQuery(name, type) {
  var ctrl = new AbortController();
  var timedOut = false;
  var timer = setTimeout(function () { timedOut = true; ctrl.abort(); }, DOH_TIMEOUT_MS);
  try {
    var dohUrl = 'https://cloudflare-dns.com/dns-query?name=' +
      encodeURIComponent(name) + '&type=' + type;
    var resp = await fetch(dohUrl, {
      headers: { 'Accept': 'application/dns-json' },
      signal: ctrl.signal,
      cf: { cacheTtl: 0 },
    });
    if (!resp.ok) throw new Error('DNS 查询失败：HTTP ' + resp.status);

    var contentLength = resp.headers.get('Content-Length');
    if (contentLength) {
      var clNum = parseInt(contentLength, 10);
      if (!isNaN(clNum) && clNum > DOH_MAX_RESPONSE_BYTES) {
        try { if (resp.body && typeof resp.body.cancel === 'function') await resp.body.cancel(); } catch (_) {}
        throw new Error('DoH 响应过大（' + clNum + ' 字节），拒绝解析');
      }
      return await resp.json();
    }

    if (!resp.body) return await resp.json();

    var reader = resp.body.getReader();
    var decoder = new TextDecoder('utf-8');
    var text = '';
    var totalRead = 0;
    var pendingChunks = [];
    var pendingBytes = 0;

    function flushPending(stream) {
      if (pendingBytes === 0) return;
      var merged = concatUint8(pendingChunks, pendingBytes);
      text += decoder.decode(merged, stream ? { stream: true } : undefined);
      pendingChunks = [];
      pendingBytes = 0;
    }

    try {
      while (true) {
        var result = await reader.read();
        if (result.done) {
          flushPending(true);
          text += decoder.decode();
          break;
        }
        totalRead += result.value.byteLength;
        if (totalRead > DOH_MAX_RESPONSE_BYTES) {
          try { await reader.cancel(); } catch (_) {}
          throw new Error('DoH 响应超过上限（' + DOH_MAX_RESPONSE_BYTES + ' 字节），拒绝解析');
        }
        pendingChunks.push(result.value);
        pendingBytes += result.value.byteLength;
        if (pendingBytes >= DOH_DECODE_THRESHOLD) flushPending(true);
      }
    } finally {
      try { reader.releaseLock(); } catch (_) {}
    }
    return JSON.parse(text);
  } catch (e) {
    if (timedOut) throw new Error('DoH 查询超时（' + (DOH_TIMEOUT_MS / 1000) + ' 秒）');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ==================== DNS 解析 ====================
async function resolveAndValidateInternal(hostname, ctx) {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    if (isPrivateIPv4(hostname)) throw new Error('禁止访问内网或保留地址');
    return [hostname];
  }
  if (hostname.includes(':')) {
    var cleanV6 = hostname.replace(/^\[|\]$/g, '');
    if (isPrivateIPv6(cleanV6)) throw new Error('禁止访问内网或保留地址');
    throw new Error('不支持纯 IPv6 目标地址');
  }

  var cacheKey = 'https://dns-cache.internal/' + hostname;
  var cache = caches.default;
  try {
    var cached = await cache.match(cacheKey);
    if (cached) {
      var cachedData = await cached.json();
      var allSafe = cachedData.ips.every(function (ip) { return !isPrivateIPv4(ip); });
      if (allSafe) return cachedData.ips;
    }
  } catch (_) {}

  var visited = new Set();
  var currentName = hostname;
  var cnameDepth = 0;
  var resolvedIps = [];

  while (cnameDepth <= MAX_CNAME_DEPTH) {
    var lower = currentName.toLowerCase();
    if (visited.has(lower)) throw new Error('检测到循环 CNAME 链');
    visited.add(lower);

    var data = await dohQuery(currentName, 'A');
    if (!data.Answer || !Array.isArray(data.Answer) || data.Answer.length === 0) {
      throw new Error('域名无法解析到任何 IP 地址');
    }

    var cnameTarget = null;
    var foundA = false;
    for (var i = 0; i < data.Answer.length; i++) {
      var answer = data.Answer[i];
      if (answer.type === 1 && answer.data) {
        foundA = true;
        if (isPrivateIPv4(answer.data)) throw new Error('域名解析到内网 IPv4 地址（' + answer.data + '），已拦截');
        resolvedIps.push(answer.data);
      }
      if (answer.type === 5 && answer.data) cnameTarget = answer.data.replace(/\.$/, '');
    }
    if (foundA && resolvedIps.length > 0) break;
    if (cnameTarget) {
      if (isPrivateHostname(cnameTarget)) throw new Error('CNAME 指向内网域名（' + cnameTarget + '），已拦截');
      currentName = cnameTarget;
      cnameDepth++;
      continue;
    }
    throw new Error('域名无法解析到任何 IP 地址');
  }
  if (resolvedIps.length === 0) throw new Error('域名无法解析到任何公网 IP 地址');

  try {
    ctx.waitUntil(cache.put(cacheKey,
      new Response(JSON.stringify({ ips: resolvedIps }), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=' + DNS_CACHE_TTL_SEC },
      })));
  } catch (_) {}
  return resolvedIps;
}

function resolveAndValidate(hostname, ctx) {
  var key = hostname.toLowerCase();
  if (dnsInflight.has(key)) return dnsInflight.get(key);

  var timerId = null;
  var promise = resolveAndValidateInternal(hostname, ctx);
  var timeoutPromise = new Promise(function (_, reject) {
    timerId = setTimeout(function () {
      reject(new Error('DNS 解析超时（内部兜底 ' + (DNS_INFLIGHT_TIMEOUT_MS / 1000) + ' 秒）'));
    }, DNS_INFLIGHT_TIMEOUT_MS);
  });

  var wrapped = Promise.race([promise, timeoutPromise]);
  wrapped.then(
    function () { if (timerId !== null) { clearTimeout(timerId); timerId = null; } },
    function () { if (timerId !== null) { clearTimeout(timerId); timerId = null; } });

  dnsInflight.set(key, wrapped);
  wrapped.then(function () {
    if (dnsInflight.get(key) === wrapped) dnsInflight.delete(key);
  }, function () {
    if (dnsInflight.get(key) === wrapped) dnsInflight.delete(key);
  });
  return wrapped;
}

function validateTargetUrl(targetUrl) {
  let parsed;
  try { parsed = new URL(targetUrl); } catch (e) { throw new Error('无效的目标 URL'); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('仅允许 http/https 协议');
  if (!parsed.hostname) throw new Error('目标 URL 缺少主机名');
  if (parsed.username || parsed.password) throw new Error('URL 不允许包含用户名或密码（认证信息）');
  if (isPrivateHostname(parsed.hostname)) throw new Error('禁止访问内网或保留地址');
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') throw new Error('仅允许 80/443 端口');
  return parsed;
}

// ==================== 认证与 CORS ====================
function checkAuth(request, env) {
  if (env && env.DISABLE_AUTH === 'true') return true;
  var expectedToken = env && env.AUTH_TOKEN;
  if (!expectedToken) return false;
  var cookieHeader = request.headers.get('Cookie') || '';
  var cookies = {};
  cookieHeader.split(';').forEach(function (pair) {
    var parts = pair.trim().split('=');
    if (parts.length >= 2) cookies[parts[0].trim()] = parts.slice(1).join('=').trim();
  });
  if (cookies['cf_dl_auth'] === expectedToken) return true;
  if (request.headers.get('X-Downloader-Auth') === expectedToken) return true;
  return false;
}

function getAllowedOrigins(env) {
  if (env && env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  }
  return [];
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
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers':
      'Content-Range, Content-Length, Accept-Ranges, ETag, Last-Modified, Content-Disposition, X-Upstream-Content-Length, X-Unknown-Size',
    'Cache-Control': 'no-store',
    'Vary': 'Origin',
  };
}

// ==================== 合并 AbortSignal ====================
function combineSignals(a, b) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
    return AbortSignal.any([a, b]);
  }
  var ctrl = new AbortController();
  var onAbort = function () { ctrl.abort(); };
  if (a) {
    if (a.aborted) { ctrl.abort(); return ctrl.signal; }
    a.addEventListener('abort', onAbort, { once: true });
  }
  if (b) {
    if (b.aborted) { ctrl.abort(); return ctrl.signal; }
    b.addEventListener('abort', onAbort, { once: true });
  }
  return ctrl.signal;
}

// ==================== 重定向守卫 + 多 IP Failover ====================
async function fetchWithRedirectGuard(targetUrl, options, maxRedirects, env, ctx, externalSignal) {
  var currentUrl = targetUrl;
  var redirectCount = 0;
  var originalParsed = new URL(targetUrl);
  var isOriginalHttps = originalParsed.protocol === 'https:';

  while (redirectCount <= maxRedirects) {
    if (externalSignal && externalSignal.aborted) throw new Error('外部中止');
    var parsed = validateTargetUrl(currentUrl);
    var resolvedIps = await resolveAndValidate(parsed.hostname, ctx);

    if (isOriginalHttps && parsed.protocol !== 'https:') {
      throw new Error('HTTPS 请求被重定向到 HTTP，已阻止协议降级');
    }

    var redirectStartTime = Date.now();
    var lastSpecificError = null;
    var lastTimeoutError = null;
    var last5xxStatus = null;
    var last5xxStatusText = null;
    var resp = null;
    var totalTimeoutReached = false;
    var ipsToTry = Math.min(resolvedIps.length, MAX_IPS_TO_TRY);

    for (var ipIdx = 0; ipIdx < ipsToTry; ipIdx++) {
      if (externalSignal && externalSignal.aborted) throw new Error('外部中止');
      var elapsed = Date.now() - redirectStartTime;
      var remainingTotal = TOTAL_FETCH_TIMEOUT_MS - elapsed;
      if (remainingTotal <= 0) { totalTimeoutReached = true; break; }

      var perIpTimeout = Math.min(PER_IP_FETCH_TIMEOUT_MS, remainingTotal);
      var ipCtrl = new AbortController();
      var ipTimedOut = false;
      var ipTimer = setTimeout(function () { ipTimedOut = true; ipCtrl.abort(); }, perIpTimeout);

      var hopHeaders = new Headers(options.headers || {});
      hopHeaders.set('Host', parsed.hostname);

      var mergedSignal = combineSignals(ipCtrl.signal, externalSignal);
      var fetchOptions = Object.assign({}, options, {
        headers: hopHeaders,
        redirect: 'manual',
        signal: mergedSignal,
        cf: Object.assign({}, options.cf, { resolveOverride: resolvedIps[ipIdx] }),
      });

      try {
        var tryResp = await fetch(currentUrl, fetchOptions);
        clearTimeout(ipTimer);

        if (tryResp.status >= 500 && tryResp.status < 600) {
          last5xxStatus = tryResp.status;
          last5xxStatusText = tryResp.statusText;
          try {
            if (tryResp.body && typeof tryResp.body.cancel === 'function') {
              var p = tryResp.body.cancel();
              if (p && typeof p.catch === 'function') p.catch(function () {});
            }
          } catch (_) {}
          continue;
        }
        resp = tryResp;
        break;
      } catch (e) {
        clearTimeout(ipTimer);
        if (ipTimedOut) lastTimeoutError = new Error('IP ' + resolvedIps[ipIdx] + ' 连接超时');
        else lastSpecificError = e;
      }
    }

    if (!resp) {
      if (totalTimeoutReached) throw new Error('多 IP 重试总超时（' + (TOTAL_FETCH_TIMEOUT_MS / 1000) + ' 秒）');
      if (last5xxStatus !== null) {
        throw new Error('所有上游节点均返回 ' + last5xxStatus + ' ' + (last5xxStatusText || ''));
      }
      throw lastSpecificError || lastTimeoutError || new Error('所有 IP 均连接失败');
    }

    if (resp.status < 300 || resp.status >= 400) return resp;
    var location = resp.headers.get('Location');
    if (!location) return resp;

    try { currentUrl = new URL(location, currentUrl).toString(); }
    catch (e) { throw new Error('无效的重定向 Location: ' + location); }

    redirectCount++;
    if (redirectCount > maxRedirects) throw new Error('重定向次数超过上限 (' + maxRedirects + ')');
  }
  throw new Error('重定向处理异常');
}

// ==================== 流截断 ====================
function buildTruncatingTransform(maxLength, upstreamCtrl) {
  var read = 0;
  var truncated = false;
  return new TransformStream({
    transform: function (chunk, controller) {
      if (truncated) return;
      var remaining = maxLength - read;
      if (chunk.byteLength <= remaining) {
        read += chunk.byteLength;
        controller.enqueue(chunk);
      } else {
        controller.enqueue(chunk.slice(0, remaining));
        read = maxLength;
        truncated = true;
        try { controller.terminate(); } catch (_) {}
        try { upstreamCtrl.abort(); } catch (_) {}
      }
    },
    flush: function (controller) {
      if (!truncated && read < maxLength) {
        try {
          controller.error(new Error('上游数据不完整：期望 ' + maxLength + ' 字节，实际 ' + read + ' 字节'));
        } catch (_) {}
      }
    },
  });
}

// ==================== 后端代理逻辑 ====================
async function handleProxy(request, env, ctx) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }
  if (!checkAuth(request, env)) {
    return new Response('未授权访问', { status: 403, headers: corsHeaders(request, env) });
  }

  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  if (!targetUrl) return new Response('缺少 url 参数', { status: 400, headers: corsHeaders(request, env) });

  try { validateTargetUrl(targetUrl); }
  catch (e) { return new Response(e.message, { status: 400, headers: corsHeaders(request, env) }); }

  const forwardHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    const lower = key.toLowerCase();
    if (lower === 'range' || lower === 'if-range') forwardHeaders.set(key, value);
  }
  forwardHeaders.set('Accept-Encoding', 'identity');
  forwardHeaders.set('Accept', '*/*');
  var clientUA = request.headers.get('User-Agent');
  forwardHeaders.set('User-Agent', clientUA || DEFAULT_UA);

  const upstreamCtrl = new AbortController();

  try {
    const upstream = await fetchWithRedirectGuard(targetUrl, {
      method: 'GET',
      headers: forwardHeaders,
      cf: { cacheEverything: false, cacheTtl: 0 },
    }, MAX_REDIRECTS, env, ctx, upstreamCtrl.signal);

    const responseHeaders = new Headers();
    const passthrough = ['content-type', 'content-range', 'accept-ranges', 'etag', 'last-modified', 'content-disposition'];
    for (const name of passthrough) {
      const val = upstream.headers.get(name);
      if (val) responseHeaders.set(name, val);
    }
    responseHeaders.delete('content-encoding');
    responseHeaders.delete('transfer-encoding');
    responseHeaders.delete('content-length');
    for (const [k, v] of Object.entries(corsHeaders(request, env))) responseHeaders.set(k, v);

    var rawCL = upstream.headers.get('content-length');
    if (rawCL) responseHeaders.set('X-Upstream-Content-Length', rawCL);

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
    if (!expectedLength && rawCL) {
      const parsedCl = parseInt(rawCL, 10);
      if (!isNaN(parsedCl) && parsedCl > 0) expectedLength = parsedCl;
    }

    if (expectedLength && expectedLength > 0) {
      responseHeaders.set('Content-Length', String(expectedLength));
      var transform = buildTruncatingTransform(expectedLength, upstreamCtrl);
      var truncated = upstream.body.pipeThrough(transform);
      return new Response(truncated, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders,
      });
    }

    var upstreamTE = upstream.headers.get('transfer-encoding') || '';
    var upstreamHasChunked = upstreamTE.toLowerCase().indexOf('chunked') !== -1;

    if (upstream.status === 200 && upstream.body) {
      if (!upstreamHasChunked) {
        try {
          if (upstream.body && typeof upstream.body.cancel === 'function') {
            var bp = upstream.body.cancel();
            if (bp && typeof bp.catch === 'function') bp.catch(function () {});
          }
        } catch (_) {}
        return new Response(
          '上游响应既无 Content-Length 也无 Transfer-Encoding: chunked，无法确定响应大小',
          { status: 502, headers: corsHeaders(request, env) });
      }
      responseHeaders.set('X-Unknown-Size', '1');
    } else if (upstream.status >= 200 && upstream.status < 300) {
      try {
        if (upstream.body && typeof upstream.body.cancel === 'function') {
          var bp2 = upstream.body.cancel();
          if (bp2 && typeof bp2.catch === 'function') bp2.catch(function () {});
        }
      } catch (_) {}
      return new Response(
        '上游响应 ' + upstream.status + ' 缺少必要的长度信息（无 Content-Length 也无 Content-Range）',
        { status: 502, headers: corsHeaders(request, env) });
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
  .progress-bar-bg { height: 10px; background: #e9ecef; border-radius: 5px; overflow: hidden; position: relative; }
  .progress-bar-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #4a6cf7, #7c8cf8); border-radius: 5px; transition: width .25s ease; }
  .progress-bar-fill.indeterminate {
    width: 40% !important;
    animation: indeterminate-slide 1.5s ease-in-out infinite;
    transition: none;
  }
  @keyframes indeterminate-slide {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(250%); }
  }
  .progress-text { display: flex; justify-content: space-between; font-size: .82rem; color: #666; margin-top: 8px; }
  .status { font-size: .85rem; margin-top: 10px; min-height: 1.2em; }
  .status.ok { color: #16a34a; }
  .status.err { color: #dc2626; }
  .status.info { color: #4a6cf7; }
  .status.warn { color: #f59e0b; }
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
    <div class="progress-bar-bg"><div class="progress-bar-fill" id="progressFill"></div></div>
    <div class="progress-text">
      <span id="progressLabel">等待中…</span>
      <span id="progressPct">0%</span>
    </div>
  </div>
  <div class="status" id="statusMsg"></div>
  <div class="hint">
    提示：每下载完一片会立即写入你选择的文件。刷新页面后重新输入同一地址，会自动续传。<br>
    若服务器不支持分段下载（不响应 Range 请求），将自动切换为单请求流式模式，此时中断后需重新下载。<br>
    安全提示：本页面会将文件句柄保存在浏览器 IndexedDB 中以实现自动续传。若在公用设备使用，请及时清理浏览器数据。
  </div>
</div>
<script>
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
var CONCURRENCY = ${CONCURRENCY};
var MAX_PENDING_CHUNKS = ${MAX_PENDING_CHUNKS};
var MAX_PENDING_BYTES = ${MAX_PENDING_BYTES};
var IDB_BATCH_SIZE = ${IDB_BATCH_SIZE};
var MAX_SINGLE_REQUEST_BYTES = ${MAX_SINGLE_REQUEST_BYTES};
var SINGLE_REQUEST_SIZE_BUFFER = ${SINGLE_REQUEST_SIZE_BUFFER};

var abortController = null;
var isDownloading = false;

// ==================== IndexedDB 单例（带重连互斥锁） ====================
var dbPromise = null;
var dbPendingOpen = null;

function openDB() {
  if (dbPromise) return dbPromise;
  if (dbPendingOpen) return dbPendingOpen;

  dbPendingOpen = new Promise(function (resolve, reject) {
    var req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = function (e) {
      var db = e.target.result;
      if (db.objectStoreNames.contains('chunks')) db.deleteObjectStore('chunks');
      if (!db.objectStoreNames.contains(STORE_META)) db.createObjectStore(STORE_META, { keyPath: 'url' });
    };
    req.onsuccess = function () {
      var db = req.result;
      db.onclose = function () { dbPromise = null; dbPendingOpen = null; };
      db.onversionchange = function () {
        try { db.close(); } catch (_) {}
        dbPromise = null; dbPendingOpen = null;
      };
      var resolved = Promise.resolve(db);
      dbPromise = resolved;
      dbPendingOpen = null;
      resolve(db);
    };
    req.onerror = function () {
      dbPromise = null; dbPendingOpen = null;
      reject(req.error);
    };
    req.onblocked = function () {
      dbPromise = null; dbPendingOpen = null;
      reject(new Error('IndexedDB 被其他标签页阻塞'));
    };
  });
  return dbPendingOpen;
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
    var req = store.keyPath ? store.put(value) : store.put(value, key);
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
        if (meta && meta.updatedAt && (Date.now() - meta.updatedAt > maxAgeMs)) cursor.delete();
        cursor.continue();
      } else { resolve(); }
    };
    req.onerror = function () { reject(req.error); };
  });
}

// ==================== IndexedDB 任务调度器 ====================
var idbPendingTasks = [];
var idbWriteInFlight = false;

var idbChan = (typeof MessageChannel !== 'undefined') ? new MessageChannel() : null;
var idbNextBatch = null;
if (idbChan) {
  idbChan.port1.onmessage = function () {
    if (idbNextBatch) {
      var fn = idbNextBatch;
      idbNextBatch = null;
      fn();
    }
  };
}

function scheduleNextBatch(fn) {
  if (idbChan) {
    idbNextBatch = fn;
    idbChan.port2.postMessage(null);
  } else {
    setTimeout(fn, 0);
  }
}

function queueIdbPut(storeName, key, value) {
  return new Promise(function (resolve, reject) {
    idbPendingTasks.push({
      storeName: storeName, key: key, value: value,
      resolve: resolve, reject: reject,
    });
    drainIdbQueue();
  });
}

function drainIdbQueue() {
  if (idbWriteInFlight) return;
  if (idbPendingTasks.length === 0) return;
  idbWriteInFlight = true;

  var runBatch = function (remaining) {
    if (idbPendingTasks.length === 0) { idbWriteInFlight = false; return; }
    if (remaining <= 0) {
      scheduleNextBatch(function () { runBatch(IDB_BATCH_SIZE); });
      return;
    }
    var task = idbPendingTasks.shift();
    idbPut(task.storeName, task.key, task.value).then(
      function () { task.resolve(); runBatch(remaining - 1); },
      function (e) { task.reject(e); runBatch(remaining - 1); });
  };
  runBatch(IDB_BATCH_SIZE);
}

async function waitIdbQueue() {
  while (idbWriteInFlight || idbPendingTasks.length > 0) {
    if (!idbWriteInFlight && idbPendingTasks.length > 0) drainIdbQueue();
    await new Promise(function (r) { setTimeout(r, 30); });
  }
}

// ==================== UI ====================
function $(id) { return document.getElementById(id); }
function setStatus(msg, type) {
  var el = $('statusMsg');
  el.textContent = msg;
  el.className = 'status ' + (type || 'info');
}

function updateProgress(downloaded, total) {
  var fill = $('progressFill');
  if (total > 0) {
    fill.classList.remove('indeterminate');
    var pct = Math.floor((downloaded / total) * 100);
    if (pct > 100) pct = 100;
    fill.style.width = pct + '%';
    $('progressPct').textContent = pct + '%';
    $('progressLabel').textContent = formatBytes(downloaded) + ' / ' + formatBytes(total);
  } else {
    fill.classList.add('indeterminate');
    fill.style.width = '';
    $('progressPct').textContent = '—';
    $('progressLabel').textContent = '已下载 ' + formatBytes(downloaded) + '（总大小未知）';
  }
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
  } catch (e) { return 'download'; }
}

function makeSafeWriter(writable) {
  var broken = false;
  return {
    isBroken: function () { return broken; },
    write: async function (position, data) {
      if (broken) throw new Error('文件句柄已损坏，无法继续写入');
      try {
        await writable.write({ type: 'write', position: position, data: data });
      } catch (e) {
        if (e && e.name === 'TypeError') {
          try {
            await writable.seek(position);
            await writable.write(data);
          } catch (e2) { broken = true; throw e2; }
        } else { broken = true; throw e; }
      }
    },
  };
}

// ==================== 探测文件元信息 ====================
async function probeFile(proxyUrl, outerSignal) {
  var ctrl = new AbortController();
  var timedOut = false;
  var timer = setTimeout(function () { timedOut = true; ctrl.abort(); }, PROBE_TIMEOUT_MS);
  var onOuterAbort = function () { ctrl.abort(); };
  if (outerSignal) {
    if (outerSignal.aborted) { clearTimeout(timer); throw new Error('ABORTED'); }
    outerSignal.addEventListener('abort', onOuterAbort, { once: true });
  }

  function releaseBody(resp) {
    try {
      if (resp && resp.body && typeof resp.body.cancel === 'function') {
        var p = resp.body.cancel();
        if (p && typeof p.catch === 'function') p.catch(function () {});
      }
    } catch (_) {}
  }

  try {
    var resp = await fetch(proxyUrl, {
      headers: { Range: 'bytes=0-0' },
      signal: ctrl.signal, cache: 'no-store', credentials: 'same-origin',
    });

    if (!resp.ok && resp.status !== 200) {
      var errText = '';
      try { errText = await resp.text(); } catch (_) {}
      throw new Error('无法获取文件信息：' + (errText || ('HTTP ' + resp.status)));
    }

    // 服务器返回 200：不支持 Range，进入单请求流式模式
    if (resp.status === 200) {
      var xUnknownSize = resp.headers.get('X-Unknown-Size') === '1';
      var upCl = resp.headers.get('X-Upstream-Content-Length');
      var cl = upCl ? parseInt(upCl, 10) : parseInt(resp.headers.get('Content-Length') || '0', 10);
      var transferEncoding = resp.headers.get('Transfer-Encoding') || '';
      var isChunked = transferEncoding.toLowerCase().indexOf('chunked') !== -1;

      if (xUnknownSize) cl = 0;

      var contentType2 = resp.headers.get('Content-Type') || 'application/octet-stream';
      var etag2 = resp.headers.get('ETag') || '';
      var lastModified2 = resp.headers.get('Last-Modified') || '';
      var fileName2 = 'download';
      try {
        var u2 = new URL(proxyUrl, location.origin);
        var targetUrl2 = u2.searchParams.get('url');
        if (targetUrl2) {
          var pathname2 = new URL(targetUrl2).pathname;
          var parts2 = pathname2.split('/').filter(Boolean);
          var last2 = parts2[parts2.length - 1];
          if (last2) fileName2 = decodeURIComponent(last2);
        }
      } catch (e) {}
      var cd2 = resp.headers.get('Content-Disposition');
      if (cd2) {
        var fn2 = cd2.match(/filename\\*?=(?:UTF-8'')?["']?([^"'\\s;]+)/i);
        if (fn2) { try { fileName2 = decodeURIComponent(fn2[1]); } catch (e) {} }
      }

      if (!cl || cl <= 0 || isNaN(cl)) {
        if (transferEncoding && transferEncoding.toLowerCase() !== 'identity' && !isChunked) {
          releaseBody(resp);
          throw new Error('上游返回了不支持的传输编码（' + transferEncoding + '），请检查源站配置');
        }
        if (isChunked || xUnknownSize) {
          releaseBody(resp);
          return {
            fileSize: 0, totalChunks: 1, singleRequest: true, unknownSize: true,
            streamFallback: true,
            contentType: contentType2, etag: etag2, lastModified: lastModified2, fileName: fileName2,
          };
        }
        releaseBody(resp);
        throw new Error('服务器不支持分段下载且未返回文件大小');
      }

      releaseBody(resp);
      return {
        fileSize: cl, totalChunks: 1, singleRequest: true, unknownSize: false,
        streamFallback: cl > CHUNK_SIZE,
        contentType: contentType2, etag: etag2, lastModified: lastModified2, fileName: fileName2,
      };
    }

    if (resp.status !== 206) {
      releaseBody(resp);
      throw new Error('服务器未响应 206 Partial Content（返回 ' + resp.status + '）');
    }

    var contentRange = resp.headers.get('Content-Range');
    if (!contentRange) { releaseBody(resp); throw new Error('响应缺少 Content-Range 头'); }

    var cleanRange = contentRange.trim();
    if (/^bytes\\s+\\*\\s*\\/\\s*\\d+/i.test(cleanRange)) {
      releaseBody(resp);
      throw new Error('服务器返回 Content-Range: ' + cleanRange + '，未提供可用的 Range 信息');
    }

    var m = cleanRange.match(/bytes\\s+(\\d+)\\s*-\\s*(\\d+)\\s*\\/\\s*(\\d+|\\*)/i);
    if (!m) m = cleanRange.match(/(\\d+)\\s*-\\s*(\\d+)\\s*\\/\\s*(\\d+|\\*)/);
    if (!m) { releaseBody(resp); throw new Error('Content-Range 格式无法解析：' + contentRange); }
    if (m[3] === '*') { releaseBody(resp); throw new Error('服务器未返回文件总大小，无法分段下载'); }

    var parsedStart = parseInt(m[1], 10);
    var parsedEnd = parseInt(m[2], 10);
    var parsedTotal = parseInt(m[3], 10);

    if (isNaN(parsedStart) || isNaN(parsedEnd) || isNaN(parsedTotal)) {
      releaseBody(resp);
      throw new Error('Content-Range 格式包含无效数字：' + contentRange);
    }
    if (parsedStart !== 0) { releaseBody(resp); throw new Error('Content-Range 起始位置不为 0（' + parsedStart + '），探测响应异常'); }
    if (parsedEnd < parsedStart) { releaseBody(resp); throw new Error('Content-Range 范围无效（end < start）'); }
    if (parsedTotal < parsedEnd + 1) { releaseBody(resp); throw new Error('Content-Range 总大小无效（total < end + 1）'); }
    if (parsedTotal <= 0) { releaseBody(resp); throw new Error('文件总大小无效'); }

    var fileSize = parsedTotal;
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
      var fn = cd.match(/filename\\*?=(?:UTF-8'')?["']?([^"'\\s;]+)/i);
      if (fn) { try { fileName = decodeURIComponent(fn[1]); } catch (e) {} }
    }

    releaseBody(resp);
    return {
      fileSize: fileSize, totalChunks: Math.ceil(fileSize / CHUNK_SIZE),
      singleRequest: false, unknownSize: false,
      streamFallback: false,
      contentType: contentType, etag: etag, lastModified: lastModified, fileName: fileName
    };
  } catch (e) {
    if (timedOut) throw new Error('探测文件信息超时（' + (PROBE_TIMEOUT_MS / 1000) + ' 秒），请检查目标地址是否可访问');
    throw e;
  } finally {
    clearTimeout(timer);
    if (outerSignal) outerSignal.removeEventListener('abort', onOuterAbort);
  }
}

async function downloadChunk(proxyUrl, index, start, end, outerSignal) {
  var expectedLen = end - start + 1;
  var attempt = 0;
  while (true) {
    var ctrl = new AbortController();
    var timedOut = false;
    var timer = setTimeout(function () { timedOut = true; ctrl.abort(); }, CHUNK_TIMEOUT_MS);
    var onOuterAbort = function () { ctrl.abort(); };
    outerSignal.addEventListener('abort', onOuterAbort, { once: true });
    try {
      var resp = await fetch(proxyUrl, {
        headers: { 'Range': 'bytes=' + start + '-' + end },
        signal: ctrl.signal, cache: 'no-store', credentials: 'same-origin',
      });
      if (!resp.ok) {
        var errText = '';
        try { errText = await resp.text(); } catch (_) {}
        throw new Error(errText || ('HTTP ' + resp.status));
      }
      if (resp.status !== 206) {
        throw new Error('目标服务器不支持分段下载（返回 ' + resp.status + ' 而非 206），已终止');
      }
      var buf = await resp.arrayBuffer();
      if (buf.byteLength === 0) throw new Error('空响应');
      if (buf.byteLength !== expectedLen) throw new Error('分片长度不匹配：期望 ' + expectedLen + '，实际 ' + buf.byteLength);
      return buf;
    } catch (e) {
      if (outerSignal.aborted) throw e;
      attempt++;
      if (e.message && e.message.indexOf('不支持分段下载') !== -1) throw e;
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

// ==================== 单请求流式下载（不再校验长度） ====================
// ★ 修复：移除 totalRead !== fileSize 的校验
//   - 服务器可能返回动态内容、Content-Length 不准确、压缩传输后长度不符
//   - 只保留硬上限（防无限流），不因长度差异判定失败
async function downloadSingleRequestStreaming(proxyUrl, fileSize, safeWriter, outerSignal, onProgress) {
  var knownSize = fileSize > 0;
  var maxAllowedBytes = knownSize
    ? Math.max(fileSize + SINGLE_REQUEST_SIZE_BUFFER, 2 * 1024 * 1024)
    : MAX_SINGLE_REQUEST_BYTES;

  var ctrl = new AbortController();
  var onOuterAbort = function () { ctrl.abort(); };
  outerSignal.addEventListener('abort', onOuterAbort, { once: true });

  try {
    var resp = await fetch(proxyUrl, { signal: ctrl.signal, cache: 'no-store', credentials: 'same-origin' });
    if (!resp.ok) {
      var errText = '';
      try { errText = await resp.text(); } catch (_) {}
      throw new Error(errText || ('HTTP ' + resp.status));
    }
    if (resp.status !== 200) throw new Error('单请求模式期望 200，实际 ' + resp.status);

    if (!resp.body) {
      // 极老浏览器降级：arrayBuffer 一次性读取
      var buf = await resp.arrayBuffer();
      // ★ 移除长度校验，只保留硬上限
      if (buf.byteLength > maxAllowedBytes) {
        throw new Error('单请求响应超过上限 ' + formatBytes(maxAllowedBytes) + '，疑似恶意源站');
      }
      await safeWriter.write(0, buf);
      onProgress(buf.byteLength, fileSize);
      return;
    }

    var reader = resp.body.getReader();
    var totalRead = 0;
    var position = 0;

    while (true) {
      var result = await reader.read();
      if (result.done) break;
      if (outerSignal.aborted) {
        try { reader.cancel(); } catch (_) {}
        throw new Error('ABORTED');
      }
      var chunk = result.value;
      if (chunk && chunk.byteLength > 0) {
        totalRead += chunk.byteLength;
        // ★ 仅保留硬上限防御，不校验与 Content-Length 是否一致
        if (totalRead > maxAllowedBytes) {
          try { await reader.cancel(); } catch (_) {}
          throw new Error('单请求响应超过上限 ' + formatBytes(maxAllowedBytes) + '（实际已收到 '
            + formatBytes(totalRead) + '），疑似恶意源站返回无限流');
        }
        await safeWriter.write(position, chunk);
        position += chunk.byteLength;
        onProgress(totalRead, fileSize);
      }
    }

    // ★ 已移除 "if (knownSize && totalRead !== fileSize) throw ..." 校验
    //   实际下载字节数可能因以下原因与声明值不同：
    //   1. 服务器动态生成内容，Content-Length 只是估计值
    //   2. 上游返回压缩流但未声明或声明错误
    //   3. CDN 边缘节点返回的内容与源站有细微差异
    //   强行校验会导致正常文件被判为失败
  } finally {
    outerSignal.removeEventListener('abort', onOuterAbort);
  }
}

// ==================== 并发下载 + 顺序写入 ====================
function downloadAllChunks(proxyUrl, meta, resumeFrom, safeWriter, outerSignal, onProgress) {
  return new Promise(function (resolve, reject) {
    var total = meta.totalChunks;
    if (resumeFrom >= total) { resolve(); return; }

    var nextIdx = resumeFrom;
    var inFlight = 0;
    var nextWriteIdx = resumeFrom;
    var pending = new Map();
    var pendingBytes = 0;
    var writesPending = 0;
    var finished = false;
    var fatalError = null;
    var writeError = null;
    var writeFailed = false;
    var writeTasks = [];
    var writeRunning = false;

    function allWorkDone() {
      return inFlight === 0 && nextIdx >= total && pending.size === 0 &&
             writeTasks.length === 0 && !writeRunning;
    }

    function done(e) {
      if (finished) return;
      finished = true;
      outerSignal.removeEventListener('abort', onAbort);
      if (e) { writeTasks.length = 0; pending.clear(); }
      var isAborted = e && e.message === 'ABORTED';
      var realError = fatalError || writeError;
      if (isAborted && realError) reject(realError);
      else if (e) reject(e);
      else if (realError) reject(realError);
      else resolve();
    }

    function tryFinish() {
      if (finished) return;
      if (!allWorkDone()) return;
      if (fatalError || writeError) done(fatalError || writeError);
      else done();
    }

    var onAbort = function () { done(new Error('ABORTED')); };
    outerSignal.addEventListener('abort', onAbort, { once: true });

    async function pumpWriteQueue() {
      if (writeRunning) return;
      writeRunning = true;
      try {
        while (writeTasks.length > 0) {
          if (finished || writeFailed) { writeTasks.length = 0; break; }
          var task = writeTasks.shift();
          try {
            await safeWriter.write(task.pos, task.buf);
            writesPending--;
            if (finished) continue;
            onProgress(task.idx + 1, total);
            tick();
          } catch (e) {
            writesPending--;
            writeFailed = true;
            writeError = e;
            if (!fatalError) {
              fatalError = e;
              try { outerSignal.dispatchEvent(new Event('abort')); } catch (_) {}
              done(e);
            }
          }
        }
      } finally {
        writeRunning = false;
        tryFinish();
      }
    }

    function isBackpressure() {
      if ((pending.size + writesPending) >= MAX_PENDING_CHUNKS) return true;
      if ((pendingBytes + writesPending * CHUNK_SIZE) >= MAX_PENDING_BYTES) return true;
      return false;
    }

    function startOneDownload(idx) {
      var start = idx * CHUNK_SIZE;
      var end = Math.min(start + CHUNK_SIZE - 1, meta.fileSize - 1);
      inFlight++;
      downloadChunk(proxyUrl, idx, start, end, outerSignal)
        .then(function (buf) {
          inFlight--;
          if (finished) return;
          pending.set(idx, buf);
          pendingBytes += buf.byteLength;
          tick();
        })
        .catch(function (e) {
          inFlight--;
          if (finished) return;
          if (!fatalError) {
            fatalError = e;
            try { outerSignal.dispatchEvent(new Event('abort')); } catch (_) {}
            done(e);
          }
        });
    }

    function tick() {
      if (finished) return;
      while (pending.has(nextWriteIdx)) {
        var idx = nextWriteIdx;
        var buf = pending.get(idx);
        pending.delete(idx);
        pendingBytes -= buf.byteLength;
        nextWriteIdx++;
        writeTasks.push({ idx: idx, pos: idx * CHUNK_SIZE, buf: buf });
        writesPending++;
      }
      pumpWriteQueue();
      while (inFlight < CONCURRENCY && nextIdx < total && !isBackpressure()) {
        startOneDownload(nextIdx++);
      }
      tryFinish();
    }

    tick();
  });
}

// ==================== 开始下载 ====================
async function startDownload() {
  if (isDownloading) { setStatus('已有下载任务进行中', 'err'); return; }
  var rawUrl = $('urlInput').value.trim();
  if (!rawUrl) { setStatus('请输入文件地址', 'err'); return; }
  try { new URL(rawUrl); } catch (e) { setStatus('URL 格式不正确', 'err'); return; }

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
  var safeWriter = null;
  var metaRecord = null;
  var chunksSinceFlush = 0;
  var lastFlushTime = Date.now();
  var lastConfirmedChunk = 0;

  try {
    try { await idbCleanupStale(STALE_AGE_MS); } catch (_) {}

    var existingMeta = await idbGet(STORE_META, rawUrl);
    var fileHandle = null;

    if (existingMeta && existingMeta.fileHandle) {
      var recovered = false;
      var recoverError = null;
      try {
        var perm = await existingMeta.fileHandle.queryPermission({ mode: 'readwrite' });
        if (perm !== 'granted') perm = await existingMeta.fileHandle.requestPermission({ mode: 'readwrite' });
        if (perm === 'granted') {
          await existingMeta.fileHandle.getFile();
          fileHandle = existingMeta.fileHandle;
          recovered = true;
          setStatus('已恢复之前的文件句柄，准备续传…', 'info');
        }
      } catch (e) { recoverError = e; console.warn('恢复文件句柄失败', e); }
      if (!recovered) {
        await idbDelete(STORE_META, rawUrl);
        existingMeta = null;
        if (recoverError && recoverError.name === 'NotAllowedError') setStatus('文件系统访问权限已被撤销，请重新选择保存位置', 'info');
        else if (recoverError && recoverError.name === 'NotFoundError') setStatus('原文件已不存在，请重新选择保存位置', 'info');
        else setStatus('之前的文件已失效或无法访问，请重新选择保存位置', 'info');
      }
    }

    if (!fileHandle) {
      setStatus('请选择保存位置…', 'info');
      try { fileHandle = await window.showSaveFilePicker({ suggestedName: guessFileName(rawUrl) }); }
      catch (e) {
        if (e && e.name === 'AbortError') { setStatus('已取消选择保存位置', 'err'); return; }
        throw e;
      }
      existingMeta = null;
    }

    setStatus('正在探测文件信息…', 'info');
    var meta = await probeFile(proxyUrl, abortController.signal);

    var resumeFrom = 0;
    if (existingMeta) {
      var oldSingle = !!existingMeta.singleRequest;
      var newSingle = !!meta.singleRequest;

      if (newSingle) {
        if (oldSingle) setStatus('该文件为单请求模式（服务器不支持 Range），无法续传，将重新下载', 'warn');
        else setStatus('服务器行为变化（分段→单请求），将从头上传', 'warn');
        await idbDelete(STORE_META, rawUrl);
        existingMeta = null;
        resumeFrom = 0;
      } else if (oldSingle) {
        setStatus('服务器行为变化（单请求→分段），将从头上传', 'warn');
        await idbDelete(STORE_META, rawUrl);
        existingMeta = null;
        resumeFrom = 0;
      } else {
        var sameSize = existingMeta.fileSize === meta.fileSize;
        var oldHasEtag = !!existingMeta.etag;
        var newHasEtag = !!meta.etag;
        var oldHasLm = !!existingMeta.lastModified;
        var newHasLm = !!meta.lastModified;
        var etagStateChanged = (oldHasEtag !== newHasEtag);
        var lmStateChanged = (oldHasLm !== newHasLm);
        var etagMatch = oldHasEtag && newHasEtag && existingMeta.etag === meta.etag;
        var lmMatch = oldHasLm && newHasLm && existingMeta.lastModified === meta.lastModified;
        var hasAnyValidator = (newHasEtag || newHasLm);

        if (!sameSize) { setStatus('文件大小已变化，从头开始下载', 'info'); resumeFrom = 0; }
        else if (!hasAnyValidator || etagStateChanged || lmStateChanged) {
          setStatus('服务器验证器状态不一致，无法安全续传，将从头上传', 'info'); resumeFrom = 0;
        } else if (!newHasEtag && newHasLm) {
          setStatus('服务器仅提供 Last-Modified 弱验证器，为防止文件损坏，将从头上传', 'warn'); resumeFrom = 0;
        } else if (etagMatch && lmMatch) {
          resumeFrom = existingMeta.nextChunk || 0;
          if (resumeFrom > 0) {
            setStatus('续传：从第 ' + (resumeFrom + 1) + '/' + meta.totalChunks + ' 片开始（已写入 '
              + formatBytes(resumeFrom * CHUNK_SIZE) + '）', 'info');
          }
        } else { setStatus('文件已变化，从头开始下载', 'info'); resumeFrom = 0; }
      }
    }

    writable = await fileHandle.createWritable({ keepExistingData: true });
    safeWriter = makeSafeWriter(writable);

    metaRecord = {
      url: rawUrl, fileSize: meta.fileSize, totalChunks: meta.totalChunks,
      etag: meta.etag, lastModified: meta.lastModified, fileName: meta.fileName,
      contentType: meta.contentType, nextChunk: resumeFrom,
      singleRequest: !!meta.singleRequest, fileHandle: fileHandle, updatedAt: Date.now(),
    };
    lastConfirmedChunk = resumeFrom;
    await idbPut(STORE_META, rawUrl, metaRecord);
    updateProgress(Math.min(resumeFrom * CHUNK_SIZE, meta.fileSize), meta.fileSize);

    if (meta.singleRequest) {
      if (meta.unknownSize) {
        setStatus('⚠️ 服务器不支持分段下载，已自动切换为单请求流式模式（大小未知，中断后需重新下载）', 'warn');
      } else if (meta.streamFallback) {
        setStatus('⚠️ 服务器不支持分段下载，已自动切换为单请求流式模式（'
          + formatBytes(meta.fileSize) + '，中断后无法续传）', 'warn');
      } else {
        setStatus('服务器不支持分段下载，已自动切换为单请求流式模式（'
          + formatBytes(meta.fileSize) + '）', 'info');
      }

      await downloadSingleRequestStreaming(
        proxyUrl, meta.fileSize, safeWriter, abortController.signal,
        function (bytesRead, fileSize) {
          lastConfirmedChunk = 1;
          updateProgress(bytesRead, fileSize);
        });
    } else {
      await downloadAllChunks(
        proxyUrl, meta, resumeFrom, safeWriter, abortController.signal,
        function (nextChunk, total) {
          lastConfirmedChunk = nextChunk;
          var downloaded = Math.min(nextChunk * CHUNK_SIZE, meta.fileSize);
          updateProgress(downloaded, meta.fileSize);

          metaRecord.nextChunk = nextChunk;
          chunksSinceFlush++;
          var now = Date.now();
          var shouldFlush = chunksSinceFlush >= META_FLUSH_CHUNK_COUNT ||
                            (now - lastFlushTime) >= META_FLUSH_INTERVAL_MS ||
                            nextChunk === total;
          if (shouldFlush) {
            var snapshot = {
              url: rawUrl, fileSize: meta.fileSize, totalChunks: meta.totalChunks,
              etag: meta.etag, lastModified: meta.lastModified, fileName: meta.fileName,
              contentType: meta.contentType, nextChunk: nextChunk,
              singleRequest: !!meta.singleRequest, fileHandle: fileHandle, updatedAt: now,
            };
            queueIdbPut(STORE_META, rawUrl, snapshot).catch(function (err) {
              console.warn('IndexedDB 写入失败:', err);
              setStatus('⚠️ 进度保存失败，如中断可能无法续传', 'err');
            });
            chunksSinceFlush = 0;
            lastFlushTime = now;
          }
        });
    }

    if (safeWriter.isBroken()) {
      writableClosed = true;
      try { await writable.abort(); } catch (_) {}
      throw new Error('文件句柄已损坏（可能磁盘已满或设备断开），下载失败');
    }

    try {
      await writable.close();
      writableClosed = true;
    } catch (closeErr) {
      writableClosed = true;
      var closeMsg = closeErr && (closeErr.message || closeErr.name) || '未知错误';
      throw new Error('文件保存失败（可能磁盘已满或设备断开）：' + closeMsg);
    }

    await idbDelete(STORE_META, rawUrl);
    metaRecord = null;

    var doneSizeText = meta.fileSize > 0 ? formatBytes(meta.fileSize) : '大小未知';
    setStatus('✅ 下载完成：' + meta.fileName + '（' + doneSizeText + '）', 'ok');
    if (meta.fileSize > 0) {
      updateProgress(meta.fileSize, meta.fileSize);
    } else {
      $('progressFill').classList.remove('indeterminate');
      $('progressFill').style.width = '100%';
      $('progressPct').textContent = '100%';
      $('progressLabel').textContent = '完成（总大小未知）';
    }
  } catch (e) {
    try { await waitIdbQueue(); } catch (_) {}
    var isCloseFailure = e && e.message && (
      e.message.indexOf('文件保存失败') !== -1 ||
      e.message.indexOf('文件句柄已损坏') !== -1);
    if (isCloseFailure) {
      try { await idbDelete(STORE_META, rawUrl); } catch (_) {}
      metaRecord = null;
      setStatus('❌ ' + e.message, 'err');
    } else {
      if (metaRecord && !metaRecord.singleRequest) {
        metaRecord.nextChunk = lastConfirmedChunk;
        try { metaRecord.updatedAt = Date.now(); await idbPut(STORE_META, rawUrl, metaRecord); } catch (_) {}
      } else if (metaRecord && metaRecord.singleRequest) {
        try { await idbDelete(STORE_META, rawUrl); } catch (_) {}
      }
      if (abortController && abortController.signal.aborted) {
        setStatus('下载已取消' + (metaRecord && !metaRecord.singleRequest ? '（进度已保存，可续传）' : '（单请求模式需重新下载）'), 'err');
      } else if (e && e.message === 'ABORTED') {
        setStatus('下载已取消' + (metaRecord && !metaRecord.singleRequest ? '（进度已保存，可续传）' : '（单请求模式需重新下载）'), 'err');
      } else {
        setStatus('❌ ' + (e && e.message ? e.message : String(e)), 'err');
      }
    }
  } finally {
    if (writable && !writableClosed) {
      try {
        if (safeWriter && safeWriter.isBroken()) await writable.abort();
        else await writable.close();
        writableClosed = true;
      } catch (ce) {
        console.error('finally 中释放句柄失败:', ce);
        try { await writable.abort(); } catch (_) {}
        writableClosed = true;
      }
    }
    try { await waitIdbQueue(); } catch (_) {}
    await new Promise(function (r) { setTimeout(r, 100); });
    isDownloading = false;
    $('startBtn').disabled = false;
    $('cancelBtn').disabled = true;
    abortController = null;
  }
}

function cancelDownload() { if (abortController) abortController.abort(); }

window.addEventListener('DOMContentLoaded', async function () {
  try {
    try { await idbCleanupStale(STALE_AGE_MS); } catch (_) {}
    var metas = await idbGetAll(STORE_META);
    var pending = metas.filter(function (m) {
      return m && typeof m.nextChunk === 'number' && m.nextChunk < m.totalChunks;
    });
    if (pending.length > 0) {
      pending.sort(function (a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0); });
      var latest = pending[0];
      $('urlInput').value = latest.url;
      setStatus('检测到未完成的下载（' + latest.fileName + '，已下载 '
        + latest.nextChunk + '/' + latest.totalChunks + ' 片），点击"开始下载"继续', 'info');
    }
  } catch (e) { console.warn('页面加载初始化失败', e); }
});

$('urlInput').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') startDownload();
});
</script>
</body>
</html>`;
}