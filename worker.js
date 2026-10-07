/**
 * Cloudflare Worker：分段代理下载 + 流式写入硬盘 + 断点续传
 * 依赖 File System Access API（Chrome / Edge）
 */

const CHUNK_SIZE = 2 * 1024 * 1024;        // 2MB 分片
const DB_NAME = 'cf-downloader-db';
const DB_VERSION = 2;
const STORE_META = 'meta';
const CHUNK_TIMEOUT_MS = 60000;            // 单片下载超时 60s
const PROBE_TIMEOUT_MS = 30000;            // 探测元信息超时 30s
const MAX_RETRIES = 3;                     // 单片最大重试次数
const STALE_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 未完成记录保留 7 天

// ==================== Worker 入口 ====================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/index.html') {
      return new Response(getHTML(), {
        headers: { 'Content-Type': 'text/html;charset=utf-8' },
      });
    }

    if (url.pathname === '/proxy') {
      return handleProxy(request);
    }

    return new Response('Not Found', { status: 404 });
  },
};

// ==================== 后端代理逻辑 ====================
async function handleProxy(request) {
  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');
  if (!targetUrl) {
    return new Response('缺少 url 参数', { status: 400 });
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const forwardHeaders = new Headers();
  for (const [key, value] of request.headers.entries()) {
    const lower = key.toLowerCase();
    if (lower === 'range' || lower === 'if-range') {
      forwardHeaders.set(key, value);
    }
  }
  // 要求上游返回未压缩内容，避免长度不匹配
  forwardHeaders.set('Accept-Encoding', 'identity');

  try {
    const upstream = await fetch(targetUrl, {
      method: 'GET',
      headers: forwardHeaders,
      redirect: 'follow',
      cf: { cacheEverything: false, cacheTtl: 0 },
    });

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

    // 移除可能引起长度不匹配的头
    responseHeaders.delete('content-encoding');
    responseHeaders.delete('transfer-encoding');
    responseHeaders.delete('content-length');

    for (const [k, v] of Object.entries(corsHeaders())) {
      responseHeaders.set(k, v);
    }

    // 从 Content-Range 计算精确长度，用 FixedLengthStream 保证 Content-Length 正确
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
        const parsed = parseInt(cl, 10);
        if (!isNaN(parsed) && parsed > 0) expectedLength = parsed;
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
    return new Response('代理请求失败: ' + e.message, { status: 502 });
  }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, If-Range',
    'Access-Control-Expose-Headers':
      'Content-Range, Content-Length, Accept-Ranges, ETag, Last-Modified, Content-Disposition',
    'Cache-Control': 'no-store',
  };
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
  <div class="hint">提示：每下载完一片会立即写入你选择的文件。刷新页面后重新输入同一地址，会自动续传。需 Chrome / Edge 等支持 File System Access API 的浏览器。</div>
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

var abortController = null;

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
    var store = tx.objectStore(storeName);
    var req = store.getAll();
    req.onsuccess = function () { resolve(req.result || []); };
    req.onerror = function () { reject(req.error); };
  });
}

// 清理超过 maxAgeMs 未更新的记录
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

// ==================== 探测文件元信息（带超时 + 可取消） ====================
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
      headers: { Range: 'bytes=0-0' },
      signal: ctrl.signal,
      cache: 'no-store',
    });

    if (!resp.ok && resp.status !== 206) {
      throw new Error('无法获取文件信息，HTTP ' + resp.status);
    }

    var fileSize = 0;
    var contentRange = resp.headers.get('Content-Range');
    if (contentRange) {
      var m = contentRange.match(/\\/(\\d+)\\s*$/);
      if (m) fileSize = parseInt(m[1], 10);
    }
    if (!fileSize) {
      var cl = resp.headers.get('Content-Length');
      if (cl) fileSize = parseInt(cl, 10);
    }
    if (!fileSize) {
      throw new Error('服务器未返回文件大小，无法分段下载');
    }

    var contentType = resp.headers.get('Content-Type') || 'application/octet-stream';
    var etag = resp.headers.get('ETag') || '';

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
      if (fn) {
        try { fileName = decodeURIComponent(fn[1]); } catch (e) {}
      }
    }

    return {
      fileSize: fileSize,
      totalChunks: Math.ceil(fileSize / CHUNK_SIZE),
      contentType: contentType,
      etag: etag,
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

// ==================== 下载单片（带超时与重试） ====================
async function downloadChunk(proxyUrl, index, start, end, outerSignal) {
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
        headers: { Range: 'bytes=' + start + '-' + end },
        signal: ctrl.signal,
        cache: 'no-store',
      });
      if (!resp.ok && resp.status !== 206) {
        throw new Error('HTTP ' + resp.status);
      }
      var buf = await resp.arrayBuffer();
      if (buf.byteLength === 0) throw new Error('空响应');
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
  var rawUrl = $('urlInput').value.trim();
  if (!rawUrl) { setStatus('请输入文件地址', 'err'); return; }
  try { new URL(rawUrl); } catch (e) {
    setStatus('URL 格式不正确', 'err'); return;
  }

  if (!window.showSaveFilePicker) {
    setStatus('当前浏览器不支持 File System Access API，请使用 Chrome 或 Edge', 'err');
    return;
  }

  $('startBtn').disabled = true;
  $('cancelBtn').disabled = false;
  $('progressWrap').classList.add('active');

  abortController = new AbortController();
  var proxyUrl = location.origin + '/proxy?url=' + encodeURIComponent(rawUrl);
  var writable = null;
  var writableClosed = false;

  try {
    // 0. 清理过期记录（超过 STALE_AGE_MS 未更新）
    try { await idbCleanupStale(STALE_AGE_MS); } catch (_) {}

    // 1. 尝试恢复之前的文件句柄
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
          // 验证文件是否仍然存在（被删除/移动会抛 NotFoundError）
          await existingMeta.fileHandle.getFile();
          fileHandle = existingMeta.fileHandle;
          recovered = true;
          setStatus('已恢复之前的文件句柄，准备续传…', 'info');
        }
      } catch (e) {
        console.warn('恢复文件句柄失败，文件可能已被删除或移动', e);
      }
      if (!recovered) {
        // 清理失效记录，走新文件流程
        await idbDelete(STORE_META, rawUrl);
        existingMeta = null;
        setStatus('之前的文件已失效或无法访问，请重新选择保存位置', 'info');
      }
    }

    // 2. 没有可用句柄则弹出保存对话框
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

    // 3. 探测文件信息（传 signal，支持取消 + 30 秒超时）
    setStatus('正在探测文件信息…', 'info');
    var meta = await probeFile(proxyUrl, abortController.signal);

    // 4. 判断续传起点
    var resumeFrom = 0;
    if (existingMeta) {
      var sameSize = existingMeta.fileSize === meta.fileSize;
      var sameEtag = !meta.etag || !existingMeta.etag || existingMeta.etag === meta.etag;
      if (sameSize && sameEtag) {
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

    // 5. 打开可写流（保留已有内容，用于续传）
    writable = await fileHandle.createWritable({ keepExistingData: true });

    // 6. 写入 meta
    var metaRecord = {
      url: rawUrl,
      fileSize: meta.fileSize,
      totalChunks: meta.totalChunks,
      etag: meta.etag,
      fileName: meta.fileName,
      contentType: meta.contentType,
      nextChunk: resumeFrom,
      fileHandle: fileHandle,
      updatedAt: Date.now(),
    };
    await idbPut(STORE_META, rawUrl, metaRecord);

    // 7. 逐片下载并写入硬盘
    for (var i = resumeFrom; i < meta.totalChunks; i++) {
      if (abortController.signal.aborted) throw new Error('ABORTED');

      var start = i * CHUNK_SIZE;
      var end = Math.min(start + CHUNK_SIZE - 1, meta.fileSize - 1);

      setStatus('正在下载第 ' + (i + 1) + '/' + meta.totalChunks + ' 片…', 'info');

      var buf = await downloadChunk(proxyUrl, i, start, end, abortController.signal);

      await writable.write({ type: 'write', position: start, data: buf });

      metaRecord.nextChunk = i + 1;
      metaRecord.updatedAt = Date.now();
      await idbPut(STORE_META, rawUrl, metaRecord);

      var downloaded = Math.min((i + 1) * CHUNK_SIZE, meta.fileSize);
      updateProgress(downloaded, meta.fileSize);
    }

    // 8. 关闭流，数据落盘
    await writable.close();
    writableClosed = true;

    // 9. 清理 meta
    await idbDelete(STORE_META, rawUrl);

    setStatus('✅ 下载完成：' + meta.fileName + '（' + formatBytes(meta.fileSize) + '）', 'ok');
    updateProgress(meta.fileSize, meta.fileSize);
    $('progressLabel').textContent = '完成';
  } catch (e) {
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
    $('startBtn').disabled = false;
    $('cancelBtn').disabled = true;
    abortController = null;
  }
}

// ==================== 取消下载 ====================
function cancelDownload() {
  if (abortController) abortController.abort();
}

// ==================== 页面加载：清理过期 + 显示最近未完成记录 ====================
window.addEventListener('DOMContentLoaded', async function () {
  try {
    // 1. 清理超过 STALE_AGE_MS 的旧记录
    try { await idbCleanupStale(STALE_AGE_MS); } catch (_) {}

    // 2. 读取所有记录，找出最近的未完成项提示用户
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