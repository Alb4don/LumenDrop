(function () {
  'use strict';

  const configNode = document.getElementById('ld-config');
  if (!configNode) return;
  const cfg = JSON.parse(configNode.textContent);
  const S = cfg.strings;
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF = csrfMeta ? csrfMeta.getAttribute('content') : '';
  const FILE_CONCURRENCY = 2;
  const CHUNK_CONCURRENCY = 3;
  const MAX_ATTEMPTS = 8;

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  };
  const fmt = (template, values) => template.replace(/\{(\w+)\}/g, (m, k) => (values[k] !== undefined ? String(values[k]) : m));
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function humanSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = Number(bytes) || 0;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    return unit === 0 ? value.toFixed(0) + ' B' : value.toFixed(1) + ' ' + units[unit];
  }

  function humanDuration(seconds) {
    if (!isFinite(seconds) || seconds < 0) return '';
    if (seconds < 60) return Math.ceil(seconds) + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + Math.ceil(seconds % 60) + 's';
    return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
  }

  function toast(message, isError) {
    const box = $('toasts');
    if (!box) return;
    const node = el('div', 'toast' + (isError ? ' error' : ''), message);
    node.setAttribute('role', isError ? 'alert' : 'status');
    box.appendChild(node);
    setTimeout(() => node.remove(), isError ? 6000 : 3000);
    while (box.children.length > 4) box.firstChild.remove();
  }

  function redirectToLogin() {
    window.location.assign('/login');
  }

  async function api(method, url, body) {
    const headers = { 'X-CSRF-Token': CSRF, 'Accept': 'application/json' };
    const init = { method: method, headers: headers, credentials: 'same-origin', cache: 'no-store' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(url, init);
    } catch (err) {
      return { status: 0, data: null, retryAfter: 0 };
    }
    if (response.status === 401) {
      redirectToLogin();
      return { status: 401, data: null, retryAfter: 0 };
    }
    let data = null;
    try { data = await response.json(); } catch (err) { data = null; }
    const retryAfter = parseInt(response.headers.get('Retry-After') || '0', 10) || 0;
    return { status: response.status, data: data, retryAfter: retryAfter };
  }

  function messageFor(result) {
    if (result && result.data && typeof result.data.detail === 'string') return result.data.detail;
    if (result && result.status === 0) return S.paused_offline;
    return S.server_error;
  }

  const net = {
    online: navigator.onLine !== false,
    waiters: [],
    probing: false,
    banner: $('netBanner'),
    setOnline(value) {
      if (this.online === value) return;
      this.online = value;
      if (this.banner) this.banner.hidden = value;
      if (value) {
        uploader.renderAll();
        const waiting = this.waiters.splice(0);
        waiting.forEach((resolve) => resolve());
      } else {
        uploader.renderAll();
        this.probe();
      }
    },
    waitOnline() {
      if (this.online) return Promise.resolve();
      return new Promise((resolve) => this.waiters.push(resolve));
    },
    async probe() {
      if (this.probing) return;
      this.probing = true;
      let delay = 1500;
      while (!this.online) {
        try {
          const response = await fetch('/api/health', { cache: 'no-store', credentials: 'same-origin' });
          if (response.ok) { this.setOnline(true); break; }
        } catch (err) {}
        await sleep(delay + Math.random() * 500);
        delay = Math.min(delay * 1.6, 10000);
      }
      this.probing = false;
    },
  };
  window.addEventListener('offline', () => net.setOnline(false));
  window.addEventListener('online', () => net.probe());

  const logoutButton = $('logoutButton');
  if (logoutButton) {
    logoutButton.addEventListener('click', async () => {
      await api('POST', '/logout');
      redirectToLogin();
    });
  }

  const gallery = {
    grid: $('fileGrid'),
    empty: $('emptyState'),
    count: $('fileCount'),
    free: $('freeSpace'),
    more: $('loadMore'),
    search: $('searchInput'),
    sort: $('sortSelect'),
    q: '',
    sortKey: 'newest',
    offset: 0,
    total: 0,
    shown: 0,
    token: 0,
    refreshTimer: null,

    init() {
      if (!this.grid) return;
      let debounce = null;
      this.search.addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => { this.q = this.search.value.trim().slice(0, 200); this.load(true); }, 220);
      });
      this.sort.addEventListener('change', () => { this.sortKey = this.sort.value; this.load(true); });
      this.more.addEventListener('click', () => this.load(false));
      this.load(true);
    },

    scheduleRefresh() {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = setTimeout(() => this.load(true), 400);
    },

    async load(reset) {
      const token = ++this.token;
      const offset = reset ? 0 : this.offset;
      const params = new URLSearchParams({ sort: this.sortKey, offset: String(offset), limit: String(cfg.pageSize) });
      if (this.q) params.set('q', this.q);
      const result = await api('GET', '/api/files?' + params.toString());
      if (token !== this.token) return;
      if (result.status !== 200 || !result.data) {
        if (result.status !== 401) toast(messageFor(result), true);
        return;
      }
      const data = result.data;
      if (reset) { this.grid.replaceChildren(); this.shown = 0; }
      const fragment = document.createDocumentFragment();
      data.items.forEach((item) => fragment.appendChild(this.card(item)));
      this.grid.appendChild(fragment);
      this.shown += data.items.length;
      this.offset = offset + data.items.length;
      this.total = data.total;
      this.empty.textContent = this.q ? S.no_results : S.gallery_empty;
      this.empty.hidden = this.total > 0;
      this.more.hidden = this.shown >= this.total;
      this.count.textContent = this.total > 0 ? fmt(S.showing, { shown: this.shown, total: this.total }) : '';
      if (this.free && typeof data.free_bytes === 'number') this.free.textContent = fmt(S.free_space, { size: humanSize(data.free_bytes) });
    },

    card(item) {
      const encoded = encodeURIComponent(item.name);
      const card = el('div', 'file-card');
      const ext = (item.name.includes('.') ? item.name.split('.').pop() : '').slice(0, 5) || 'file';
      const icon = el('div', 'file-icon', ext);
      if (item.image) {
        const img = el('img', 'file-thumb');
        img.alt = '';
        img.loading = 'lazy';
        img.decoding = 'async';
        img.src = item.thumb ? '/thumbs/' + encoded + '?v=' + item.mtime : '/files/' + encoded + '?v=' + item.mtime;
        img.addEventListener('error', () => img.replaceWith(icon), { once: true });
        card.appendChild(img);
      } else {
        card.appendChild(icon);
      }
      const body = el('div', 'file-body');
      if (item.quarantined) {
        const badge = el('div', 'badge-quarantine', S.quarantine_badge);
        badge.title = item.reasons.join(', ');
        body.appendChild(badge);
      }
      body.appendChild(el('div', 'file-name', item.name));
      const when = new Date(item.mtime * 1000);
      body.appendChild(el('div', 'file-meta', humanSize(item.size) + ' · ' + when.toLocaleString()));
      const actions = el('div', 'file-actions');
      const download = el('a', '', S.download);
      download.href = '/files/' + encoded + '?download=1';
      download.setAttribute('download', item.name);
      actions.appendChild(download);
      if (item.sha256) {
        const hashButton = el('button', 'hash', '#');
        hashButton.type = 'button';
        hashButton.title = S.copy_hash;
        hashButton.setAttribute('aria-label', S.copy_hash);
        hashButton.addEventListener('click', () => copyText(item.sha256));
        actions.appendChild(hashButton);
      }
      const del = el('button', 'delete', S.delete);
      del.type = 'button';
      del.addEventListener('click', async () => {
        if (!window.confirm(S.delete_confirm)) return;
        card.classList.add('removing');
        const result = await api('DELETE', '/api/files/' + encoded);
        if (result.status === 200) {
          card.remove();
          this.total = Math.max(0, this.total - 1);
          this.shown = Math.max(0, this.shown - 1);
          this.offset = Math.max(0, this.offset - 1);
          this.count.textContent = this.total > 0 ? fmt(S.showing, { shown: this.shown, total: this.total }) : '';
          this.empty.hidden = this.total > 0;
          toast(S.deleted);
        } else {
          card.classList.remove('removing');
          toast(messageFor(result), true);
        }
      });
      actions.appendChild(del);
      body.appendChild(actions);
      card.appendChild(body);
      return card;
    },
  };

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        toast(S.copied);
        return;
      }
    } catch (err) {}
    const area = el('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    area.remove();
    toast(ok ? S.copied : text, !ok);
  }

  async function sha256Hex(buffer) {
    if (!(window.crypto && window.crypto.subtle && window.isSecureContext)) return null;
    try {
      const digest = await window.crypto.subtle.digest('SHA-256', buffer);
      return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch (err) {
      return null;
    }
  }

  const storage = {
    key(file) { return 'ld:v2:' + file.name + ':' + file.size + ':' + (file.lastModified || 0); },
    get(file) { try { return window.localStorage.getItem(this.key(file)); } catch (err) { return null; } },
    set(file, id) { try { window.localStorage.setItem(this.key(file), id); } catch (err) {} },
    clear(file) { try { window.localStorage.removeItem(this.key(file)); } catch (err) {} },
  };

  class CancelledError extends Error {}
  class FatalUploadError extends Error {}

  const uploader = {
    queue: [],
    active: 0,
    running: 0,
    wakeLock: null,
    list: $('uploadList'),

    add(files) {
      Array.from(files).forEach((file) => {
        if (file.size <= 0) return;
        if (file.size > cfg.maxUpload) { toast(file.name + ': ' + S.file_too_large, true); return; }
        const task = this.createTask(file);
        this.queue.push(task);
      });
      this.pump();
    },

    createTask(file) {
      const row = el('div', 'upload-row');
      const name = el('div', 'upload-name', file.name);
      name.title = file.name;
      const state = el('div', 'upload-state', S.queued);
      const bar = el('progress');
      bar.max = 1000;
      bar.value = 0;
      const actions = el('div', 'upload-actions');
      const cancel = el('button', '', S.cancel);
      cancel.type = 'button';
      actions.appendChild(cancel);
      row.append(name, state, bar, actions);
      this.list.prepend(row);
      const task = {
        file, row, state, bar, actions, cancelled: false, xhrs: new Set(), uploadId: null, chunkSize: 0,
        totalChunks: 0, doneBytes: 0, inflight: new Map(), lastBytes: 0, lastTime: performance.now(), speed: 0,
      };
      cancel.addEventListener('click', () => this.cancel(task));
      return task;
    },

    pump() {
      while (this.running < FILE_CONCURRENCY && this.queue.length) {
        const task = this.queue.shift();
        if (task.cancelled) continue;
        this.running += 1;
        this.setActive(1);
        this.tasks.add(task);
        this.run(task).finally(() => {
          this.tasks.delete(task);
          this.running -= 1;
          this.setActive(-1);
          this.pump();
        });
      }
    },

    async setActive(delta) {
      this.active += delta;
      try {
        if (this.active > 0 && !this.wakeLock && navigator.wakeLock && document.visibilityState === 'visible') {
          this.wakeLock = await navigator.wakeLock.request('screen');
          this.wakeLock.addEventListener('release', () => { this.wakeLock = null; });
        } else if (this.active <= 0 && this.wakeLock) {
          await this.wakeLock.release();
          this.wakeLock = null;
        }
      } catch (err) {
        this.wakeLock = null;
      }
    },

    cancel(task) {
      task.cancelled = true;
      task.xhrs.forEach((xhr) => { try { xhr.abort(); } catch (err) {} });
      if (task.uploadId) {
        api('DELETE', '/api/uploads/' + task.uploadId);
        storage.clear(task.file);
      }
      this.finish(task, 'error', S.cancelled);
    },

    finish(task, cls, text) {
      task.row.classList.remove('done', 'error');
      if (cls) task.row.classList.add(cls);
      task.state.textContent = text;
      task.actions.hidden = true;
      if (cls === 'done') {
        task.bar.value = task.bar.max;
        setTimeout(() => task.row.remove(), 4000);
      }
    },

    tasks: new Set(),

    renderAll() {
      this.tasks.forEach((task) => this.render(task));
    },

    render(task) {
      let inflight = 0;
      task.inflight.forEach((value) => { inflight += value; });
      const sent = Math.min(task.file.size, task.doneBytes + inflight);
      task.bar.value = Math.round((sent / task.file.size) * task.bar.max);
      const now = performance.now();
      const elapsed = (now - task.lastTime) / 1000;
      if (elapsed >= 0.8) {
        const instant = (sent - task.lastBytes) / elapsed;
        task.speed = task.speed ? task.speed * 0.7 + instant * 0.3 : instant;
        task.lastBytes = sent;
        task.lastTime = now;
      }
      const pct = Math.floor((sent / task.file.size) * 100);
      const eta = task.speed > 0 ? humanDuration((task.file.size - sent) / task.speed) : '';
      const speed = task.speed > 0 ? humanSize(task.speed) + '/s' : '';
      task.state.textContent = net.online ? [pct + '%', speed, eta].filter(Boolean).join(' · ') : pct + '% · ' + S.paused_offline;
    },

    async run(task) {
      try {
        await this.prepare(task);
        await this.sendAll(task);
        await this.complete(task);
      } catch (err) {
        if (task.cancelled || err instanceof CancelledError) return;
        this.finish(task, 'error', err && err.message ? err.message : S.failed);
      }
    },

    async prepare(task) {
      task.state.textContent = S.uploading;
      const saved = storage.get(task.file);
      if (saved) {
        const status = await this.request(task, () => api('GET', '/api/uploads/' + saved));
        if (status.status === 200 && status.data && status.data.total_size === task.file.size && status.data.status === 'open') {
          task.uploadId = saved;
          task.chunkSize = status.data.chunk_size;
          task.totalChunks = status.data.total_chunks;
          task.received = new Set(status.data.received);
          return;
        }
        storage.clear(task.file);
      }
      const created = await this.request(task, () => api('POST', '/api/uploads', {
        filename: task.file.name, total_size: task.file.size, chunk_size: cfg.chunk.preferred,
      }));
      if (created.status !== 200 || !created.data) throw new FatalUploadError(messageFor(created));
      task.uploadId = created.data.upload_id;
      task.chunkSize = created.data.chunk_size;
      task.totalChunks = created.data.total_chunks;
      task.received = new Set();
      storage.set(task.file, task.uploadId);
    },

    async request(task, fn) {
      let attempt = 0;
      for (;;) {
        if (task.cancelled) throw new CancelledError();
        await net.waitOnline();
        const result = await fn();
        if (result.status === 0) { net.setOnline(false); continue; }
        if (result.status === 429 || result.status === 503 || (result.status >= 500 && result.status !== 507)) {
          attempt += 1;
          if (attempt >= MAX_ATTEMPTS) return result;
          task.state.textContent = S.retrying;
          await sleep(result.retryAfter ? result.retryAfter * 1000 : backoff(attempt));
          continue;
        }
        return result;
      }
    },

    chunkLength(task, index) {
      return index < task.totalChunks - 1 ? task.chunkSize : task.file.size - task.chunkSize * (task.totalChunks - 1);
    },

    async sendAll(task) {
      task.doneBytes = 0;
      task.received.forEach((index) => { task.doneBytes += this.chunkLength(task, index); });
      const pending = [];
      for (let i = 0; i < task.totalChunks; i += 1) if (!task.received.has(i)) pending.push(i);
      this.render(task);
      let cursor = 0;
      const worker = async () => {
        while (cursor < pending.length) {
          if (task.cancelled) throw new CancelledError();
          const index = pending[cursor];
          cursor += 1;
          await this.sendChunk(task, index);
          task.received.add(index);
          task.doneBytes += this.chunkLength(task, index);
          this.render(task);
        }
      };
      const workers = [];
      for (let w = 0; w < Math.min(CHUNK_CONCURRENCY, pending.length); w += 1) workers.push(worker());
      await Promise.all(workers);
    },

    async sendChunk(task, index) {
      const start = index * task.chunkSize;
      const blob = task.file.slice(start, start + this.chunkLength(task, index));
      let buffer = null;
      let checksum = null;
      if (window.isSecureContext && window.crypto && window.crypto.subtle) {
        buffer = await blob.arrayBuffer();
        checksum = await sha256Hex(buffer);
      }
      let attempt = 0;
      for (;;) {
        if (task.cancelled) throw new CancelledError();
        await net.waitOnline();
        const result = await this.putChunk(task, index, buffer || blob, checksum);
        task.inflight.delete(index);
        if (result.status >= 200 && result.status < 300) return;
        if (result.status === 0) {
          if (task.cancelled) throw new CancelledError();
          net.setOnline(false);
          task.state.textContent = S.paused_offline;
          continue;
        }
        if (result.status === 401) { redirectToLogin(); throw new CancelledError(); }
        if (result.status === 404) { storage.clear(task.file); throw new FatalUploadError(S.session_expired); }
        const retryable = result.status === 429 || result.status === 422 || result.status >= 500;
        if (!retryable || result.status === 507) throw new FatalUploadError(result.detail || S.failed);
        attempt += 1;
        if (attempt >= MAX_ATTEMPTS) throw new FatalUploadError(S.failed);
        task.state.textContent = S.retrying;
        await sleep(result.retryAfter ? result.retryAfter * 1000 : backoff(attempt));
      }
    },

    putChunk(task, index, body, checksum) {
      return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        task.xhrs.add(xhr);
        xhr.open('PUT', '/api/uploads/' + task.uploadId + '/chunks/' + index);
        xhr.setRequestHeader('X-CSRF-Token', CSRF);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        if (checksum) xhr.setRequestHeader('X-Chunk-SHA256', checksum);
        xhr.timeout = 120000;
        xhr.upload.addEventListener('progress', (event) => {
          if (event.lengthComputable) { task.inflight.set(index, event.loaded); this.render(task); }
        });
        const done = (status) => {
          task.xhrs.delete(xhr);
          let detail = null;
          try { detail = JSON.parse(xhr.responseText).detail; } catch (err) { detail = null; }
          resolve({ status: status, retryAfter: parseInt(xhr.getResponseHeader('Retry-After') || '0', 10) || 0, detail: detail });
        };
        xhr.addEventListener('load', () => done(xhr.status));
        xhr.addEventListener('error', () => done(0));
        xhr.addEventListener('timeout', () => done(0));
        xhr.addEventListener('abort', () => done(0));
        xhr.send(body);
      });
    },

    async complete(task) {
      task.state.textContent = S.verifying;
      for (let round = 0; round < 3; round += 1) {
        const result = await this.request(task, () => api('POST', '/api/uploads/' + task.uploadId + '/complete'));
        if (result.status === 200 && result.data) {
          storage.clear(task.file);
          this.finish(task, 'done', S.done);
          if (result.data.quarantined) toast(result.data.name + ': ' + S.quarantine_badge, true);
          gallery.scheduleRefresh();
          return;
        }
        if (result.status === 409) {
          const status = await this.request(task, () => api('GET', '/api/uploads/' + task.uploadId));
          if (status.status !== 200 || !status.data) break;
          task.received = new Set(status.data.received);
          await this.sendAll(task);
          continue;
        }
        if (result.status === 404) storage.clear(task.file);
        throw new FatalUploadError(messageFor(result));
      }
      throw new FatalUploadError(S.failed);
    },
  };

  function backoff(attempt) {
    const cap = Math.min(15000, 500 * Math.pow(2, attempt));
    return Math.floor(Math.random() * cap) + 250;
  }

  function initDropzone() {
    const dropzone = $('dropzone');
    const input = $('fileInput');
    if (!dropzone || !input) return;
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach((type) => {
      document.addEventListener(type, (event) => event.preventDefault());
    });
    dropzone.addEventListener('click', (event) => { if (event.target !== input) input.click(); });
    dropzone.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); }
    });
    dropzone.addEventListener('dragover', () => dropzone.classList.add('dragover'));
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (event) => {
      dropzone.classList.remove('dragover');
      if (event.dataTransfer && event.dataTransfer.files.length) uploader.add(event.dataTransfer.files);
    });
    input.addEventListener('change', () => {
      if (input.files.length) uploader.add(input.files);
      input.value = '';
    });
    document.addEventListener('paste', (event) => {
      const files = event.clipboardData && event.clipboardData.files;
      if (files && files.length) uploader.add(files);
    });
    window.addEventListener('beforeunload', (event) => {
      if (uploader.active > 0) { event.preventDefault(); event.returnValue = S.leave_warning; return S.leave_warning; }
      return undefined;
    });
  }

  initDropzone();
  gallery.init();
})();
