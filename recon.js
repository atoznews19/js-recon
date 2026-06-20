(function(){
    'use strict';

    /* ── Patterns ──────────────────────────────────────────────────────── */
    const P = {
        endpoints:   /(?:"|'|`)([a-zA-Z0-9_\-\.]*\/[a-zA-Z0-9_\-\.\/\?=&#%]{2,})(?:"|'|`)/g,
        credentials: /(?:"|'|`)?(api[_-]?key|secret[_-]?key?|password|passwd|token|auth[_-]?token|access[_-]?token|bearer|jwt|aws[_-]?(?:access[_-]?)?key|private[_-]?key|slack[_-]?token|client[_-]?secret|app[_-]?secret|encryption[_-]?key|session[_-]?(?:token|key)|x[_-]?api[_-]?key)(?:"|'|`)?\s*[:=]\s*(?:"|'|`)([a-zA-Z0-9_\-\.\~\+\/=]{12,})(?:"|'|`)/gi,
        jwt:         /\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b/g,
        cloudKeys: new RegExp([
            'AIzaSy[A-Za-z0-9_\\-]{33}',
            'AAAA[A-Za-z0-9_\\-]{7}:[A-Za-z0-9_\\-]{140}',
            'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'AKIA[0-9A-Z]{16}',
            'sq0idp-[0-9A-Za-z\\-_]{22}',
            'sq0atp-[0-9A-Za-z\\-_]{22}',
            'sk_live_[0-9a-zA-Z]{24,}',
            'pk_live_[0-9a-zA-Z]{24,}',
            'rk_live_[0-9a-zA-Z]{24,}',
            'ghp_[0-9a-zA-Z]{36}',
            'github_pat_[0-9a-zA-Z_]{82}',
            'glpat-[0-9a-zA-Z\\-_]{20}',
            'xox[baprs]-[0-9a-zA-Z\\-]{10,}',
            'key-[0-9a-zA-Z]{32}',
            '[0-9a-f]{32}-us[0-9]{1,2}',
            'SG\\.[0-9a-zA-Z\\-_]{22}\\.[0-9a-zA-Z\\-_]{43}',
            'ya29\\.[0-9a-zA-Z\\-_]{50,}',
            'ey[A-Za-z0-9]{2}[A-Za-z0-9\\-_]{100,}',
        ].join('|'), 'g'),
        s3:         /https?:\/\/([a-z0-9.\-]+)\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com\/[^\s"'`<>]*/gi,
        subdomains: /(?:https?:\/\/)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\.[a-zA-Z]{2,6})/gi,
    };

    const SKIP_EXTS  = /\.(js|css|svg|png|jpg|jpeg|gif|webp|woff2?|ttf|eot|otf|ico|map|br|gz)(\?.*)?$/i;
    const SKIP_HOSTS = ['w3.org','schema.org','mozilla.org','jquery.com','google.com','googleapis.com','gstatic.com','cloudflare.com','unpkg.com','jsdelivr.net','cdnjs.com'];

    /* ── State ─────────────────────────────────────────────────────────── */
    const D = {
        endpoints:    new Set(),
        fullUrls:     new Set(),
        curls:        new Set(),
        secrets:      new Set(),
        targetSubs:   new Set(),
        potentialSubs:new Set(),
        s3Buckets:    new Set(),
        sources:      [],
        bookmarks:    [],   /* { url, note, tag, ts } */
        scanned:      0,
        total:        0,
    };

    const baseUrl     = window.location.origin;
    const currentHost = window.location.hostname;
    const MULTI_TLD   = /\.(co|com|net|org|gov|edu|ac)\.[a-z]{2}$/i;
    const parts       = currentHost.split('.');
    const rootDomain  = MULTI_TLD.test(currentHost) ? parts.slice(-3).join('.') : parts.slice(-2).join('.');
    D.targetSubs.add(currentHost);

    /* ── Scanner ────────────────────────────────────────────────────────── */
    function resetIdx() { Object.values(P).forEach(r => { if (r.lastIndex !== undefined) r.lastIndex = 0; }); }

    function scanText(text) {
        resetIdx();
        let m;
        while ((m = P.endpoints.exec(text)) !== null) {
            const raw = m[1];
            if (!raw.startsWith('/') || raw.startsWith('//') || raw.length < 3) continue;
            if (SKIP_EXTS.test(raw)) continue;
            if (raw.includes('w3.org') || raw.includes('schema.org')) continue;
            const clean = raw.replace(/\\/g, '');
            D.endpoints.add(clean);
            const url = baseUrl + (clean.startsWith('/') ? '' : '/') + clean;
            if (D.fullUrls.has(url)) continue;
            D.fullUrls.add(url);
            D.curls.add(`curl -si -X GET "${url}" \\\n  -H "User-Agent: Mozilla/5.0 (compatible; Recon/1.0)" \\\n  -H "Accept: application/json, text/plain, */*" \\\n  -H "Origin: ${baseUrl}"`);
        }
        resetIdx();
        while ((m = P.credentials.exec(text)) !== null) D.secrets.add(`[Credential] ${m[1]} = ${m[2]}`);
        resetIdx(); P.jwt.lastIndex = 0;
        while ((m = P.jwt.exec(text)) !== null) D.secrets.add(`[JWT] ${m[0].substring(0,80)}...`);
        resetIdx(); P.cloudKeys.lastIndex = 0;
        while ((m = P.cloudKeys.exec(text)) !== null) D.secrets.add(`[API Key] ${m[0]}`);
        resetIdx(); P.s3.lastIndex = 0;
        while ((m = P.s3.exec(text)) !== null) D.s3Buckets.add(m[0]);
        resetIdx(); P.subdomains.lastIndex = 0;
        while ((m = P.subdomains.exec(text)) !== null) {
            const sub = m[1].replace(/^https?:\/\//i,'').toLowerCase().replace(/\/$/, '');
            if (SKIP_HOSTS.some(h => sub.includes(h))) continue;
            if (sub.endsWith(rootDomain)) D.targetSubs.add(sub);
            else if (!sub.startsWith('www.') && sub.includes('.') && !/\d+\.\d+\.\d+\.\d+/.test(sub)) D.potentialSubs.add(sub);
        }
    }

    scanText(document.documentElement.outerHTML);

    const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.src).filter(Boolean)
        .filter(u => { try { return new URL(u).hostname === currentHost || !SKIP_HOSTS.some(h => u.includes(h)); } catch(_){ return false; } });
    D.sources = scriptSrcs;
    D.total   = scriptSrcs.length;

    /* ── Bookmark helpers ───────────────────────────────────────────────── */
    function addBookmark(url, note, tag) {
        if (D.bookmarks.find(b => b.url === url)) return false;
        D.bookmarks.push({ url: url.trim(), note: (note||'').trim(), tag: (tag||'').trim(), ts: new Date().toISOString() });
        return true;
    }
    function removeBookmark(url) {
        const i = D.bookmarks.findIndex(b => b.url === url);
        if (i !== -1) { D.bookmarks.splice(i, 1); return true; }
        return false;
    }
    function isBookmarked(url) { return !!D.bookmarks.find(b => b.url === url); }

    /* ── Build UI ────────────────────────────────────────────────────────── */
    function buildUI() {
        const existing = document.getElementById('__recon__');
        if (existing) existing.remove();

        const root = document.createElement('div');
        root.id = '__recon__';
        root.setAttribute('role','dialog');
        root.setAttribute('aria-label','Recon Dashboard');

        root.innerHTML = `
<style>
#__recon__ *{box-sizing:border-box;font-family:monospace}
#__recon__{position:fixed;top:40px;right:40px;width:960px;max-width:95vw;height:640px;max-height:90vh;background:#0d0d0d;color:#e0e0e0;z-index:2147483647;display:flex;flex-direction:column;border:1px solid #2a2a2a;border-radius:6px;overflow:hidden;user-select:none}
#__recon__ #rh{background:#111;padding:8px 12px;display:flex;align-items:center;gap:10px;cursor:move;border-bottom:1px solid #222;flex-shrink:0}
#__recon__ #rh-scope{font-size:11px;color:#888;flex:1}
#__recon__ #rh-scope b{color:#4d9cff}
#__recon__ #rh-status{font-size:11px;color:#555}
#__recon__ #rh-close{margin-left:8px;background:#c0392b;color:#fff;border:none;padding:4px 10px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:12px}
#__recon__ #rh-close:hover{background:#e74c3c}
#__recon__ #rtabs{display:flex;flex-wrap:wrap;gap:4px;padding:7px 10px;background:#111;border-bottom:1px solid #1e1e1e;flex-shrink:0}
#__recon__ .rtab{background:transparent;border:1px solid #2a2a2a;border-radius:3px;padding:4px 9px;cursor:pointer;font-family:monospace;font-size:11px;transition:background .1s}
#__recon__ .rtab:hover{background:#1a1a1a}
#__recon__ .rtab.active{background:#1c1c1c;border-color:#444}
#__recon__ .rtab .tc{display:inline-block;margin-left:5px;font-size:10px;background:#222;border-radius:8px;padding:0 5px;line-height:16px;color:#aaa}
#__recon__ #rtool{display:flex;align-items:center;gap:6px;padding:6px 10px;background:#0a0a0a;border-bottom:1px solid #1a1a1a;flex-shrink:0}
#__recon__ #rtool input[type=text]{flex:1;background:#111;border:1px solid #2a2a2a;color:#ccc;padding:4px 8px;border-radius:3px;font-family:monospace;font-size:11px;outline:none}
#__recon__ #rtool input::placeholder{color:#444}
#__recon__ .rbtn{background:#1a1a1a;border:1px solid #2e2e2e;color:#aaa;padding:4px 10px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:11px}
#__recon__ .rbtn:hover{background:#252525;color:#ddd}
#__recon__ .rbtn.bm-add{border-color:#2a4a2a;color:#4caf50}
#__recon__ .rbtn.bm-add:hover{background:#1a2e1a;color:#66bb6a}
#__recon__ #rbody{flex:1;overflow:hidden;display:flex;flex-direction:column}
#__recon__ #rout{flex:1;width:100%;background:transparent;color:#d4d4d4;border:none;resize:none;font-family:monospace;font-size:11px;outline:none;white-space:pre;overflow:auto;line-height:1.6;padding:10px}
/* Bookmark panel */
#__recon__ #bm-panel{flex:1;display:flex;flex-direction:column;overflow:hidden}
#__recon__ #bm-add-bar{display:flex;gap:6px;padding:8px 10px;border-bottom:1px solid #1a1a1a;flex-shrink:0;background:#0c0c0c}
#__recon__ #bm-add-bar input{background:#111;border:1px solid #2a2a2a;color:#ccc;padding:4px 8px;border-radius:3px;font-family:monospace;font-size:11px;outline:none}
#__recon__ #bm-url-in{flex:2}
#__recon__ #bm-note-in{flex:2}
#__recon__ #bm-tag-in{flex:1}
#__recon__ #bm-list{flex:1;overflow-y:auto;padding:6px 10px;display:flex;flex-direction:column;gap:5px}
#__recon__ .bm-row{background:#111;border:1px solid #222;border-radius:4px;padding:7px 10px;display:flex;align-items:flex-start;gap:8px}
#__recon__ .bm-row:hover{border-color:#333}
#__recon__ .bm-info{flex:1;min-width:0}
#__recon__ .bm-url{color:#4d9cff;font-size:11px;word-break:break-all;cursor:pointer;text-decoration:none}
#__recon__ .bm-url:hover{text-decoration:underline}
#__recon__ .bm-meta{display:flex;gap:8px;margin-top:3px;flex-wrap:wrap}
#__recon__ .bm-note{font-size:10px;color:#888}
#__recon__ .bm-tag{font-size:10px;color:#333;background:#1e1e1e;border:1px solid #2a2a2a;border-radius:10px;padding:0 6px;line-height:16px}
#__recon__ .bm-tag.t-recon{color:#b87fff;border-color:#3a2a4a}
#__recon__ .bm-tag.t-vuln{color:#ff4444;border-color:#4a1a1a}
#__recon__ .bm-tag.t-info{color:#4d9cff;border-color:#1a2a4a}
#__recon__ .bm-tag.t-s3{color:#ff8c00;border-color:#3a2a00}
#__recon__ .bm-tag.t-secret{color:#ff4444;border-color:#4a1a1a}
#__recon__ .bm-ts{font-size:9px;color:#333}
#__recon__ .bm-del{background:transparent;border:none;color:#444;cursor:pointer;font-size:13px;padding:0 2px;line-height:1;flex-shrink:0}
#__recon__ .bm-del:hover{color:#e74c3c}
#__recon__ #bm-empty{color:#333;font-size:12px;text-align:center;padding:40px 0}
#__recon__ #bm-footer{padding:6px 10px;border-top:1px solid #1a1a1a;display:flex;gap:6px;align-items:center;flex-shrink:0;background:#0a0a0a}
#__recon__ #bm-filter-tag{background:#111;border:1px solid #2a2a2a;color:#ccc;padding:3px 6px;border-radius:3px;font-family:monospace;font-size:11px;outline:none}
#__recon__ #bm-count{font-size:11px;color:#444;flex:1}
</style>
<div id="rh">
  <span id="rh-scope">Scope: <b>*.${rootDomain}</b></span>
  <span id="rh-status">Scanning scripts…</span>
  <button id="rh-close">✕ Close</button>
</div>
<div id="rtabs">
  <button class="rtab active" data-tab="curls"       style="color:#e6a817">PoC cURLs<span class="tc" id="c-curls">0</span></button>
  <button class="rtab"        data-tab="fullUrls"    style="color:#4d9cff">Full URLs<span class="tc" id="c-fullUrls">0</span></button>
  <button class="rtab"        data-tab="endpoints"   style="color:#00cc99">Relative Paths<span class="tc" id="c-endpoints">0</span></button>
  <button class="rtab"        data-tab="targetSubs"  style="color:#b87fff">Target Subs<span class="tc" id="c-targetSubs">0</span></button>
  <button class="rtab"        data-tab="potentialSubs" style="color:#777">Other Hosts<span class="tc" id="c-potentialSubs">0</span></button>
  <button class="rtab"        data-tab="s3Buckets"   style="color:#ff8c00">S3 Buckets<span class="tc" id="c-s3Buckets">0</span></button>
  <button class="rtab"        data-tab="secrets"     style="color:#ff4444;font-weight:bold">Secrets<span class="tc" id="c-secrets">0</span></button>
  <button class="rtab"        data-tab="sources"     style="color:#555">JS Sources<span class="tc" id="c-sources">0</span></button>
  <button class="rtab"        data-tab="bookmarks"   style="color:#f0c040;font-weight:bold">★ Bookmarks<span class="tc" id="c-bookmarks">0</span></button>
</div>
<div id="rtool">
  <input id="rfilter" type="text" placeholder="Filter results…" aria-label="Filter results" />
  <button class="rbtn bm-add" id="rbtn-bm">★ Bookmark selected line</button>
  <button class="rbtn" id="rbtn-copy">Copy</button>
  <button class="rbtn" id="rbtn-export">Export All</button>
</div>
<div id="rbody">
  <textarea id="rout" readonly aria-label="Results"></textarea>
  <div id="bm-panel" style="display:none">
    <div id="bm-add-bar">
      <input id="bm-url-in"  type="text" placeholder="URL or finding to bookmark…" />
      <input id="bm-note-in" type="text" placeholder="Note (optional)…" />
      <input id="bm-tag-in"  type="text" placeholder="Tag: recon/vuln/info/s3/secret" />
      <button class="rbtn bm-add" id="bm-add-btn">+ Add</button>
    </div>
    <div id="bm-list"></div>
    <div id="bm-footer">
      <span id="bm-count">0 bookmarks</span>
      <input id="bm-filter-tag" type="text" placeholder="Filter by tag…" />
      <button class="rbtn" id="bm-export-btn">Export Bookmarks</button>
      <button class="rbtn" id="bm-clear-btn" style="color:#c0392b">Clear All</button>
    </div>
  </div>
</div>`;

        document.body.appendChild(root);

        const out      = root.querySelector('#rout');
        const filterIn = root.querySelector('#rfilter');
        const bmPanel  = root.querySelector('#bm-panel');
        const bmList   = root.querySelector('#bm-list');

        let activeTab = 'curls';
        let filterVal = '';

        /* ── Drag ── */
        const header = root.querySelector('#rh');
        let dx=0,dy=0,dragging=false;
        header.addEventListener('mousedown', e => {
            if (e.target.id==='rh-close') return;
            dragging=true; dx=e.clientX-root.offsetLeft; dy=e.clientY-root.offsetTop; e.preventDefault();
        });
        document.addEventListener('mousemove', e => {
            if (!dragging) return;
            root.style.left=(e.clientX-dx)+'px'; root.style.top=(e.clientY-dy)+'px'; root.style.right='auto';
        });
        document.addEventListener('mouseup', () => dragging=false);

        /* ── Render text tabs ── */
        function tabData() {
            if (activeTab==='sources') return D.sources;
            return Array.from(D[activeTab]||[]);
        }

        function render() {
            if (activeTab==='bookmarks') { renderBM(); return; }
            const raw = tabData();
            const filtered = filterVal ? raw.filter(l => l.toLowerCase().includes(filterVal)) : raw;
            out.value = filtered.join(activeTab==='curls' ? '\n\n' : '\n') || '(no results)';
            updateCounts();
        }

        function updateCounts() {
            ['curls','fullUrls','endpoints','targetSubs','potentialSubs','s3Buckets','secrets'].forEach(k => {
                const el = document.getElementById('c-'+k);
                if (el) el.textContent = (D[k]||new Set()).size;
            });
            const srcEl = document.getElementById('c-sources');
            if (srcEl) srcEl.textContent = D.sources.length;
            const bmEl = document.getElementById('c-bookmarks');
            if (bmEl) bmEl.textContent = D.bookmarks.length;
        }

        /* ── Render bookmark panel ── */
        function tagClass(tag) {
            const t = (tag||'').toLowerCase();
            if (t==='vuln'||t==='secret') return 't-vuln';
            if (t==='info') return 't-info';
            if (t==='s3') return 't-s3';
            if (t==='recon') return 't-recon';
            if (t==='secret') return 't-secret';
            return '';
        }

        function renderBM() {
            updateCounts();
            const tagFilter = (root.querySelector('#bm-filter-tag').value||'').toLowerCase().trim();
            const list = tagFilter
                ? D.bookmarks.filter(b => b.tag.toLowerCase().includes(tagFilter))
                : D.bookmarks;

            root.querySelector('#bm-count').textContent = `${D.bookmarks.length} bookmark${D.bookmarks.length!==1?'s':''}`;

            if (!list.length) {
                bmList.innerHTML = '<div id="bm-empty">No bookmarks yet.<br>Bookmark any line from other tabs using the ★ button or select a line and click "★ Bookmark selected line".</div>';
                return;
            }

            bmList.innerHTML = '';
            list.slice().reverse().forEach(b => {
                const row = document.createElement('div');
                row.className = 'bm-row';
                const d = new Date(b.ts);
                const ts = `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
                row.innerHTML = `
                  <div class="bm-info">
                    <a class="bm-url" href="${b.url}" target="_blank" rel="noopener">${b.url}</a>
                    <div class="bm-meta">
                      ${b.note ? `<span class="bm-note">${b.note}</span>` : ''}
                      ${b.tag  ? `<span class="bm-tag ${tagClass(b.tag)}">${b.tag}</span>` : ''}
                      <span class="bm-ts">${ts}</span>
                    </div>
                  </div>
                  <button class="bm-del" title="Remove bookmark" data-url="${b.url}">✕</button>`;
                bmList.appendChild(row);
            });

            bmList.querySelectorAll('.bm-del').forEach(btn => {
                btn.addEventListener('click', () => {
                    removeBookmark(btn.dataset.url);
                    renderBM();
                });
            });
        }

        /* ── Quick-bookmark: get selected line from textarea ── */
        function getSelectedLine() {
            const v = out.value;
            const s = out.selectionStart;
            const ls = v.lastIndexOf('\n', s-1)+1;
            const le = v.indexOf('\n', s);
            return v.substring(ls, le===-1 ? v.length : le).trim();
        }

        root.querySelector('#rbtn-bm').addEventListener('click', () => {
            if (activeTab==='bookmarks') return;
            const line = getSelectedLine();
            if (!line) { alert('Click on a line in the results first, then click ★ Bookmark selected line.'); return; }
            /* Auto-detect tag */
            let autoTag = activeTab==='s3Buckets' ? 's3'
                        : activeTab==='secrets'   ? 'secret'
                        : activeTab==='targetSubs'||activeTab==='potentialSubs' ? 'recon'
                        : 'info';
            const note = prompt('Note for this bookmark (optional):', '') || '';
            const tag  = prompt('Tag (recon / vuln / info / s3 / secret):', autoTag) || autoTag;
            if (addBookmark(line, note, tag)) {
                const btn = root.querySelector('#rbtn-bm');
                btn.textContent = '★ Bookmarked!';
                setTimeout(() => btn.textContent='★ Bookmark selected line', 1500);
                updateCounts();
            } else {
                alert('Already bookmarked.');
            }
        });

        /* ── Tabs ── */
        root.querySelectorAll('.rtab').forEach(btn => {
            btn.addEventListener('click', () => {
                root.querySelectorAll('.rtab').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeTab = btn.dataset.tab;
                filterIn.value=''; filterVal='';

                if (activeTab==='bookmarks') {
                    out.style.display='none';
                    bmPanel.style.display='flex';
                    root.querySelector('#rbtn-bm').style.display='none';
                    renderBM();
                } else {
                    out.style.display='block';
                    bmPanel.style.display='none';
                    root.querySelector('#rbtn-bm').style.display='';
                    render();
                }
            });
        });

        /* ── Filter ── */
        filterIn.addEventListener('input', () => { filterVal=filterIn.value.toLowerCase().trim(); render(); });

        /* ── Manual add bookmark from panel ── */
        root.querySelector('#bm-add-btn').addEventListener('click', () => {
            const url  = root.querySelector('#bm-url-in').value.trim();
            const note = root.querySelector('#bm-note-in').value.trim();
            const tag  = root.querySelector('#bm-tag-in').value.trim();
            if (!url) { root.querySelector('#bm-url-in').focus(); return; }
            if (!addBookmark(url, note, tag)) { alert('Already bookmarked.'); return; }
            root.querySelector('#bm-url-in').value='';
            root.querySelector('#bm-note-in').value='';
            root.querySelector('#bm-tag-in').value='';
            renderBM();
        });

        root.querySelector('#bm-url-in').addEventListener('keydown', e => {
            if (e.key==='Enter') root.querySelector('#bm-add-btn').click();
        });

        /* ── Tag filter inside BM panel ── */
        root.querySelector('#bm-filter-tag').addEventListener('input', renderBM);

        /* ── Copy ── */
        root.querySelector('#rbtn-copy').addEventListener('click', () => {
            navigator.clipboard.writeText(out.value).then(() => {
                const btn = root.querySelector('#rbtn-copy');
                btn.textContent='Copied!';
                setTimeout(()=>btn.textContent='Copy',1500);
            }).catch(() => { out.select(); document.execCommand('copy'); });
        });

        /* ── Export bookmarks ── */
        root.querySelector('#bm-export-btn').addEventListener('click', () => {
            const txt = D.bookmarks.map(b =>
                `[${b.tag||'—'}] ${b.url}${b.note ? '  // '+b.note : ''}  (${b.ts})`
            ).join('\n');
            const blob = new Blob([txt], {type:'text/plain'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `bookmarks-${rootDomain}-${Date.now()}.txt`;
            a.click();
        });

        /* ── Clear all bookmarks ── */
        root.querySelector('#bm-clear-btn').addEventListener('click', () => {
            if (!D.bookmarks.length) return;
            if (confirm(`Clear all ${D.bookmarks.length} bookmarks?`)) {
                D.bookmarks.length = 0;
                renderBM();
            }
        });

        /* ── Export all data ── */
        root.querySelector('#rbtn-export').addEventListener('click', () => {
            const data = {
                target: rootDomain,
                timestamp: new Date().toISOString(),
                curls: Array.from(D.curls),
                fullUrls: Array.from(D.fullUrls),
                endpoints: Array.from(D.endpoints),
                targetSubdomains: Array.from(D.targetSubs),
                otherHosts: Array.from(D.potentialSubs),
                s3Buckets: Array.from(D.s3Buckets),
                secrets: Array.from(D.secrets),
                bookmarks: D.bookmarks,
                scannedScripts: D.sources,
            };
            const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `recon-${rootDomain}-${Date.now()}.json`;
            a.click();
        });

        root.querySelector('#rh-close').addEventListener('click', () => root.remove());

        render();
        return { render, updateCounts };
    }

    /* ── Kick off ────────────────────────────────────────────────────────── */
    const ui = buildUI();

    const fetchJobs = D.sources.map(url =>
        fetch(url, {credentials:'omit'})
            .then(r => r.text())
            .then(t => {
                scanText(t);
                D.scanned++;
                const el = document.querySelector('#__recon__ #rh-status');
                if (el) el.textContent = `Scanned ${D.scanned}/${D.total} scripts…`;
                ui.render();
            })
            .catch(() => { D.scanned++; })
    );

    Promise.all(fetchJobs).then(() => {
        const el = document.querySelector('#__recon__ #rh-status');
        if (el) el.textContent = `Done — ${D.scanned} script${D.scanned!==1?'s':''} scanned`;
        ui.render();
    });
})();
