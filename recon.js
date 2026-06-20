(function(){
    'use strict';

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

    /* ── Skip extensions (assets never useful for recon) ── */
    const SKIP_EXTS = /\.(js|css|svg|png|jpg|jpeg|gif|webp|woff2?|ttf|eot|otf|ico|map|br|gz|pdf|xml|txt|csv|zip|tar|mp4|mp3|wav|ogg)(\?.*)?$/i;

    /* ── Noise paths: framework internals, build artifacts, CDN paths ── */
    const NOISE_PATHS = [
        /^\/static\//i, /^\/assets\//i, /^\/dist\//i, /^\/build\//i,
        /^\/public\//i, /^\/node_modules\//i, /^\/vendor\//i,
        /^\/__webpack/i, /^\/_next\//i, /^\/_nuxt\//i, /^\/webpack/i,
        /^\/chunk/i,     /^\/chunks\//i,
        /^\/(wd|tb|cb|fb|gb|rb)\//i,
    ];

    /* ── Noise segment patterns: UUIDs, hashes, version strings ── */
    const NOISE_SEGS = [
        /^[a-f0-9]{8,}$/i,           /* pure hex hash  e.g. a3f9c2b1 */
        /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i, /* UUID */
        /^\d+\.\d+(\.\d+)?$/,         /* version numbers 1.2.3 */
        /^v\d+(\.\d+)*$/i,            /* v1, v2.0 */
    ];

    /* ── Segment keywords that strongly suggest a real API/app path ── */
    const API_HINTS = /^(api|v\d|rest|graphql|gql|auth|oauth|login|logout|signup|register|user|users|account|accounts|admin|dashboard|profile|settings|config|data|search|query|upload|download|export|import|webhook|notify|notification|message|messages|payment|payments|order|orders|cart|checkout|product|products|report|reports|analytics|metrics|health|status|ping|token|refresh|reset|verify|confirm|invite|member|members|team|teams|org|orgs|repo|repos|project|projects|issue|issues|ticket|tickets|feed|feeds|event|events|media|file|files|folder|folders|comment|comments|review|reviews|rating|ratings|like|likes|follow|followers|subscription|subscriptions|session|sessions|log|logs|audit|job|jobs|task|tasks|schedule|hook|hooks|apps|app|service|services|internal|private|public|external|client|clients|partner|partners|billing|invoice|invoices|role|roles|permission|permissions|group|groups|tag|tags|label|labels|category|categories|post|posts|article|articles|content|page|pages|asset|assets)$/i;

    /* ── Global noise hosts ── */
    const SKIP_HOSTS = [
        'w3.org','schema.org','mozilla.org','jquery.com',
        'google.com','googleapis.com','gstatic.com','google-analytics.com','googletagmanager.com',
        'cloudflare.com','cloudflareinsights.com',
        'unpkg.com','jsdelivr.net','cdnjs.com','bootstrapcdn.com',
        'facebook.com','fbcdn.net','twitter.com','twimg.com',
        'youtube.com','ytimg.com','vimeo.com',
        'amazon.com','amazonaws.com','akamai.com','akamaized.net',
        'newrelic.com','sentry.io','segment.com','mixpanel.com','hotjar.com',
        'intercom.io','zendesk.com','hubspot.com','salesforce.com',
        'recaptcha.net','hcaptcha.com',
    ];

    /* ── State ── */
    const D = {
        endpoints:    new Set(),
        fullUrls:     new Set(),
        curls:        new Set(),
        secrets:      new Set(),
        targetSubs:   new Set(),
        potentialSubs:new Set(),
        s3Buckets:    new Set(),
        sources:      [],
        bookmarks:    [],
        scanned:      0,
        total:        0,
    };

    const baseUrl     = window.location.origin;
    const currentHost = window.location.hostname;
    const MULTI_TLD   = /\.(co|com|net|org|gov|edu|ac)\.[a-z]{2}$/i;
    const parts       = currentHost.split('.');
    const rootDomain  = MULTI_TLD.test(currentHost) ? parts.slice(-3).join('.') : parts.slice(-2).join('.');
    D.targetSubs.add(currentHost);

    /* ── Path quality scorer ──────────────────────────────────────────────
       Returns:  'target'    → looks like a real endpoint on this domain
                 'potential' → might be useful, lower confidence
                 'noise'     → skip entirely
    ──────────────────────────────────────────────────────────────────── */
    function classifyPath(raw) {
        /* must start with / and have some substance */
        if (!raw.startsWith('/') || raw.startsWith('//')) return 'noise';
        if (raw.length < 4) return 'noise';

        /* strip query string for path analysis */
        const path = raw.split('?')[0].split('#')[0];

        /* skip pure asset extensions */
        if (SKIP_EXTS.test(path)) return 'noise';

        /* skip known noisy path prefixes (framework internals) */
        if (NOISE_PATHS.some(r => r.test(path))) return 'noise';

        /* skip paths that contain known noise hosts */
        if (SKIP_HOSTS.some(h => raw.includes(h))) return 'noise';

        /* skip paths that are just a MIME type or XML namespace */
        if (/\/(text|application|image|audio|video)\//.test(path)) return 'noise';

        /* skip template placeholders e.g. /{id}, /%s, /:param */
        if (/\/(\{[^}]+\}|:[a-z_]+|%[sd])/.test(path) && path.split('/').length < 3) return 'noise';

        /* check each path segment */
        const segs = path.split('/').filter(Boolean);
        if (segs.length === 0) return 'noise';

        /* if path is deeply nested with all-hash segments → noise */
        const hashSegs = segs.filter(s => NOISE_SEGS.some(r => r.test(s)));
        if (hashSegs.length > 0 && hashSegs.length === segs.length) return 'noise';

        /* score: does any segment look like a real API keyword? */
        const hasApiHint = segs.some(s => API_HINTS.test(s));

        /* score: does path start with /api, /v1, /graphql etc? */
        const startsWithApi = /^\/(api|v\d|graphql|gql|rest|_api|__api)\b/i.test(path);

        /* score: path has reasonable depth (2-6 segments) */
        const goodDepth = segs.length >= 1 && segs.length <= 8;

        /* score: no pure-numeric segments dominating */
        const numericOnly = segs.every(s => /^\d+$/.test(s));
        if (numericOnly) return 'noise';

        /* score: looks like a file reference without useful extension */
        const looksLikeFile = /\.[a-z]{2,5}$/i.test(path) && !SKIP_EXTS.test(path);

        if (startsWithApi && goodDepth) return 'target';
        if (hasApiHint && goodDepth) return 'target';
        if (looksLikeFile && goodDepth) return 'potential';
        if (goodDepth && segs.length >= 2) return 'potential';

        return 'noise';
    }

    /* ── Subdomain classifier ── */
    function classifyHost(sub) {
        if (!sub || sub.length < 4) return 'noise';
        if (SKIP_HOSTS.some(h => sub.includes(h))) return 'noise';
        if (/\d+\.\d+\.\d+\.\d+/.test(sub)) return 'noise';   /* IPv4 */
        if (!sub.includes('.')) return 'noise';

        /* known tracking/analytics subdomains */
        if (/^(cdn\d*|static\d*|assets\d*|media\d*|img\d*|images\d*|fonts\d*|js\d*|css\d*)\./.test(sub)) return 'potential';

        if (sub.endsWith(rootDomain)) return 'target';
        return 'potential';
    }

    /* ── Scanner ── */
    function resetIdx() { Object.values(P).forEach(r => { if (r.lastIndex !== undefined) r.lastIndex = 0; }); }

    function scanText(text) {
        resetIdx();
        let m;

        /* Endpoints */
        while ((m = P.endpoints.exec(text)) !== null) {
            const raw = m[1].replace(/\\/g, '');
            const grade = classifyPath(raw);
            if (grade === 'noise') continue;

            /* only add to endpoints/curls if target-grade */
            if (grade === 'target') {
                D.endpoints.add(raw);
                const url = baseUrl + (raw.startsWith('/') ? '' : '/') + raw;
                if (!D.fullUrls.has(url)) {
                    D.fullUrls.add(url);
                    D.curls.add(
                        'curl -si -X GET "' + url + '" \\\n' +
                        '  -H "User-Agent: Mozilla/5.0 (compatible; Recon/1.0)" \\\n' +
                        '  -H "Accept: application/json, text/plain, */*" \\\n' +
                        '  -H "Origin: ' + baseUrl + '"'
                    );
                }
            } else if (grade === 'potential') {
                /* potential paths go into potentialSubs display as paths */
                const url = baseUrl + (raw.startsWith('/') ? '' : '/') + raw;
                D.potentialSubs.add('[path] ' + url);
            }
        }

        /* Credentials */
        resetIdx();
        while ((m = P.credentials.exec(text)) !== null) D.secrets.add('[Credential] ' + m[1] + ' = ' + m[2]);

        /* JWTs */
        P.jwt.lastIndex = 0;
        while ((m = P.jwt.exec(text)) !== null) D.secrets.add('[JWT] ' + m[0].substring(0,80) + '...');

        /* Cloud keys */
        P.cloudKeys.lastIndex = 0;
        while ((m = P.cloudKeys.exec(text)) !== null) D.secrets.add('[API Key] ' + m[0]);

        /* S3 */
        P.s3.lastIndex = 0;
        while ((m = P.s3.exec(text)) !== null) D.s3Buckets.add(m[0]);

        /* Subdomains */
        P.subdomains.lastIndex = 0;
        while ((m = P.subdomains.exec(text)) !== null) {
            const sub = m[1].replace(/^https?:\/\//i,'').toLowerCase().replace(/\/.*$/, '');
            const grade = classifyHost(sub);
            if (grade === 'noise') continue;
            if (grade === 'target') D.targetSubs.add(sub);
            else D.potentialSubs.add(sub);
        }
    }

    scanText(document.documentElement.outerHTML);

    const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
        .map(function(s){ return s.src; }).filter(Boolean)
        .filter(function(u){
            try {
                var h = new URL(u).hostname;
                return h === currentHost || !SKIP_HOSTS.some(function(sh){ return u.includes(sh); });
            } catch(_){ return false; }
        });
    D.sources = scriptSrcs;
    D.total   = scriptSrcs.length;

    /* ── Bookmark helpers ── */
    function addBookmark(url, note, tag) {
        if (D.bookmarks.find(function(b){ return b.url === url; })) return false;
        D.bookmarks.push({ url: url.trim(), note: (note||'').trim(), tag: (tag||'').trim(), ts: new Date().toISOString() });
        return true;
    }
    function removeBookmark(url) {
        var i = D.bookmarks.findIndex(function(b){ return b.url === url; });
        if (i !== -1) { D.bookmarks.splice(i, 1); return true; }
        return false;
    }

    /* ── Build UI ── */
    function buildUI() {
        var existing = document.getElementById('__recon__');
        if (existing) existing.remove();

        var root = document.createElement('div');
        root.id = '__recon__';
        root.setAttribute('role','dialog');
        root.setAttribute('aria-label','Recon Dashboard');

        root.innerHTML = '<style>' +
'#__recon__ *{box-sizing:border-box;font-family:monospace}' +
'#__recon__{position:fixed;top:40px;right:40px;width:960px;max-width:95vw;height:640px;max-height:90vh;background:#0d0d0d;color:#e0e0e0;z-index:2147483647;display:flex;flex-direction:column;border:1px solid #2a2a2a;border-radius:6px;overflow:hidden;user-select:none}' +
'#__recon__ #rh{background:#111;padding:8px 12px;display:flex;align-items:center;gap:10px;cursor:move;border-bottom:1px solid #222;flex-shrink:0}' +
'#__recon__ #rh-scope{font-size:11px;color:#888;flex:1}' +
'#__recon__ #rh-scope b{color:#4d9cff}' +
'#__recon__ #rh-status{font-size:11px;color:#555}' +
'#__recon__ #rh-close{margin-left:8px;background:#c0392b;color:#fff;border:none;padding:4px 10px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:12px}' +
'#__recon__ #rh-close:hover{background:#e74c3c}' +
'#__recon__ #rtabs{display:flex;flex-wrap:wrap;gap:4px;padding:7px 10px;background:#111;border-bottom:1px solid #1e1e1e;flex-shrink:0}' +
'#__recon__ .rtab{background:transparent;border:1px solid #2a2a2a;border-radius:3px;padding:4px 9px;cursor:pointer;font-family:monospace;font-size:11px;transition:background .1s}' +
'#__recon__ .rtab:hover{background:#1a1a1a}' +
'#__recon__ .rtab.active{background:#1c1c1c;border-color:#444}' +
'#__recon__ .rtab .tc{display:inline-block;margin-left:5px;font-size:10px;background:#222;border-radius:8px;padding:0 5px;line-height:16px;color:#aaa}' +
'#__recon__ #rtool{display:flex;align-items:center;gap:6px;padding:6px 10px;background:#0a0a0a;border-bottom:1px solid #1a1a1a;flex-shrink:0}' +
'#__recon__ #rtool input[type=text]{flex:1;background:#111;border:1px solid #2a2a2a;color:#ccc;padding:4px 8px;border-radius:3px;font-family:monospace;font-size:11px;outline:none}' +
'#__recon__ #rtool input::placeholder{color:#444}' +
'#__recon__ .rbtn{background:#1a1a1a;border:1px solid #2e2e2e;color:#aaa;padding:4px 10px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:11px}' +
'#__recon__ .rbtn:hover{background:#252525;color:#ddd}' +
'#__recon__ .rbtn.bm-add{border-color:#2a4a2a;color:#4caf50}' +
'#__recon__ .rbtn.bm-add:hover{background:#1a2e1a;color:#66bb6a}' +
'#__recon__ #rbody{flex:1;overflow:hidden;display:flex;flex-direction:column}' +
'#__recon__ #rout{flex:1;width:100%;background:transparent;color:#d4d4d4;border:none;resize:none;font-family:monospace;font-size:11px;outline:none;white-space:pre;overflow:auto;line-height:1.6;padding:10px}' +
'#__recon__ #bm-panel{flex:1;display:flex;flex-direction:column;overflow:hidden}' +
'#__recon__ #bm-add-bar{display:flex;gap:6px;padding:8px 10px;border-bottom:1px solid #1a1a1a;flex-shrink:0;background:#0c0c0c}' +
'#__recon__ #bm-add-bar input{background:#111;border:1px solid #2a2a2a;color:#ccc;padding:4px 8px;border-radius:3px;font-family:monospace;font-size:11px;outline:none}' +
'#__recon__ #bm-url-in{flex:2}' +
'#__recon__ #bm-note-in{flex:2}' +
'#__recon__ #bm-tag-in{flex:1}' +
'#__recon__ #bm-list{flex:1;overflow-y:auto;padding:6px 10px;display:flex;flex-direction:column;gap:5px}' +
'#__recon__ .bm-row{background:#111;border:1px solid #222;border-radius:4px;padding:7px 10px;display:flex;align-items:flex-start;gap:8px}' +
'#__recon__ .bm-row:hover{border-color:#333}' +
'#__recon__ .bm-info{flex:1;min-width:0}' +
'#__recon__ .bm-url{color:#4d9cff;font-size:11px;word-break:break-all;cursor:pointer;text-decoration:none}' +
'#__recon__ .bm-url:hover{text-decoration:underline}' +
'#__recon__ .bm-meta{display:flex;gap:8px;margin-top:3px;flex-wrap:wrap}' +
'#__recon__ .bm-note{font-size:10px;color:#888}' +
'#__recon__ .bm-tag{font-size:10px;background:#1e1e1e;border:1px solid #2a2a2a;border-radius:10px;padding:0 6px;line-height:16px;color:#aaa}' +
'#__recon__ .bm-tag.t-recon{color:#b87fff;border-color:#3a2a4a}' +
'#__recon__ .bm-tag.t-vuln{color:#ff4444;border-color:#4a1a1a}' +
'#__recon__ .bm-tag.t-info{color:#4d9cff;border-color:#1a2a4a}' +
'#__recon__ .bm-tag.t-s3{color:#ff8c00;border-color:#3a2a00}' +
'#__recon__ .bm-tag.t-secret{color:#ff4444;border-color:#4a1a1a}' +
'#__recon__ .bm-ts{font-size:9px;color:#333}' +
'#__recon__ .bm-del{background:transparent;border:none;color:#444;cursor:pointer;font-size:13px;padding:0 2px;line-height:1;flex-shrink:0}' +
'#__recon__ .bm-del:hover{color:#e74c3c}' +
'#__recon__ #bm-empty{color:#444;font-size:12px;text-align:center;padding:40px 0}' +
'#__recon__ #bm-footer{padding:6px 10px;border-top:1px solid #1a1a1a;display:flex;gap:6px;align-items:center;flex-shrink:0;background:#0a0a0a}' +
'#__recon__ #bm-filter-tag{background:#111;border:1px solid #2a2a2a;color:#ccc;padding:3px 6px;border-radius:3px;font-family:monospace;font-size:11px;outline:none}' +
'#__recon__ #bm-count{font-size:11px;color:#444;flex:1}' +
'</style>' +
'<div id="rh">' +
'  <span id="rh-scope">Scope: <b>*.' + rootDomain + '</b></span>' +
'  <span id="rh-status">Scanning scripts\u2026</span>' +
'  <button id="rh-close">\u2715 Close</button>' +
'</div>' +
'<div id="rtabs">' +
'  <button class="rtab active" data-tab="curls"        style="color:#e6a817">PoC cURLs<span class="tc" id="c-curls">0</span></button>' +
'  <button class="rtab"        data-tab="fullUrls"     style="color:#4d9cff">Confirmed URLs<span class="tc" id="c-fullUrls">0</span></button>' +
'  <button class="rtab"        data-tab="endpoints"    style="color:#00cc99">API Paths<span class="tc" id="c-endpoints">0</span></button>' +
'  <button class="rtab"        data-tab="targetSubs"   style="color:#b87fff">Target Subs<span class="tc" id="c-targetSubs">0</span></button>' +
'  <button class="rtab"        data-tab="potentialSubs" style="color:#777">Potential<span class="tc" id="c-potentialSubs">0</span></button>' +
'  <button class="rtab"        data-tab="s3Buckets"    style="color:#ff8c00">S3 Buckets<span class="tc" id="c-s3Buckets">0</span></button>' +
'  <button class="rtab"        data-tab="secrets"      style="color:#ff4444;font-weight:bold">Secrets<span class="tc" id="c-secrets">0</span></button>' +
'  <button class="rtab"        data-tab="sources"      style="color:#555">JS Sources<span class="tc" id="c-sources">0</span></button>' +
'  <button class="rtab"        data-tab="bookmarks"    style="color:#f0c040;font-weight:bold">\u2605 Bookmarks<span class="tc" id="c-bookmarks">0</span></button>' +
'</div>' +
'<div id="rtool">' +
'  <input id="rfilter" type="text" placeholder="Filter results\u2026" aria-label="Filter results" />' +
'  <button class="rbtn bm-add" id="rbtn-bm">\u2605 Bookmark line</button>' +
'  <button class="rbtn" id="rbtn-copy">Copy</button>' +
'  <button class="rbtn" id="rbtn-export">Export All</button>' +
'</div>' +
'<div id="rbody">' +
'  <textarea id="rout" readonly aria-label="Results"></textarea>' +
'  <div id="bm-panel" style="display:none">' +
'    <div id="bm-add-bar">' +
'      <input id="bm-url-in"  type="text" placeholder="URL or finding to bookmark\u2026" />' +
'      <input id="bm-note-in" type="text" placeholder="Note (optional)\u2026" />' +
'      <input id="bm-tag-in"  type="text" placeholder="Tag: recon/vuln/info/s3/secret" />' +
'      <button class="rbtn bm-add" id="bm-add-btn">+ Add</button>' +
'    </div>' +
'    <div id="bm-list"></div>' +
'    <div id="bm-footer">' +
'      <span id="bm-count">0 bookmarks</span>' +
'      <input id="bm-filter-tag" type="text" placeholder="Filter by tag\u2026" />' +
'      <button class="rbtn" id="bm-export-btn">Export Bookmarks</button>' +
'      <button class="rbtn" id="bm-clear-btn" style="color:#c0392b">Clear All</button>' +
'    </div>' +
'  </div>' +
'</div>';

        document.body.appendChild(root);

        var out      = root.querySelector('#rout');
        var filterIn = root.querySelector('#rfilter');
        var bmPanel  = root.querySelector('#bm-panel');
        var bmList   = root.querySelector('#bm-list');
        var activeTab = 'curls';
        var filterVal = '';

        /* Drag */
        var header = root.querySelector('#rh');
        var dx=0,dy=0,dragging=false;
        header.addEventListener('mousedown', function(e){
            if (e.target.id==='rh-close') return;
            dragging=true; dx=e.clientX-root.offsetLeft; dy=e.clientY-root.offsetTop; e.preventDefault();
        });
        document.addEventListener('mousemove', function(e){
            if (!dragging) return;
            root.style.left=(e.clientX-dx)+'px'; root.style.top=(e.clientY-dy)+'px'; root.style.right='auto';
        });
        document.addEventListener('mouseup', function(){ dragging=false; });

        function tabData() {
            if (activeTab==='sources') return D.sources;
            return Array.from(D[activeTab]||[]);
        }

        function render() {
            if (activeTab==='bookmarks') { renderBM(); return; }
            var raw = tabData();
            var filtered = filterVal ? raw.filter(function(l){ return l.toLowerCase().includes(filterVal); }) : raw;
            out.value = filtered.join(activeTab==='curls' ? '\n\n' : '\n') || '(no results)';
            updateCounts();
        }

        function updateCounts() {
            ['curls','fullUrls','endpoints','targetSubs','potentialSubs','s3Buckets','secrets'].forEach(function(k){
                var el = document.getElementById('c-'+k);
                if (el) el.textContent = (D[k]||new Set()).size;
            });
            var srcEl = document.getElementById('c-sources');
            if (srcEl) srcEl.textContent = D.sources.length;
            var bmEl = document.getElementById('c-bookmarks');
            if (bmEl) bmEl.textContent = D.bookmarks.length;
        }

        function tagClass(tag) {
            var t = (tag||'').toLowerCase();
            if (t==='vuln'||t==='secret') return 't-vuln';
            if (t==='info') return 't-info';
            if (t==='s3') return 't-s3';
            if (t==='recon') return 't-recon';
            return '';
        }

        function renderBM() {
            updateCounts();
            var tagFilter = (root.querySelector('#bm-filter-tag').value||'').toLowerCase().trim();
            var list = tagFilter ? D.bookmarks.filter(function(b){ return b.tag.toLowerCase().includes(tagFilter); }) : D.bookmarks;
            root.querySelector('#bm-count').textContent = D.bookmarks.length + ' bookmark' + (D.bookmarks.length!==1?'s':'');
            if (!list.length) {
                bmList.innerHTML = '<div id="bm-empty">No bookmarks yet.<br>Click a line in any tab then click \u2605 Bookmark line.</div>';
                return;
            }
            bmList.innerHTML = '';
            list.slice().reverse().forEach(function(b){
                var row = document.createElement('div');
                row.className = 'bm-row';
                var d = new Date(b.ts);
                var ts = d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
                row.innerHTML =
                    '<div class="bm-info">' +
                    '<a class="bm-url" href="' + b.url + '" target="_blank" rel="noopener">' + b.url + '</a>' +
                    '<div class="bm-meta">' +
                    (b.note ? '<span class="bm-note">'+b.note+'</span>' : '') +
                    (b.tag  ? '<span class="bm-tag '+tagClass(b.tag)+'">'+b.tag+'</span>' : '') +
                    '<span class="bm-ts">'+ts+'</span>' +
                    '</div></div>' +
                    '<button class="bm-del" title="Remove" data-url="'+b.url+'">\u2715</button>';
                bmList.appendChild(row);
            });
            bmList.querySelectorAll('.bm-del').forEach(function(btn){
                btn.addEventListener('click', function(){ removeBookmark(btn.dataset.url); renderBM(); });
            });
        }

        function getSelectedLine() {
            var v = out.value, s = out.selectionStart;
            var ls = v.lastIndexOf('\n', s-1)+1;
            var le = v.indexOf('\n', s);
            return v.substring(ls, le===-1 ? v.length : le).trim();
        }

        root.querySelector('#rbtn-bm').addEventListener('click', function(){
            if (activeTab==='bookmarks') return;
            var line = getSelectedLine();
            if (!line) { alert('Click on a line in the results first.'); return; }
            var autoTag = activeTab==='s3Buckets' ? 's3'
                        : activeTab==='secrets'   ? 'secret'
                        : (activeTab==='targetSubs'||activeTab==='potentialSubs') ? 'recon' : 'info';
            var note = prompt('Note (optional):', '') || '';
            var tag  = prompt('Tag (recon/vuln/info/s3/secret):', autoTag) || autoTag;
            if (addBookmark(line, note, tag)) {
                var btn = root.querySelector('#rbtn-bm');
                btn.textContent = '\u2605 Bookmarked!';
                setTimeout(function(){ btn.textContent='\u2605 Bookmark line'; }, 1500);
                updateCounts();
            } else { alert('Already bookmarked.'); }
        });

        root.querySelectorAll('.rtab').forEach(function(btn){
            btn.addEventListener('click', function(){
                root.querySelectorAll('.rtab').forEach(function(b){ b.classList.remove('active'); });
                btn.classList.add('active');
                activeTab = btn.dataset.tab;
                filterIn.value=''; filterVal='';
                if (activeTab==='bookmarks') {
                    out.style.display='none'; bmPanel.style.display='flex';
                    root.querySelector('#rbtn-bm').style.display='none';
                    renderBM();
                } else {
                    out.style.display=''; bmPanel.style.display='none';
                    root.querySelector('#rbtn-bm').style.display='';
                    render();
                }
            });
        });

        filterIn.addEventListener('input', function(){ filterVal=filterIn.value.toLowerCase().trim(); render(); });

        root.querySelector('#bm-add-btn').addEventListener('click', function(){
            var url  = root.querySelector('#bm-url-in').value.trim();
            var note = root.querySelector('#bm-note-in').value.trim();
            var tag  = root.querySelector('#bm-tag-in').value.trim();
            if (!url) { root.querySelector('#bm-url-in').focus(); return; }
            if (!addBookmark(url, note, tag)) { alert('Already bookmarked.'); return; }
            root.querySelector('#bm-url-in').value='';
            root.querySelector('#bm-note-in').value='';
            root.querySelector('#bm-tag-in').value='';
            renderBM();
        });

        root.querySelector('#bm-url-in').addEventListener('keydown', function(e){
            if (e.key==='Enter') root.querySelector('#bm-add-btn').click();
        });

        root.querySelector('#bm-filter-tag').addEventListener('input', renderBM);

        root.querySelector('#rbtn-copy').addEventListener('click', function(){
            navigator.clipboard.writeText(out.value).then(function(){
                var btn = root.querySelector('#rbtn-copy');
                btn.textContent='Copied!';
                setTimeout(function(){ btn.textContent='Copy'; }, 1500);
            }).catch(function(){ out.select(); document.execCommand('copy'); });
        });

        root.querySelector('#bm-export-btn').addEventListener('click', function(){
            var txt = D.bookmarks.map(function(b){
                return '[' + (b.tag||'-') + '] ' + b.url + (b.note ? '  // '+b.note : '') + '  (' + b.ts + ')';
            }).join('\n');
            var blob = new Blob([txt], {type:'text/plain'});
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = 'bookmarks-'+rootDomain+'-'+Date.now()+'.txt'; a.click();
        });

        root.querySelector('#bm-clear-btn').addEventListener('click', function(){
            if (!D.bookmarks.length) return;
            if (confirm('Clear all ' + D.bookmarks.length + ' bookmarks?')) { D.bookmarks.length=0; renderBM(); }
        });

        root.querySelector('#rbtn-export').addEventListener('click', function(){
            var data = {
                target: rootDomain, timestamp: new Date().toISOString(),
                curls: Array.from(D.curls), fullUrls: Array.from(D.fullUrls),
                endpoints: Array.from(D.endpoints), targetSubdomains: Array.from(D.targetSubs),
                potential: Array.from(D.potentialSubs), s3Buckets: Array.from(D.s3Buckets),
                secrets: Array.from(D.secrets), bookmarks: D.bookmarks, scannedScripts: D.sources,
            };
            var blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = 'recon-'+rootDomain+'-'+Date.now()+'.json'; a.click();
        });

        root.querySelector('#rh-close').addEventListener('click', function(){ root.remove(); });

        render();
        return { render: render, updateCounts: updateCounts };
    }

    var ui = buildUI();

    var fetchJobs = D.sources.map(function(url){
        return fetch(url, {credentials:'omit'})
            .then(function(r){ return r.text(); })
            .then(function(t){
                scanText(t);
                D.scanned++;
                var el = document.querySelector('#__recon__ #rh-status');
                if (el) el.textContent = 'Scanned ' + D.scanned + '/' + D.total + ' scripts\u2026';
                ui.render();
            })
            .catch(function(){ D.scanned++; });
    });

    Promise.all(fetchJobs).then(function(){
        var el = document.querySelector('#__recon__ #rh-status');
        if (el) el.textContent = 'Done \u2014 ' + D.scanned + ' script' + (D.scanned!==1?'s':'') + ' scanned';
        ui.render();
    });
})();
