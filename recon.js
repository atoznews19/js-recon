(function(){
'use strict';

/* ═══════════════════════════════════════════════════════════════
   RECON BOOKMARKLET  v3.0
   Improvements:
   - Endpoint shape normalisation (dedup /api/users/123 → /api/users/{id})
   - HTTP method detection from fetch/axios/XHR/jQuery context
   - Request body/params extraction for POST/PUT/PATCH
   - Absolute same-domain URL extraction
   - GraphQL endpoint + operation name detection
   - WebSocket (ws:// wss://) endpoint detection
   - Hardcoded internal IP detection
   - Secret severity ranking (CRITICAL / HIGH / MEDIUM)
   - Greatly reduced false positives via path scoring
═══════════════════════════════════════════════════════════════ */

/* ── Domain setup ─────────────────────────────────────────────── */
var baseUrl     = window.location.origin;
var currentHost = window.location.hostname;
var MULTI_TLD   = /\.(co|com|net|org|gov|edu|ac)\.[a-z]{2}$/i;
var hparts      = currentHost.split('.');
var rootDomain  = MULTI_TLD.test(currentHost) ? hparts.slice(-3).join('.') : hparts.slice(-2).join('.');

/* ── Skip lists ───────────────────────────────────────────────── */
var SKIP_EXTS = /\.(js|css|svg|png|jpg|jpeg|gif|webp|woff2?|ttf|eot|otf|ico|map|br|gz|pdf|xml|txt|csv|zip|tar|mp4|mp3|wav|ogg)(\?.*)?$/i;

var SKIP_HOSTS = [
    'w3.org','schema.org','mozilla.org','jquery.com',
    'google.com','googleapis.com','gstatic.com','google-analytics.com','googletagmanager.com',
    'doubleclick.net','googlesyndication.com',
    'cloudflare.com','cloudflareinsights.com',
    'unpkg.com','jsdelivr.net','cdnjs.com','bootstrapcdn.com',
    'facebook.com','fbcdn.net','twitter.com','twimg.com','instagram.com',
    'youtube.com','ytimg.com','vimeo.com',
    'amazon.com','akamai.com','akamaized.net',
    'newrelic.com','sentry.io','segment.com','mixpanel.com','hotjar.com','fullstory.com',
    'intercom.io','zendesk.com','hubspot.com','salesforce.com','marketo.com',
    'recaptcha.net','hcaptcha.com','stripe.com','paypal.com',
    'digicert.com','verisign.com','letsencrypt.org',
    'apple.com','microsoft.com','windows.net',
];

var NOISE_PATHS = [
    /^\/static\//i,/^\/assets\//i,/^\/dist\//i,/^\/build\//i,
    /^\/public\//i,/^\/node_modules\//i,/^\/vendor\//i,
    /^\/__webpack/i,/^\/_next\//i,/^\/_nuxt\//i,/^\/webpack/i,
    /^\/chunks?\//i,/^\/runtime\//i,/^\/polyfill/i,/^\/hmr/i,
    /^\/sockjs/i,/^\/livereload/i,
];

var NOISE_SEGS = [
    /^[a-f0-9]{8,}$/i,
    /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,
    /^\d+\.\d+(\.\d+)?(\.\d+)?$/,
    /^v\d+(\.\d+)*$/i,
];

/* Strong API keyword hints */
var API_HINTS = /^(api|v\d+|rest|graphql|gql|auth|oauth|login|logout|signup|register|user|users|account|accounts|admin|dashboard|profile|settings|config|data|search|query|upload|download|export|import|webhook|webhooks|notify|notification|notifications|message|messages|payment|payments|order|orders|cart|checkout|product|products|report|reports|analytics|metrics|health|status|ping|token|tokens|refresh|reset|verify|confirm|invite|member|members|team|teams|org|orgs|repo|repos|project|projects|issue|issues|ticket|tickets|feed|feeds|event|events|media|file|files|folder|folders|comment|comments|review|reviews|rating|ratings|like|likes|follow|followers|subscription|subscriptions|session|sessions|log|logs|audit|job|jobs|task|tasks|schedule|hook|hooks|apps|app|service|services|internal|private|external|client|clients|partner|partners|billing|invoice|invoices|role|roles|permission|permissions|group|groups|tag|tags|label|labels|category|categories|post|posts|article|articles|content|page|pages|me|self|whoami|current|lookup|resolve|validate|check|list|detail|details|info|summary|bulk|batch|count|exists|available|suggest|autocomplete|complete|send|receive|publish|subscribe|connect|disconnect|activate|deactivate|enable|disable|lock|unlock|archive|restore|delete|remove|create|update|patch|put|get|fetch|load|save|store|cache|purge|flush|sync|push|pull|stream|live|realtime|ws|wss|socket|rpc|endpoint|route|proxy|redirect|callback|return|next|prev|cursor|page|limit|offset|sort|filter|include|exclude|expand|fields|embed|format|version|revision|history|changelog|diff|compare|merge|fork|clone|deploy|release|build|test|debug|trace|monitor|alert|report|export|backup|restore|migrate|schema|model|entity|resource|collection|item|record|entry|document|node|edge|relation|reference|link|embed|attachment|thumbnail|preview|render|transform|convert|process|execute|run|invoke|trigger|fire|emit|dispatch|broadcast|multicast|unicast)$/i;

/* ── Patterns ─────────────────────────────────────────────────── */
var P = {
    /* quoted paths */
    pathQuoted:  /(?:"|'|`)(\/?[a-zA-Z0-9_\-\.~%]+(?:\/[a-zA-Z0-9_\-\.~%]*)+(?:\?[^\s"'`]*)?)(?:"|'|`)/g,

    /* absolute URLs to any host */
    absUrl:      /https?:\/\/([a-zA-Z0-9_\-\.]+)(\:[0-9]+)?(\/[^\s"'`<>]*)?/g,

    /* WebSocket URLs */
    wsUrl:       /wss?:\/\/([a-zA-Z0-9_\-\.]+)(\:[0-9]+)?(\/[^\s"'`<>]*)?/g,

    /* Internal IPs */
    internalIp:  /(?:https?:\/\/|['"` ])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)(:\d+)?(\/[^\s"'`<>]*)?/g,

    /* HTTP method from fetch/axios/XHR/jQuery */
    httpMethod:  /(?:fetch|axios|request|http|ajax|get|post|put|patch|delete|head|options)\s*\(\s*(?:["'`]([^"'`]+)["'`]\s*,\s*)?\{[^}]*method\s*:\s*["'`]([A-Z]+)["'`]/gi,
    axiosShort:  /axios\.(get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    jqueryAjax:  /\$\.(get|post|ajax|getJSON)\s*\(\s*["'`]([^"'`\s]+)["'`]/gi,
    xhrOpen:     /\.open\s*\(\s*["'`]([A-Z]+)["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi,

    /* Request body context: grab up to 300 chars after a URL match */
    bodyContext: /(?:body|data|payload|params)\s*[:=]\s*(?:JSON\.stringify\s*\()?(\{[^}]{0,300}\})/gi,

    /* GraphQL */
    gqlOp:       /(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]*)/g,
    gqlEndpoint: /["'`](\/[a-zA-Z0-9_\-\/]*graphql[a-zA-Z0-9_\-\/]*)["'`]/gi,

    /* Credentials */
    credentials: /(?:["'`])?(api[_-]?key|secret[_-]?key?|password|passwd|pwd|token|auth[_-]?token|access[_-]?token|bearer|id[_-]?token|jwt|aws[_-]?(?:access[_-]?)?key|aws[_-]?secret|private[_-]?key|slack[_-]?token|client[_-]?secret|app[_-]?secret|encryption[_-]?key|session[_-]?(?:token|key)|x[_-]?api[_-]?key|service[_-]?account|database[_-]?(?:url|uri|password)|connection[_-]?string|smtp[_-]?(?:pass|password)|ftp[_-]?(?:pass|password)|ssh[_-]?(?:key|password)|pgp[_-]?(?:key|passphrase)|master[_-]?(?:key|secret|password))(?:["'`])?\s*[:=]\s*(?:["'`])([a-zA-Z0-9_\-\.\~\+\/=]{12,})(?:["'`])/gi,

    /* JWT standalone */
    jwt:         /\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b/g,

    /* Cloud / service keys */
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
        'sk_test_[0-9a-zA-Z]{24,}',
        'ghp_[0-9a-zA-Z]{36}',
        'github_pat_[0-9a-zA-Z_]{82}',
        'glpat-[0-9a-zA-Z\\-_]{20}',
        'xox[baprs]-[0-9a-zA-Z\\-]{10,}',
        'key-[0-9a-zA-Z]{32}',
        '[0-9a-f]{32}-us[0-9]{1,2}',
        'SG\\.[0-9a-zA-Z\\-_]{22}\\.[0-9a-zA-Z\\-_]{43}',
        'ya29\\.[0-9a-zA-Z\\-_]{50,}',
        'ey[A-Za-z0-9]{2}[A-Za-z0-9\\-_]{100,}',
        'AC[a-zA-Z0-9]{32}',
        'SK[a-zA-Z0-9]{32}',
    ].join('|'), 'g'),

    /* S3 buckets */
    s3: /https?:\/\/([a-z0-9.\-]+)\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com\/[^\s"'`<>]*/gi,

    /* Subdomains — must be inside a URL context (quotes + protocol or clear hostname position) */
    subdomains: /(?:["'`])(?:https?:\/\/)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\.[a-zA-Z]{2,6})(?:[/"'`\s]|$)/gi,
};

/* ── State ────────────────────────────────────────────────────── */
var D = {
    endpoints:    new Map(),   /* shape → { methods:Set, bodies:[], original:string } */
    fullUrls:     new Set(),
    curls:        new Map(),   /* shape → curl string */
    secrets:      new Set(),
    targetSubs:   new Set(),
    potentialSubs:new Set(),
    s3Buckets:    new Set(),
    wsEndpoints:  new Set(),
    internalIps:  new Set(),
    graphql:      new Set(),
    sources:      [],
    bookmarks:    [],
    scanned:      0,
    total:        0,
};
D.targetSubs.add(currentHost);

/* ── Normalise path: replace IDs/hashes with {id} ────────────── */
function normalisePath(path) {
    return path
        .split('?')[0]   /* strip query */
        .split('/')
        .map(function(seg) {
            if (!seg) return seg;
            /* UUID */
            if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(seg)) return '{id}';
            /* pure number */
            if (/^\d+$/.test(seg)) return '{id}';
            /* short hex hash ≥8 chars */
            if (/^[a-f0-9]{8,}$/i.test(seg) && !/[g-z]/i.test(seg)) return '{hash}';
            /* base64-like long token */
            if (seg.length > 32 && /^[a-zA-Z0-9_\-=+\/]{32,}$/.test(seg)) return '{token}';
            return seg;
        })
        .join('/');
}

/* ── Path quality classifier ──────────────────────────────────── */
function classifyPath(raw) {
    if (!raw || raw.length < 3) return 'noise';
    var path = raw.split('?')[0].split('#')[0];
    if (!path.startsWith('/') || path.startsWith('//')) return 'noise';
    if (SKIP_EXTS.test(path)) return 'noise';
    if (NOISE_PATHS.some(function(r){ return r.test(path); })) return 'noise';
    if (/\/(text|application|image|audio|video)\//.test(path)) return 'noise';

    var segs = path.split('/').filter(Boolean);
    if (!segs.length) return 'noise';

    /* all segments are noise hashes/versions → skip */
    var hashCount = segs.filter(function(s){ return NOISE_SEGS.some(function(r){ return r.test(s); }); }).length;
    if (hashCount === segs.length) return 'noise';

    /* all numeric */
    if (segs.every(function(s){ return /^\d+$/.test(s); })) return 'noise';

    var hasApiHint    = segs.some(function(s){ return API_HINTS.test(s); });
    var startsWithApi = /^\/(api|v\d+|graphql|gql|rest|_api|__api|rpc)\b/i.test(path);
    var goodDepth     = segs.length >= 1 && segs.length <= 10;

    if (startsWithApi && goodDepth) return 'target';
    if (hasApiHint && goodDepth)    return 'target';
    if (goodDepth && segs.length >= 2) return 'potential';
    return 'noise';
}

/* ── Valid TLDs whitelist (real registered TLDs only) ─────────── */
var VALID_TLDS = /\.(com|net|org|io|co|ai|app|dev|edu|gov|mil|int|info|biz|name|pro|museum|aero|coop|uk|us|ca|au|de|fr|nl|br|in|jp|cn|ru|it|es|pl|pt|se|no|fi|dk|be|ch|at|nz|za|mx|ar|kr|sg|hk|ae|sa|tr|th|id|vn|ph|my|pk|bd|ng|ke|gh|eg|il|ir|ua|ro|hu|cz|sk|bg|hr|si|lt|lv|ee|is|lu|mt|cy|rs|ba|mk|me|al|ge|am|az|kz|uz|mn|np|lk|mm|kh|la|mv|bt|af|iq|sy|lb|jo|ps|ye|om|kw|bh|qa|am|by|md|kg|tj|tm|dz|ma|tn|ly|sd|et|tz|ug|rw|zm|zw|mz|mg|cm|ci|sn|ml|bf|ne|td|gn|tg|bj|sl|lr|gm|gw|mr|dj|so|er|ls|bw|na|sz|mw|ao|cg|cd|cf|ga|gq|st|cv|km|sc|mu|re|yt|pm|nc|pf|gu|mp|vi|pr|as|ws|to|fj|pg|sb|vu|ki|nr|pw|fm|mh|tv|ck|nu|tk|wf|tf|sh|ac|io|cc|cx|nf|hm|aq|xyz|club|online|site|website|tech|store|shop|blog|news|media|agency|studio|design|digital|cloud|host|server|systems|solutions|network|software|services|group|global|international|enterprises|consulting|management|finance|capital|invest|trading|market|exchange|bank|pay|money|cash|fund|insurance|health|care|med|pharma|bio|life|food|eat|drink|travel|hotel|tour|fly|car|auto|drive|energy|solar|green|eco|land|property|real|estate|legal|law|firm|partners|associates|ventures|holdings|industries|manufacturing|logistics|supply|delivery|express|courier|cargo|freight|mail|post|telecom|mobile|wireless|broadband|fiber|voice|video|stream|play|games|sports|fitness|beauty|fashion|style|art|music|film|photo|print|publish|education|school|academy|university|institute|training|learn|course|class|library|research|science|lab|tech|data|analytics|intelligence|security|protect|defend|guard|safe|trust|verify|auth|id|identity|profile|social|community|connect|chat|meet|date|share|review|rate|compare|search|find|discover|explore|map|local|place|city|country|world|global|space|sky|air|sea|ocean|earth|nature|wild|park|garden|farm|food|health|wellness|fitness|sport|game|play|fun|kids|family|home|house|work|office|business|company|corp|inc|ltd|llc|gmbh|sa|srl|bv|nv|ag|oy|ab|as|aps|plc|pvt|pte|sdn|bhd|pty|co|cv|snc|sas|sar|spa|soc|coop|assoc|found|fund|trust|estate|charity|ngo|org|gov|edu|mil|int|un|eu|nato|who|imf|wb|ifc|ilo|fao|wto|iaea|icao|imo|itu|upu|wmo|wipo|ifad|unido|unwto|unicef|unhcr|undp|unep|wfp|ocha|ohchr|unodc|unog|unon|unov|escap|eclac|eca|ecwa|desa|dpko|dpa|dpi|oios|osasg|srsg|dsrsg|rc|hc|rr)$/i;

/* ── JS globals / DOM APIs that produce false-positive "hosts" ── */
var JS_NOISE_ROOTS = /^(window|document|navigator|location|history|screen|console|performance|crypto|math|json|object|array|string|number|boolean|function|promise|proxy|reflect|symbol|error|regexp|date|map|set|weakmap|weakset|arraybuffer|dataview|globalthis|fetch|xmlhttprequest|websocket|worker|serviceworker|indexeddb|localstorage|sessionstorage|notification|geolocation|mediadevices|eventtarget|element|node|nodelist|htmlcollection|domparser|formdata|blob|file|filereader|url|urlsearchparams|headers|request|response|textencoder|textdecoder|broadcastchannel|messagechannel|sharedarraybuffer|atomics|webassembly|intl|css|animation|documentfragment|range|selection|treewalker|svgelement|canvaspattern|canvasgradient|imagedata|imagebitmap|offscreencanvas|path2d|dommatrix|dompoint|domrect|domquad|htmlelement|htmlinputelement|htmlformelement|htmlbuttonelement|htmlselectelement|htmltextareaelement|htmlanchorelement|htmlimageelement|htmlscriptelement|htmllinkelement|htmlmetaelement|htmlbodyelement|htmldivelement|htmlspanelement|htmlcanvaselement|htmlvideoelement|htmlaudioelement|htmliframeelement|mutationobserver|intersectionobserver|resizeobserver|performanceobserver|customelementregistry|shadowroot|jquery|cryptojs|angular|react|vue|backbone|lodash|underscore|moment|axios|socket|d3|three|gsap|anime|lottie|swiper|bootstrap|webpack|babel|rollup|vite|typescript|redux|mobx|rxjs|apollo|prisma|mongoose|sequelize|express|fastify|koa|electron|tauri|cordova|ionic|expo|srcform|srcdiv|subweb|setcookie|curobj|newpassword|internetgatewaydevice)$/i;

/* ── JS property/method suffixes that appear after dots ──────── */
var JS_NOISE_SUFFIXES = /^(length|size|width|height|top|left|right|bottom|value|checked|selected|disabled|readonly|required|hidden|type|name|id|classname|classlist|style|innerhtml|innertext|textcontent|outerhtml|tagname|nodename|nodetype|nodevalue|parentnode|parentelement|childnodes|children|firstchild|lastchild|nextsibling|previoussibling|ownerdocument|attributes|dataset|offsetwidth|offsetheight|offsettop|offsetleft|offsetparent|scrollwidth|scrollheight|scrolltop|scrollleft|clientwidth|clientheight|clienttop|clientleft|getboundingclientrect|addeventlistener|removeeventlistener|dispatchevent|appendchild|removechild|insertbefore|replacechild|clonenode|contains|haschildnodes|getattribute|setattribute|removeattribute|hasattribute|queryselector|queryselectorall|getelementbyid|getelementsbytagname|getelementsbyclassname|createelement|createtextnode|createcomment|createdocumentfragment|createevent|createrange|importnode|adoptnode|tostring|valueof|hasownproperty|isprototypeof|propertyisenumerable|constructor|prototype|apply|call|bind|push|pop|shift|unshift|splice|slice|concat|join|reverse|sort|indexof|lastindexof|includes|find|findindex|filter|map|reduce|reduceright|foreach|some|every|flat|flatmap|keys|values|entries|from|isarray|assign|create|defineproperty|defineproperties|getownpropertynames|getprototypeof|setprototypeof|freeze|seal|isfrozen|issealed|parse|stringify|now|gettime|getdate|getmonth|getfullyear|gethours|getminutes|getseconds|getmilliseconds|toisostring|tolocaledatestring|tolocaletimestring|tolocalestring|todatestring|totimestring|toutcstring|exec|test|match|matchall|replace|replaceall|search|split|trim|trimstart|trimend|padstart|padend|repeat|startswith|endswith|charat|charcodeat|fromdocharcode|abs|ceil|floor|round|max|min|pow|sqrt|log|exp|sin|cos|tan|asin|acos|atan|atan2|sign|trunc|random|resolve|reject|then|catch|finally|next|done|get|set|has|delete|clear|add|send|close|abort|arraybuffer|json|text|formdata|read|write|cancel|enqueue|terminate|postmessage|onmessage|onerror|onclose|onopen|action|method|target|submit|reset|append|remove|displa|tolowe|touppe|indexo|replac|substr|subst|offset|select|insert|update|doscro|return|comple|except|getsta|protot|trigge|specia|global|dispatch|handler|predispatch|postdispatch|rnamespace|originalevent|csstex|positi|backgr|initia|presha|wlanconf|landevice|options|elements|append2|fire|elemen|method2|action2|target2|nativecontrol|tableitemlist|urllist|observer|prophooks|prefilters|tweens|opts|timers|speeds|valhooks|ajaxsettings|datatypes|flatop|contentype|beforecend|namespace|trigger2|default|setup|teardown|remove2|fix|handlers|simulate|ajaxprefilter|ajaxtransport|support|browser|dommanip|buildfragment|clean|cleandata|defaul|getstat|excepti|init|extend|fn|expr|event|ajax|fx|deferred|callbacks|cssHooks|attrHooks|valHooks|pseudos|match|find|filter2|setfilters|needscontext|childnodes2|sourceleindex|source)$/i;

/* ── Host classifier (hardened) ───────────────────────────────── */
function classifyHost(sub) {
    if (!sub || sub.length < 4 || !sub.includes('.')) return 'noise';

    /* must end with a known real TLD */
    if (!VALID_TLDS.test(sub)) return 'noise';

    var segs = sub.split('.');
    var tld  = segs[segs.length - 1];
    var sld  = segs[segs.length - 2] || '';

    /* TLD must be purely alpha, 2-6 chars */
    if (!/^[a-z]{2,6}$/i.test(tld)) return 'noise';

    /* real hostnames are lowercase + hyphens only — reject camelCase */
    if (segs.some(function(s){ return /[A-Z]/.test(s); })) return 'noise';

    /* reject if any segment is a JS global/DOM API name */
    if (segs.some(function(s){ return JS_NOISE_ROOTS.test(s); })) return 'noise';

    /* reject if SLD looks like a JS property/method name */
    if (JS_NOISE_SUFFIXES.test(sld)) return 'noise';

    /* reject file extensions as TLDs: .js .ts .css .json etc */
    if (/^(js|ts|jsx|tsx|mjs|cjs|css|scss|less|json|xml|yaml|yml|html|htm|php|py|rb|go|rs|java|kt|swift|c|cpp|cs|sh|sql|gql|wasm|map|min|bundle|chunk|vendor|polyfill|worker|sw|htaccess|env|lock|md|txt|log|csv|gz|br|zip)$/.test(tld)) return 'noise';

    /* reject segments that truncated mid-word (common in JS source) */
    if (segs.some(function(s){ return s.length > 0 && s.length <= 2 && segs.length > 2; })) return 'noise';

    /* reject >4 segment chains with all-lowercase short segs (prop chains) */
    if (segs.length > 4 && segs.every(function(s){ return s.length <= 15 && /^[a-z_]+$/.test(s); })) return 'noise';

    /* reject known 3rd-party noise hosts */
    if (SKIP_HOSTS.some(function(h){ return sub.includes(h); })) return 'noise';

    /* reject IPv4 */
    if (/\d+\.\d+\.\d+\.\d+/.test(sub)) return 'noise';

    /* classify */
    if (sub.endsWith(rootDomain)) return 'target';
    if (/^(cdn\d*|static\d*|assets\d*|media\d*|img\d*|images\d*)\./.test(sub)) return 'potential';
    return 'potential';
}

/* ── Secret severity ──────────────────────────────────────────── */
function secretSeverity(raw) {
    var r = raw.toUpperCase();
    if (/AKIA|SK_LIVE|SK_TEST|SLACK|GITHUB_PAT|GHP_|GLPAT|SENDGRID|SG\.|TWILIO|AC[A-Z0-9]{32}/.test(r)) return 'CRITICAL';
    if (/JWT|BEARER|PRIVATE.KEY|AWS|SECRET|PASSWORD|PASSWD|PWD|CLIENT.SECRET|MASTER/.test(r)) return 'HIGH';
    return 'MEDIUM';
}

/* ── Build cURL ───────────────────────────────────────────────── */
function buildCurl(url, method, body) {
    method = (method || 'GET').toUpperCase();
    var cmd = 'curl -si -X ' + method + ' "' + url + '" \\\n' +
              '  -H "User-Agent: Mozilla/5.0 (compatible; Recon/1.0)" \\\n' +
              '  -H "Accept: application/json, text/plain, */*" \\\n' +
              '  -H "Origin: ' + baseUrl + '"';
    if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        cmd += ' \\\n  -H "Content-Type: application/json" \\\n  -d \'' + body.replace(/'/g,"'\\''") + '\'';
    }
    return cmd;
}

/* ── Register endpoint ────────────────────────────────────────── */
function addEndpoint(rawPath, method, body) {
    method = (method || 'GET').toUpperCase();
    var grade = classifyPath(rawPath);
    if (grade === 'noise') return;

    var shape = normalisePath(rawPath);
    var url   = baseUrl + (rawPath.startsWith('/') ? '' : '/') + rawPath;

    if (grade === 'target') {
        if (!D.endpoints.has(shape)) {
            D.endpoints.set(shape, { methods: new Set(), bodies: [], original: rawPath });
        }
        var entry = D.endpoints.get(shape);
        entry.methods.add(method);
        if (body && !entry.bodies.includes(body)) entry.bodies.push(body);

        D.fullUrls.add(url);
        /* update curl with best known method */
        var bestMethod = entry.methods.has('POST') ? 'POST'
                       : entry.methods.has('PUT')  ? 'PUT'
                       : entry.methods.has('PATCH')? 'PATCH'
                       : method;
        D.curls.set(shape, buildCurl(url, bestMethod, entry.bodies[0]||null));
    } else {
        D.potentialSubs.add('[path] ' + url);
    }
}

/* ── Method/body detection context window ─────────────────────── */
function extractMethodAndBody(text, urlStr) {
    /* look in a 500-char window around each occurrence of the URL */
    var method = 'GET', body = null;
    var idx = text.indexOf(urlStr);
    if (idx === -1) return { method: method, body: body };

    var window_ = text.substring(Math.max(0, idx - 200), idx + 300);

    /* fetch({method:'POST'}) */
    var mMethod = window_.match(/method\s*:\s*["'`]([A-Z]+)["'`]/i);
    if (mMethod) method = mMethod[1].toUpperCase();

    /* axios.post / axios.delete etc */
    var mAxios = window_.match(/axios\.(get|post|put|patch|delete|head|options)\s*\(/i);
    if (mAxios) method = mAxios[1].toUpperCase();

    /* XHR.open('POST', ...) */
    var mXhr = window_.match(/\.open\s*\(\s*["'`]([A-Z]+)["'`]/i);
    if (mXhr) method = mXhr[1].toUpperCase();

    /* jQuery $.post / $.get */
    var mJq = window_.match(/\$\.(post|get|put|patch|delete)\s*\(/i);
    if (mJq) method = mJq[1].toUpperCase();

    /* body/data/payload extraction */
    var mBody = window_.match(/(?:body|data|payload)\s*[:=]\s*(?:JSON\.stringify\s*\()?(\{[^}]{1,300}\})/);
    if (mBody) {
        try { body = JSON.stringify(JSON.parse(mBody[1])); }
        catch(_) { body = mBody[1].replace(/\s+/g,' ').trim(); }
    }

    return { method: method, body: body };
}

/* ── Reset regex lastIndex ────────────────────────────────────── */
function resetIdx() {
    Object.values(P).forEach(function(r){ if (r && r.lastIndex !== undefined) r.lastIndex = 0; });
}

/* ── Main scanner ─────────────────────────────────────────────── */
function scanText(text) {
    resetIdx();
    var m;

    /* 1. Quoted relative paths */
    P.pathQuoted.lastIndex = 0;
    while ((m = P.pathQuoted.exec(text)) !== null) {
        var raw = m[1];
        if (!raw.startsWith('/') || raw.startsWith('//')) continue;
        if (SKIP_HOSTS.some(function(h){ return raw.includes(h); })) continue;
        var ctx = extractMethodAndBody(text, m[1]);
        addEndpoint(raw, ctx.method, ctx.body);
    }

    /* 2. Absolute URLs — same domain → confirmed; other domain → subdomain check */
    P.absUrl.lastIndex = 0;
    while ((m = P.absUrl.exec(text)) !== null) {
        var host = m[1].toLowerCase();
        var path = m[3] || '/';
        if (SKIP_HOSTS.some(function(h){ return host.includes(h); })) continue;

        if (host === currentHost || host.endsWith('.' + rootDomain)) {
            /* same-domain absolute URL → treat as confirmed endpoint */
            var ctx2 = extractMethodAndBody(text, m[0]);
            addEndpoint(path, ctx2.method, ctx2.body);
            var hgrade = classifyHost(host);
            if (hgrade === 'target') D.targetSubs.add(host);
        } else {
            var hgrade2 = classifyHost(host);
            if (hgrade2 === 'target') D.targetSubs.add(host);
            else if (hgrade2 === 'potential') D.potentialSubs.add(host);
        }
    }

    /* 3. WebSocket URLs */
    P.wsUrl.lastIndex = 0;
    while ((m = P.wsUrl.exec(text)) !== null) {
        D.wsEndpoints.add(m[0]);
    }

    /* 4. Internal IPs */
    P.internalIp.lastIndex = 0;
    while ((m = P.internalIp.exec(text)) !== null) {
        var ipStr = (m[1]||'') + (m[2]||'') + (m[3]||'');
        D.internalIps.add(ipStr.trim());
    }

    /* 5. GraphQL operations */
    P.gqlOp.lastIndex = 0;
    while ((m = P.gqlOp.exec(text)) !== null) {
        D.graphql.add('[op] ' + m[0].trim());
    }
    P.gqlEndpoint.lastIndex = 0;
    while ((m = P.gqlEndpoint.exec(text)) !== null) {
        D.graphql.add('[endpoint] ' + m[1]);
        addEndpoint(m[1], 'POST', null);
    }

    /* 6. Credentials */
    P.credentials.lastIndex = 0;
    while ((m = P.credentials.exec(text)) !== null) {
        var sev = secretSeverity(m[1]);
        D.secrets.add('[' + sev + '] [Credential] ' + m[1] + ' = ' + m[2]);
    }

    /* 7. JWTs */
    P.jwt.lastIndex = 0;
    while ((m = P.jwt.exec(text)) !== null) {
        D.secrets.add('[HIGH] [JWT] ' + m[0].substring(0,80) + '...');
    }

    /* 8. Cloud keys */
    P.cloudKeys.lastIndex = 0;
    while ((m = P.cloudKeys.exec(text)) !== null) {
        var sev2 = secretSeverity(m[0]);
        D.secrets.add('[' + sev2 + '] [API Key] ' + m[0]);
    }

    /* 9. S3 */
    P.s3.lastIndex = 0;
    while ((m = P.s3.exec(text)) !== null) {
        D.s3Buckets.add(m[0]);
    }

    /* 10. Subdomains */
    P.subdomains.lastIndex = 0;
    while ((m = P.subdomains.exec(text)) !== null) {
        var sub = m[1].replace(/^https?:\/\//i,'').toLowerCase().replace(/\/.*$/,'');
        var sg = classifyHost(sub);
        if (sg === 'target') D.targetSubs.add(sub);
        else if (sg === 'potential') D.potentialSubs.add(sub);
    }
}

/* ── Initial scan ─────────────────────────────────────────────── */
scanText(document.documentElement.outerHTML);

var scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
    .map(function(s){ return s.src; }).filter(Boolean)
    .filter(function(u){
        try {
            var h = new URL(u).hostname;
            return h === currentHost || !SKIP_HOSTS.some(function(sh){ return u.includes(sh); });
        } catch(_){ return false; }
    });
D.sources = scriptSrcs;
D.total   = scriptSrcs.length;

/* ── Bookmark helpers ─────────────────────────────────────────── */
function addBookmark(url, note, tag) {
    if (D.bookmarks.find(function(b){ return b.url === url; })) return false;
    D.bookmarks.push({ url: url.trim(), note: (note||'').trim(), tag: (tag||'').trim(), ts: new Date().toISOString() });
    return true;
}
function removeBookmark(url) {
    var i = D.bookmarks.findIndex(function(b){ return b.url === url; });
    if (i !== -1) { D.bookmarks.splice(i,1); return true; }
    return false;
}

/* ── Tab data helpers ─────────────────────────────────────────── */
function getCurlLines() {
    return Array.from(D.curls.values());
}
function getEndpointLines() {
    var lines = [];
    D.endpoints.forEach(function(v, shape) {
        var methods = Array.from(v.methods).join('|');
        lines.push('[' + methods + '] ' + shape + (v.bodies.length ? '  // body: '+v.bodies[0].substring(0,80) : ''));
    });
    return lines;
}
function getFullUrlLines() {
    return Array.from(D.fullUrls);
}
function getSecretsSorted() {
    var arr = Array.from(D.secrets);
    arr.sort(function(a,b){
        var order = {CRITICAL:0, HIGH:1, MEDIUM:2};
        var ga = (a.match(/\[(CRITICAL|HIGH|MEDIUM)\]/) || ['','MEDIUM'])[1];
        var gb = (b.match(/\[(CRITICAL|HIGH|MEDIUM)\]/) || ['','MEDIUM'])[1];
        return (order[ga]||2) - (order[gb]||2);
    });
    return arr;
}

/* ── Count helpers ────────────────────────────────────────────── */
function counts() {
    return {
        curls:        D.curls.size,
        fullUrls:     D.fullUrls.size,
        endpoints:    D.endpoints.size,
        targetSubs:   D.targetSubs.size,
        potentialSubs:D.potentialSubs.size,
        s3Buckets:    D.s3Buckets.size,
        secrets:      D.secrets.size,
        wsEndpoints:  D.wsEndpoints.size,
        internalIps:  D.internalIps.size,
        graphql:      D.graphql.size,
        sources:      D.sources.length,
        bookmarks:    D.bookmarks.length,
    };
}

/* ═══════════════════════════════════════════════════════════════
   UI
═══════════════════════════════════════════════════════════════ */
function buildUI() {
    var ex = document.getElementById('__recon__');
    if (ex) ex.remove();

    var root = document.createElement('div');
    root.id = '__recon__';
    root.setAttribute('role','dialog');

    var CSS = [
        '#__recon__ *{box-sizing:border-box;font-family:monospace}',
        '#__recon__{position:fixed;top:40px;right:40px;width:980px;max-width:96vw;height:660px;max-height:92vh;background:#0a0a0a;color:#e0e0e0;z-index:2147483647;display:flex;flex-direction:column;border:1px solid #252525;border-radius:6px;overflow:hidden;user-select:none;box-shadow:0 8px 40px rgba(0,0,0,.7)}',
        '#__recon__ #rh{background:#0f0f0f;padding:7px 12px;display:flex;align-items:center;gap:10px;cursor:move;border-bottom:1px solid #1e1e1e;flex-shrink:0}',
        '#__recon__ #rh-scope{font-size:11px;color:#777;flex:1}',
        '#__recon__ #rh-scope b{color:#4d9cff}',
        '#__recon__ #rh-status{font-size:10px;color:#555}',
        '#__recon__ #rh-rescan{background:#1a2a1a;border:1px solid #2a4a2a;color:#4caf50;padding:3px 8px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:10px}',
        '#__recon__ #rh-rescan:hover{background:#1e3a1e}',
        '#__recon__ #rh-close{background:#c0392b;color:#fff;border:none;padding:3px 10px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:11px}',
        '#__recon__ #rh-close:hover{background:#e74c3c}',
        '#__recon__ #rtabs{display:flex;flex-wrap:wrap;gap:3px;padding:6px 10px;background:#0f0f0f;border-bottom:1px solid #1a1a1a;flex-shrink:0}',
        '#__recon__ .rtab{background:transparent;border:1px solid #222;border-radius:3px;padding:3px 8px;cursor:pointer;font-size:10px;transition:background .1s}',
        '#__recon__ .rtab:hover{background:#161616}',
        '#__recon__ .rtab.active{background:#1a1a1a;border-color:#3a3a3a}',
        '#__recon__ .tc{display:inline-block;margin-left:4px;font-size:9px;background:#1e1e1e;border-radius:8px;padding:0 5px;line-height:15px;color:#888}',
        '#__recon__ .tc.has{background:#1e2e1e;color:#4caf50}',
        '#__recon__ #rtool{display:flex;align-items:center;gap:5px;padding:5px 10px;background:#080808;border-bottom:1px solid #161616;flex-shrink:0}',
        '#__recon__ #rfilter{flex:1;background:#111;border:1px solid #222;color:#ccc;padding:3px 8px;border-radius:3px;font-size:11px;outline:none}',
        '#__recon__ #rfilter::placeholder{color:#383838}',
        '#__recon__ .rbtn{background:#141414;border:1px solid #252525;color:#888;padding:3px 9px;cursor:pointer;border-radius:3px;font-size:10px}',
        '#__recon__ .rbtn:hover{background:#1e1e1e;color:#bbb}',
        '#__recon__ .rbtn.green{border-color:#2a4a2a;color:#4caf50}',
        '#__recon__ .rbtn.green:hover{background:#1a2e1a}',
        '#__recon__ #rbody{flex:1;overflow:hidden;display:flex;flex-direction:column}',
        '#__recon__ #rout{flex:1;width:100%;background:transparent;color:#c8c8c8;border:none;resize:none;font-size:11px;outline:none;white-space:pre;overflow:auto;line-height:1.65;padding:10px}',
        /* severity colours in textarea via ::selection not possible; use legend */
        '#__recon__ #rsev{padding:3px 10px;background:#080808;border-top:1px solid #161616;font-size:10px;color:#444;flex-shrink:0;display:none}',
        '#__recon__ #rsev span{margin-right:12px}',
        '#__recon__ .sev-c{color:#ff4444}',
        '#__recon__ .sev-h{color:#ff8c00}',
        '#__recon__ .sev-m{color:#f0c040}',
        /* bookmark panel */
        '#__recon__ #bm-panel{flex:1;display:flex;flex-direction:column;overflow:hidden}',
        '#__recon__ #bm-add-bar{display:flex;gap:5px;padding:7px 10px;border-bottom:1px solid #161616;flex-shrink:0;background:#0c0c0c}',
        '#__recon__ #bm-add-bar input{background:#111;border:1px solid #222;color:#ccc;padding:3px 7px;border-radius:3px;font-size:11px;outline:none}',
        '#__recon__ #bm-url-in{flex:2}',
        '#__recon__ #bm-note-in{flex:2}',
        '#__recon__ #bm-tag-in{flex:1}',
        '#__recon__ #bm-list{flex:1;overflow-y:auto;padding:6px 10px;display:flex;flex-direction:column;gap:4px}',
        '#__recon__ .bm-row{background:#0f0f0f;border:1px solid #1e1e1e;border-radius:4px;padding:6px 10px;display:flex;align-items:flex-start;gap:8px}',
        '#__recon__ .bm-row:hover{border-color:#2e2e2e}',
        '#__recon__ .bm-info{flex:1;min-width:0}',
        '#__recon__ .bm-url{color:#4d9cff;font-size:11px;word-break:break-all;text-decoration:none}',
        '#__recon__ .bm-url:hover{text-decoration:underline}',
        '#__recon__ .bm-meta{display:flex;gap:8px;margin-top:3px;flex-wrap:wrap}',
        '#__recon__ .bm-note{font-size:10px;color:#777}',
        '#__recon__ .bm-tag{font-size:10px;background:#161616;border:1px solid #222;border-radius:10px;padding:0 6px;line-height:15px;color:#888}',
        '#__recon__ .t-recon{color:#b87fff;border-color:#3a2a4a}',
        '#__recon__ .t-vuln{color:#ff4444;border-color:#4a1a1a}',
        '#__recon__ .t-info{color:#4d9cff;border-color:#1a2a4a}',
        '#__recon__ .t-s3{color:#ff8c00;border-color:#3a2a00}',
        '#__recon__ .t-secret{color:#ff4444;border-color:#4a1a1a}',
        '#__recon__ .bm-ts{font-size:9px;color:#2e2e2e}',
        '#__recon__ .bm-del{background:transparent;border:none;color:#333;cursor:pointer;font-size:12px;padding:0;line-height:1;flex-shrink:0}',
        '#__recon__ .bm-del:hover{color:#e74c3c}',
        '#__recon__ #bm-empty{color:#2e2e2e;font-size:12px;text-align:center;padding:40px 0}',
        '#__recon__ #bm-footer{padding:5px 10px;border-top:1px solid #161616;display:flex;gap:5px;align-items:center;flex-shrink:0;background:#080808}',
        '#__recon__ #bm-filter-tag{background:#111;border:1px solid #222;color:#ccc;padding:2px 6px;border-radius:3px;font-size:11px;outline:none;width:120px}',
        '#__recon__ #bm-count{font-size:10px;color:#3a3a3a;flex:1}',
    ].join('');

    /* Tab definitions */
    var TABS = [
        { id:'curls',        label:'PoC cURLs',     color:'#e6a817' },
        { id:'fullUrls',     label:'Confirmed URLs', color:'#4d9cff' },
        { id:'endpoints',    label:'API Paths',      color:'#00cc99' },
        { id:'targetSubs',   label:'Target Subs',    color:'#b87fff' },
        { id:'potentialSubs',label:'Potential',      color:'#666'    },
        { id:'s3Buckets',    label:'S3 Buckets',     color:'#ff8c00' },
        { id:'wsEndpoints',  label:'WebSockets',     color:'#00ccff' },
        { id:'internalIps',  label:'Internal IPs',   color:'#ff6666' },
        { id:'graphql',      label:'GraphQL',        color:'#e040fb' },
        { id:'secrets',      label:'Secrets',        color:'#ff4444', bold:true },
        { id:'sources',      label:'JS Sources',     color:'#444'    },
        { id:'bookmarks',    label:'\u2605 Saved',   color:'#f0c040', bold:true },
    ];

    var tabsHtml = TABS.map(function(t){
        return '<button class="rtab' + (t.id==='curls'?' active':'') + '" data-tab="'+t.id+'" style="color:'+t.color+(t.bold?';font-weight:bold':'')+'">' +
               t.label + '<span class="tc" id="c-'+t.id+'">0</span></button>';
    }).join('');

    root.innerHTML = '<style>'+CSS+'</style>' +
        '<div id="rh">' +
        '  <span id="rh-scope">Scope: <b>*.'+rootDomain+'</b></span>' +
        '  <span id="rh-status">Ready</span>' +
        '  <button id="rh-rescan">\u21bb Rescan</button>' +
        '  <button id="rh-close">\u2715 Close</button>' +
        '</div>' +
        '<div id="rtabs">'+tabsHtml+'</div>' +
        '<div id="rtool">' +
        '  <input id="rfilter" type="text" placeholder="Filter\u2026" />' +
        '  <button class="rbtn green" id="rbtn-bm">\u2605 Bookmark line</button>' +
        '  <button class="rbtn" id="rbtn-open">Open URL</button>' +
        '  <button class="rbtn" id="rbtn-copy">Copy</button>' +
        '  <button class="rbtn" id="rbtn-export">Export JSON</button>' +
        '</div>' +
        '<div id="rbody">' +
        '  <textarea id="rout" readonly></textarea>' +
        '  <div id="rsev"><span class="sev-c">\u25cf CRITICAL</span><span class="sev-h">\u25cf HIGH</span><span class="sev-m">\u25cf MEDIUM</span> — sorted by severity</div>' +
        '  <div id="bm-panel" style="display:none">' +
        '    <div id="bm-add-bar">' +
        '      <input id="bm-url-in" type="text" placeholder="URL or finding\u2026" />' +
        '      <input id="bm-note-in" type="text" placeholder="Note\u2026" />' +
        '      <input id="bm-tag-in" type="text" placeholder="Tag: recon/vuln/info/s3/secret" />' +
        '      <button class="rbtn green" id="bm-add-btn">+ Add</button>' +
        '    </div>' +
        '    <div id="bm-list"></div>' +
        '    <div id="bm-footer">' +
        '      <span id="bm-count">0 bookmarks</span>' +
        '      <input id="bm-filter-tag" type="text" placeholder="Filter tag\u2026" />' +
        '      <button class="rbtn" id="bm-export-btn">Export .txt</button>' +
        '      <button class="rbtn" id="bm-clear-btn" style="color:#c0392b">Clear All</button>' +
        '    </div>' +
        '  </div>' +
        '</div>';

    document.body.appendChild(root);

    var out      = root.querySelector('#rout');
    var filterIn = root.querySelector('#rfilter');
    var bmPanel  = root.querySelector('#bm-panel');
    var bmList   = root.querySelector('#bm-list');
    var sevBar   = root.querySelector('#rsev');
    var activeTab = 'curls';
    var filterVal = '';

    /* Drag */
    var hdr = root.querySelector('#rh');
    var dx=0,dy=0,drag=false;
    hdr.addEventListener('mousedown',function(e){
        if (e.target.id==='rh-close'||e.target.id==='rh-rescan') return;
        drag=true; dx=e.clientX-root.offsetLeft; dy=e.clientY-root.offsetTop; e.preventDefault();
    });
    document.addEventListener('mousemove',function(e){ if(!drag)return; root.style.left=(e.clientX-dx)+'px'; root.style.top=(e.clientY-dy)+'px'; root.style.right='auto'; });
    document.addEventListener('mouseup',function(){ drag=false; });

    /* Data for each tab */
    function tabLines() {
        switch(activeTab) {
            case 'curls':        return getCurlLines();
            case 'fullUrls':     return getFullUrlLines();
            case 'endpoints':    return getEndpointLines();
            case 'targetSubs':   return Array.from(D.targetSubs);
            case 'potentialSubs':return Array.from(D.potentialSubs);
            case 's3Buckets':    return Array.from(D.s3Buckets);
            case 'wsEndpoints':  return Array.from(D.wsEndpoints);
            case 'internalIps':  return Array.from(D.internalIps);
            case 'graphql':      return Array.from(D.graphql);
            case 'secrets':      return getSecretsSorted();
            case 'sources':      return D.sources;
            default:             return [];
        }
    }

    function render() {
        if (activeTab==='bookmarks') { renderBM(); return; }
        var lines = tabLines();
        var sep   = activeTab==='curls' ? '\n\n' : '\n';
        var filtered = filterVal ? lines.filter(function(l){ return l.toLowerCase().includes(filterVal); }) : lines;
        out.value = filtered.join(sep) || '(no results)';
        sevBar.style.display = activeTab==='secrets' ? 'block' : 'none';
        updateCounts();
    }

    function updateCounts() {
        var c = counts();
        TABS.forEach(function(t){
            var el = document.getElementById('c-'+t.id);
            if (!el) return;
            var n = c[t.id] || 0;
            el.textContent = n;
            el.className   = 'tc' + (n > 0 ? ' has' : '');
        });
    }

    function tagClass(tag) {
        var t = (tag||'').toLowerCase();
        if (t==='vuln'||t==='secret') return 't-vuln';
        if (t==='info')   return 't-info';
        if (t==='s3')     return 't-s3';
        if (t==='recon')  return 't-recon';
        return '';
    }

    function renderBM() {
        updateCounts();
        var tf = (root.querySelector('#bm-filter-tag').value||'').toLowerCase().trim();
        var list = tf ? D.bookmarks.filter(function(b){ return b.tag.toLowerCase().includes(tf); }) : D.bookmarks;
        root.querySelector('#bm-count').textContent = D.bookmarks.length + ' bookmark' + (D.bookmarks.length!==1?'s':'');
        if (!list.length) {
            bmList.innerHTML = '<div id="bm-empty">No bookmarks yet.<br>Click a line in any tab then \u2605 Bookmark line.</div>';
            return;
        }
        bmList.innerHTML = '';
        list.slice().reverse().forEach(function(b){
            var row = document.createElement('div');
            row.className = 'bm-row';
            var d = new Date(b.ts);
            row.innerHTML =
                '<div class="bm-info">' +
                '<a class="bm-url" href="'+b.url+'" target="_blank" rel="noopener">'+b.url+'</a>' +
                '<div class="bm-meta">' +
                (b.note ? '<span class="bm-note">'+b.note+'</span>' : '') +
                (b.tag  ? '<span class="bm-tag '+tagClass(b.tag)+'">'+b.tag+'</span>' : '') +
                '<span class="bm-ts">'+d.toLocaleDateString()+' '+d.toLocaleTimeString()+'</span>' +
                '</div></div>' +
                '<button class="bm-del" data-url="'+b.url+'">\u2715</button>';
            bmList.appendChild(row);
        });
        bmList.querySelectorAll('.bm-del').forEach(function(btn){
            btn.addEventListener('click',function(){ removeBookmark(btn.dataset.url); renderBM(); });
        });
    }

    function getSelectedLine() {
        var v=out.value, s=out.selectionStart;
        var ls=v.lastIndexOf('\n',s-1)+1, le=v.indexOf('\n',s);
        return v.substring(ls, le===-1?v.length:le).trim();
    }

    /* Tabs */
    root.querySelectorAll('.rtab').forEach(function(btn){
        btn.addEventListener('click',function(){
            root.querySelectorAll('.rtab').forEach(function(b){ b.classList.remove('active'); });
            btn.classList.add('active');
            activeTab = btn.dataset.tab;
            filterIn.value=''; filterVal='';
            var isBM = activeTab==='bookmarks';
            out.style.display     = isBM ? 'none' : '';
            bmPanel.style.display = isBM ? 'flex'  : 'none';
            root.querySelector('#rbtn-bm').style.display   = isBM ? 'none' : '';
            root.querySelector('#rbtn-open').style.display = isBM ? 'none' : '';
            if (isBM) renderBM(); else render();
        });
    });

    filterIn.addEventListener('input',function(){ filterVal=filterIn.value.toLowerCase().trim(); render(); });

    /* Bookmark selected line */
    root.querySelector('#rbtn-bm').addEventListener('click',function(){
        var line = getSelectedLine();
        if (!line) { alert('Click a line first.'); return; }
        var autoTag = activeTab==='s3Buckets' ? 's3'
                    : activeTab==='secrets'   ? 'secret'
                    : (activeTab==='targetSubs'||activeTab==='potentialSubs') ? 'recon' : 'info';
        var note = prompt('Note (optional):', '') || '';
        var tag  = prompt('Tag (recon/vuln/info/s3/secret):', autoTag) || autoTag;
        if (addBookmark(line, note, tag)) {
            var btn = root.querySelector('#rbtn-bm');
            btn.textContent = '\u2605 Saved!';
            setTimeout(function(){ btn.textContent='\u2605 Bookmark line'; }, 1500);
            updateCounts();
        } else { alert('Already bookmarked.'); }
    });

    /* Open URL in new tab */
    root.querySelector('#rbtn-open').addEventListener('click',function(){
        var line = getSelectedLine();
        if (!line) { alert('Click a URL line first.'); return; }
        var url = line.match(/https?:\/\/[^\s]+/);
        if (url) window.open(url[0], '_blank');
        else if (line.startsWith('/')) window.open(baseUrl + line.split(' ')[0], '_blank');
        else alert('No URL found on that line.');
    });

    /* Copy */
    root.querySelector('#rbtn-copy').addEventListener('click',function(){
        navigator.clipboard.writeText(out.value).then(function(){
            var btn=root.querySelector('#rbtn-copy');
            btn.textContent='Copied!';
            setTimeout(function(){ btn.textContent='Copy'; },1500);
        }).catch(function(){ out.select(); document.execCommand('copy'); });
    });

    /* Add bookmark manually */
    root.querySelector('#bm-add-btn').addEventListener('click',function(){
        var url=root.querySelector('#bm-url-in').value.trim();
        if (!url) { root.querySelector('#bm-url-in').focus(); return; }
        var note=root.querySelector('#bm-note-in').value.trim();
        var tag=root.querySelector('#bm-tag-in').value.trim();
        if (!addBookmark(url,note,tag)) { alert('Already bookmarked.'); return; }
        root.querySelector('#bm-url-in').value='';
        root.querySelector('#bm-note-in').value='';
        root.querySelector('#bm-tag-in').value='';
        renderBM();
    });
    root.querySelector('#bm-url-in').addEventListener('keydown',function(e){ if(e.key==='Enter') root.querySelector('#bm-add-btn').click(); });
    root.querySelector('#bm-filter-tag').addEventListener('input',renderBM);

    /* Export bookmarks */
    root.querySelector('#bm-export-btn').addEventListener('click',function(){
        var txt=D.bookmarks.map(function(b){ return '['+( b.tag||'-')+'] '+b.url+(b.note?'  // '+b.note:'')+' ('+b.ts+')'; }).join('\n');
        var a=document.createElement('a');
        a.href=URL.createObjectURL(new Blob([txt],{type:'text/plain'}));
        a.download='bookmarks-'+rootDomain+'-'+Date.now()+'.txt'; a.click();
    });

    /* Clear bookmarks */
    root.querySelector('#bm-clear-btn').addEventListener('click',function(){
        if (!D.bookmarks.length) return;
        if (confirm('Clear all '+D.bookmarks.length+' bookmarks?')) { D.bookmarks.length=0; renderBM(); }
    });

    /* Export all JSON */
    root.querySelector('#rbtn-export').addEventListener('click',function(){
        var data = {
            target:rootDomain, timestamp:new Date().toISOString(),
            curls:getCurlLines(), fullUrls:getFullUrlLines(),
            endpoints:getEndpointLines(), targetSubdomains:Array.from(D.targetSubs),
            potential:Array.from(D.potentialSubs), s3Buckets:Array.from(D.s3Buckets),
            webSockets:Array.from(D.wsEndpoints), internalIps:Array.from(D.internalIps),
            graphql:Array.from(D.graphql), secrets:getSecretsSorted(),
            bookmarks:D.bookmarks, scannedScripts:D.sources,
        };
        var a=document.createElement('a');
        a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
        a.download='recon-'+rootDomain+'-'+Date.now()+'.json'; a.click();
    });

    /* Rescan */
    root.querySelector('#rh-rescan').addEventListener('click',function(){
        D.endpoints.clear(); D.fullUrls.clear(); D.curls.clear(); D.secrets.clear();
        D.targetSubs.clear(); D.potentialSubs.clear(); D.s3Buckets.clear();
        D.wsEndpoints.clear(); D.internalIps.clear(); D.graphql.clear();
        D.targetSubs.add(currentHost); D.scanned=0;
        root.querySelector('#rh-status').textContent = 'Rescanning\u2026';
        scanText(document.documentElement.outerHTML);
        runFetches();
    });

    root.querySelector('#rh-close').addEventListener('click',function(){ root.remove(); });

    render();
    return { render:render, updateCounts:updateCounts };
}

var ui = buildUI();

/* ── Fetch & scan external scripts ───────────────────────────── */
function runFetches() {
    var jobs = D.sources.map(function(url){
        return fetch(url,{credentials:'omit'})
            .then(function(r){ return r.text(); })
            .then(function(t){
                scanText(t); D.scanned++;
                var el=document.querySelector('#__recon__ #rh-status');
                if (el) el.textContent='Scanned '+D.scanned+'/'+D.total+' scripts\u2026';
                ui.render();
            })
            .catch(function(){ D.scanned++; });
    });
    Promise.all(jobs).then(function(){
        var el=document.querySelector('#__recon__ #rh-status');
        if (el) el.textContent='Done \u2014 '+D.scanned+' script'+(D.scanned!==1?'s':'')+' scanned';
        ui.render();
    });
}

runFetches();

})();
