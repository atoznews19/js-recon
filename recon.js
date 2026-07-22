/**
 * recon.js v4.0.0 - Complete Recon Scanner
 * Auto-generated build
 */

// ============================================================
// PART 1: CONSTANTS & UTILITIES
// ============================================================

const CONFIG = {
  VERSION: '4.0.0',
  DEBUG: false,
  MAX_CONCURRENT_REQUESTS: 10,
  REQUEST_TIMEOUT: 10000,
  RETRY_ATTEMPTS: 2,
  RETRY_DELAY: 1000,
  ENDPOINT_SCAN_DEPTH: 2,
  ENDPOINT_BATCH_SIZE: 50,
  MAX_ENDPOINTS: 5000,
  SECRET_SCAN_BATCH_SIZE: 100,
  MIN_ENTROPY_THRESHOLD: 3.5,
  UI_UPDATE_INTERVAL: 250,
  MAX_LOG_ENTRIES: 1000,
  RESULTS_PER_PAGE: 50,
  STORAGE_KEYS: {
    BOOKMARKS: 'recon_bookmarks',
    SETTINGS: 'recon_settings',
    HISTORY: 'recon_history',
    SAVED_RESULTS: 'recon_saved_results',
  },
  DEFAULT_HEADERS: {
    'User-Agent': 'Recon-Scanner/4.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
  },
};

const Utils = {
  generateId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let id = '';
    for (let i = 0; i < length; i++) {
      id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
  },
  debounce(func, wait = 300) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  },
  throttle(func, limit = 250) {
    let inThrottle;
    return function(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => (inThrottle = false), limit);
      }
    };
  },
  deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj);
    if (obj instanceof Array) return obj.map(item => this.deepClone(item));
    const clone = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        clone[key] = this.deepClone(obj[key]);
      }
    }
    return clone;
  },
  safeJSONParse(str, fallback = null) {
    try { return JSON.parse(str); } catch { return fallback; }
  },
  calculateEntropy(str) {
    if (!str || str.length < 8) return 0;
    const freq = {};
    for (const char of str) freq[char] = (freq[char] || 0) + 1;
    let entropy = 0;
    const len = str.length;
    for (const key in freq) {
      const p = freq[key] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  },
  looksLikeSecret(value) {
    if (!value || typeof value !== 'string') return false;
    const patterns = [
      /[A-Za-z0-9+/]{32,}={0,2}/, /[0-9a-f]{32,}/i, /[0-9a-f]{40,}/i,
      /[0-9a-f]{64,}/i, /[A-Z]{2,}[0-9]{6,}/, /sk_live_[A-Za-z0-9]{24}/,
      /sk_test_[A-Za-z0-9]{24}/, /ghp_[A-Za-z0-9]{36}/, /AKIA[0-9A-Z]{16}/
    ];
    return patterns.some(p => p.test(value));
  },
  formatTimestamp(date, format = 'YYYY-MM-DD HH:mm:ss') {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return 'Invalid Date';
    const pad = n => String(n).padStart(2, '0');
    const r = {
      'YYYY': d.getFullYear(), 'MM': pad(d.getMonth() + 1),
      'DD': pad(d.getDate()), 'HH': pad(d.getHours()),
      'mm': pad(d.getMinutes()), 'ss': pad(d.getSeconds())
    };
    return format.replace(/YYYY|MM|DD|HH|mm|ss/g, m => r[m] || m);
  },
  escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },
  getURLOrigin(url) {
    try { return new URL(url).origin; } catch { return url; }
  },
  normalizeURL(url) {
    try {
      const parsed = new URL(url);
      parsed.hash = '';
      parsed.search = parsed.search.replace(/[^=&]+=[^&]*/g, '');
      return parsed.toString().replace(//+$/, '');
    } catch { return url; }
  },
  sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); },
  async retry(fn, maxRetries = 3, delay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try { return await fn(); }
      catch (error) {
        if (attempt === maxRetries) throw error;
        await this.sleep(delay * Math.pow(2, attempt - 1));
      }
    }
  },
  async batchProcess(items, processor, concurrency = 5) {
    const results = [];
    for (let i = 0; i < items.length; i += concurrency) {
      const chunk = items.slice(i, i + concurrency);
      const chunkResults = await Promise.all(
        chunk.map(item => processor(item).catch(err => ({ error: err, item })))
      );
      results.push(...chunkResults);
    }
    return results;
  },
  createElement(tag, attributes = {}, content = null) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attributes)) {
      if (key === 'className') el.className = value;
      else if (key === 'dataset') {
        for (const [dk, dv] of Object.entries(value)) el.dataset[dk] = dv;
      } else if (key.startsWith('on') && typeof value === 'function') {
        el.addEventListener(key.slice(2).toLowerCase(), value);
      } else el.setAttribute(key, value);
    }
    if (content) {
      if (typeof content === 'string') el.innerHTML = content;
      else if (content instanceof Node) el.appendChild(content);
    }
    return el;
  },
  renderTemplate(template, data) {
    return template.replace(/{{([^}]+)}}/g, (_, key) => {
      const value = data[key.trim()];
      return value !== undefined ? value : _;
    });
  }
};

const Patterns = {
  URL: {
    URL: /https?://[^s"'<>]+/gi,
    API_ENDPOINT: //api/[a-zA-Z0-9-_/]+/gi,
    GRAPHQL: //graphql(?:?.+)?$/i,
    WEBSOCKET: /wss?://[^s"']+/gi,
    ADMIN: //(?:admin|administrator|manage|dashboard|control)/i,
    LOGIN: //(?:login|signin|auth|authenticate)/i,
    UPLOAD: //(?:upload|file|media|asset|storage)/i,
  },
  SECRETS: {
    AWS_KEY: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    GITHUB_TOKEN: /gh[ops]_[a-zA-Z0-9]{36,}/g,
    SLACK_TOKEN: /xox[baprs]-[0-9a-zA-Z]{10,}/g,
    STRIPE_LIVE: /sk_live_[0-9a-zA-Z]{24}/g,
    STRIPE_TEST: /sk_test_[0-9a-zA-Z]{24}/g,
    JWT: /eyJ[a-zA-Z0-9_-]+.[a-zA-Z0-9_-]+.[a-zA-Z0-9_-]+/g,
    GOOGLE_API: /AIza[0-9A-Za-z-_]{35}/g,
  },
  FILES: {
    JSON: /.json(?:?.*)?$/i,
    XML: /.xml(?:?.*)?$/i,
    YAML: /.ya?ml(?:?.*)?$/i,
    JS: /.js(?:?.*)?$/i,
    CSS: /.css(?:?.*)?$/i,
    HTML: /.html?/i,
    PHP: /.php(?:?.*)?$/i,
    ENV: /.env(?:?.*)?$/i,
  },
  SENSITIVE: {
    EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}/g,
    PHONE: /d{3}[-.]?d{3}[-.]?d{4}/g,
    IPV4: /(?:d{1,3}.){3}d{1,3}/g,
    API_KEY: /[a-zA-Z0-9-_]{20,}/g,
  },
  testAll(text, patternObj) {
    const results = [];
    for (const [name, pattern] of Object.entries(patternObj)) {
      if (pattern instanceof RegExp) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
          results.push({ type: name, match: match[0], index: match.index });
        }
      }
    }
    return results;
  }
};

// ============================================================
// PART 2: DATA STORE
// ============================================================

class DataStore {
  constructor() {
    this.data = {
      endpoints: new Map(),
      secrets: [],
      graphql: [],
      websockets: [],
      vulnerabilities: [],
      logs: [],
      bookmarks: new Map(),
      stats: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        startTime: null,
        endTime: null,
      }
    };
    this.listeners = new Map();
    this.persistKey = CONFIG.STORAGE_KEYS.SAVED_RESULTS;
    this.loadFromStorage();
  }

  subscribe(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.listeners.get(event).delete(callback);
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(cb => {
        try { cb(data); } catch (e) { console.error('Listener error:', e); }
      });
    }
  }

  addEndpoint(url, data = {}) {
    const normalized = Utils.normalizeURL(url);
    if (!this.data.endpoints.has(normalized)) {
      this.data.endpoints.set(normalized, {
        url: normalized,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        status: 'pending',
        ...data
      });
      this.emit('endpoint:added', { url: normalized, data });
      this.saveToStorage();
      return true;
    }
    this.data.endpoints.get(normalized).lastSeen = Date.now();
    Object.assign(this.data.endpoints.get(normalized), data);
    return false;
  }

  getEndpoints() {
    return Array.from(this.data.endpoints.values());
  }

  getEndpointsByStatus(status) {
    return this.getEndpoints().filter(e => e.status === status);
  }

  addSecret(secret) {
    if (!this.data.secrets.some(s => s.value === secret.value)) {
      this.data.secrets.push({
        ...secret,
        id: Utils.generateId(),
        timestamp: Date.now()
      });
      this.emit('secret:added', secret);
      this.saveToStorage();
      return true;
    }
    return false;
  }

  getSecrets() {
    return this.data.secrets;
  }

  addGraphQL(endpoint) {
    if (!this.data.graphql.some(g => g.url === endpoint.url)) {
      this.data.graphql.push({
        ...endpoint,
        id: Utils.generateId(),
        timestamp: Date.now()
      });
      this.emit('graphql:added', endpoint);
      this.saveToStorage();
      return true;
    }
    return false;
  }

  getGraphQL() {
    return this.data.graphql;
  }

  addWebSocket(ws) {
    if (!this.data.websockets.some(w => w.url === ws.url)) {
      this.data.websockets.push({
        ...ws,
        id: Utils.generateId(),
        timestamp: Date.now()
      });
      this.emit('websocket:added', ws);
      this.saveToStorage();
      return true;
    }
    return false;
  }

  getWebSockets() {
    return this.data.websockets;
  }

  addVulnerability(vuln) {
    this.data.vulnerabilities.push({
      ...vuln,
      id: Utils.generateId(),
      timestamp: Date.now()
    });
    this.emit('vulnerability:added', vuln);
    this.saveToStorage();
  }

  getVulnerabilities() {
    return this.data.vulnerabilities;
  }

  addLog(message, level = 'info') {
    const log = {
      message,
      level,
      timestamp: Date.now(),
      id: Utils.generateId()
    };
    this.data.logs.push(log);
    if (this.data.logs.length > CONFIG.MAX_LOG_ENTRIES) {
      this.data.logs.shift();
    }
    this.emit('log:added', log);
    return log;
  }

  getLogs() {
    return this.data.logs;
  }

  getStats() {
    const endpoints = this.getEndpoints();
    return {
      ...this.data.stats,
      totalEndpoints: endpoints.length,
      endpointsByStatus: {
        pending: endpoints.filter(e => e.status === 'pending').length,
        success: endpoints.filter(e => e.status === 'success').length,
        failed: endpoints.filter(e => e.status === 'failed').length,
      },
      secrets: this.data.secrets.length,
      graphql: this.data.graphql.length,
      websockets: this.data.websockets.length,
      vulnerabilities: this.data.vulnerabilities.length,
      logs: this.data.logs.length,
    };
  }

  clear() {
    this.data.endpoints.clear();
    this.data.secrets = [];
    this.data.graphql = [];
    this.data.websockets = [];
    this.data.vulnerabilities = [];
    this.data.logs = [];
    this.data.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      startTime: null,
      endTime: null,
    };
    this.emit('cleared', {});
    this.saveToStorage();
  }

  saveToStorage() {
    try {
      const serialized = {
        endpoints: Array.from(this.data.endpoints.entries()),
        secrets: this.data.secrets,
        graphql: this.data.graphql,
        websockets: this.data.websockets,
        vulnerabilities: this.data.vulnerabilities,
        stats: this.data.stats,
        savedAt: Date.now()
      };
      localStorage.setItem(this.persistKey, JSON.stringify(serialized));
    } catch (e) {
      console.warn('Failed to save to storage:', e);
    }
  }

  loadFromStorage() {
    try {
      const raw = localStorage.getItem(this.persistKey);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (saved.endpoints) {
        this.data.endpoints = new Map(saved.endpoints);
      }
      if (saved.secrets) this.data.secrets = saved.secrets;
      if (saved.graphql) this.data.graphql = saved.graphql;
      if (saved.websockets) this.data.websockets = saved.websockets;
      if (saved.vulnerabilities) this.data.vulnerabilities = saved.vulnerabilities;
      if (saved.stats) this.data.stats = saved.stats;
    } catch (e) {
      console.warn('Failed to load from storage:', e);
    }
  }

  exportData() {
    return {
      version: CONFIG.VERSION,
      exportedAt: Date.now(),
      endpoints: this.getEndpoints(),
      secrets: this.data.secrets,
      graphql: this.data.graphql,
      websockets: this.data.websockets,
      vulnerabilities: this.data.vulnerabilities,
      stats: this.getStats(),
    };
  }

  importData(data) {
    this.clear();
    if (data.endpoints) {
      data.endpoints.forEach(e => {
        this.data.endpoints.set(e.url, e);
      });
    }
    if (data.secrets) this.data.secrets = data.secrets;
    if (data.graphql) this.data.graphql = data.graphql;
    if (data.websockets) this.data.websockets = data.websockets;
    if (data.vulnerabilities) this.data.vulnerabilities = data.vulnerabilities;
    this.emit('imported', data);
    this.saveToStorage();
  }
}

// ============================================================
// PART 3: ENDPOINT SCANNER
// ============================================================

class EndpointScanner {
  constructor(store) {
    this.store = store;
    this.isRunning = false;
    this.queue = [];
    this.processed = new Set();
    this.discovered = new Set();
  }

  async scan(baseUrl, depth = CONFIG.ENDPOINT_SCAN_DEPTH) {
    if (this.isRunning) {
      this.store.addLog('Scanner already running', 'warning');
      return;
    }

    this.isRunning = true;
    this.processed = new Set();
    this.discovered = new Set();
    this.queue = [];
    
    this.store.addLog(`Starting endpoint scan: ${baseUrl} (depth: ${depth})`, 'info');
    this.store.data.stats.startTime = Date.now();

    try {
      await this.discoverEndpoints(baseUrl, depth);
      await this.scanAllEndpoints();
    } catch (error) {
      this.store.addLog(`Scan error: ${error.message}`, 'error');
      console.error('Scan error:', error);
    }

    this.isRunning = false;
    this.store.data.stats.endTime = Date.now();
    this.store.addLog('Endpoint scan completed', 'info');
    this.store.emit('scan:complete', this.store.getStats());
  }

  async discoverEndpoints(baseUrl, depth, currentDepth = 0) {
    if (currentDepth > depth) return;
    if (this.discovered.has(baseUrl)) return;
    if (this.discovered.size > CONFIG.MAX_ENDPOINTS) {
      this.store.addLog('Max endpoints reached, stopping discovery', 'warning');
      return;
    }

    this.discovered.add(baseUrl);
    this.queue.push({ url: baseUrl, depth: currentDepth });
    this.store.addEndpoint(baseUrl);

    if (currentDepth < depth) {
      try {
        const response = await this.fetchWithTimeout(baseUrl);
        if (response.ok) {
          const html = await response.text();
          const links = this.extractLinks(html, baseUrl);
          
          for (const link of links) {
            if (!this.discovered.has(link) && this.shouldFollow(link)) {
              await this.discoverEndpoints(link, depth, currentDepth + 1);
            }
          }
        }
      } catch (error) {
        this.store.addLog(`Failed to fetch ${baseUrl}: ${error.message}`, 'warning');
      }
    }
  }

  async scanAllEndpoints() {
    const endpoints = this.queue.filter(q => !this.processed.has(q.url));
    this.store.addLog(`Scanning ${endpoints.length} endpoints`, 'info');

    await Utils.batchProcess(
      endpoints,
      async (item) => {
        if (this.processed.has(item.url)) return;
        this.processed.add(item.url);
        
        try {
          const response = await this.fetchWithTimeout(item.url);
          const endpoint = this.store.data.endpoints.get(Utils.normalizeURL(item.url));
          if (endpoint) {
            endpoint.status = response.ok ? 'success' : 'failed';
            endpoint.statusCode = response.status;
            endpoint.headers = Object.fromEntries(response.headers);
            endpoint.contentLength = parseInt(response.headers.get('content-length') || '0');
            endpoint.contentType = response.headers.get('content-type') || 'unknown';
            endpoint.lastChecked = Date.now();
            
            if (response.ok) {
              this.store.data.stats.successfulRequests++;
              const body = await response.text();
              await this.analyzeContent(item.url, body, response.headers);
            }
          }
        } catch (error) {
          this.store.addLog(`Failed to scan ${item.url}: ${error.message}`, 'error');
          const endpoint = this.store.data.endpoints.get(Utils.normalizeURL(item.url));
          if (endpoint) {
            endpoint.status = 'failed';
            endpoint.error = error.message;
          }
          this.store.data.stats.failedRequests++;
        }
        this.store.data.stats.totalRequests++;
        this.store.emit('endpoint:scanned', { url: item.url });
      },
      CONFIG.ENDPOINT_BATCH_SIZE
    );
  }

  async fetchWithTimeout(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);
    
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: CONFIG.DEFAULT_HEADERS,
      });
      return response;
    } finally {
      clearTimeout(timeout);
    }
  }

  extractLinks(html, baseUrl) {
    const links = new Set();
    const urlPattern = /https?://[^s"'<>]+/gi;
    const relativePattern = /(?:href|src|action)=["']([^"']+)["']/gi;
    
    let match;
    while ((match = urlPattern.exec(html)) !== null) {
      try {
        const url = new URL(match[0]);
        links.add(url.href);
      } catch (e) {}
    }
    
    while ((match = relativePattern.exec(html)) !== null) {
      try {
        const url = new URL(match[1], baseUrl);
        links.add(url.href);
      } catch (e) {}
    }
    
    return Array.from(links);
  }

  shouldFollow(url) {
    try {
      const parsed = new URL(url);
      const extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.mp4', '.mp3', '.pdf'];
      return !extensions.some(ext => parsed.pathname.endsWith(ext));
    } catch {
      return false;
    }
  }

  async analyzeContent(url, body, headers) {
    // Check for secrets
    const secretMatches = Patterns.testAll(body, Patterns.SECRETS);
    for (const match of secretMatches) {
      this.store.addSecret({
        value: match.match,
        type: match.type,
        location: url,
        context: this.getContext(body, match.index),
      });
    }

    // Check for GraphQL
    if (Patterns.URL.GRAPHQL.test(url) || body.includes('__schema')) {
      this.store.addGraphQL({
        url: url,
        methods: ['POST', 'GET'],
        introspection: body.includes('__schema'),
      });
    }

    // Check for WebSocket
    if (Patterns.URL.WEBSOCKET.test(url) || body.includes('WebSocket')) {
      this.store.addWebSocket({
        url: url,
        protocols: this.extractWSProtocols(body),
      });
    }

    // Check for vulnerabilities
    for (const [type, pattern] of Object.entries(Patterns.VULNERABILITIES)) {
      if (pattern.test(body)) {
        this.store.addVulnerability({
          type: type,
          location: url,
          severity: this.getSeverity(type),
          description: `Potential ${type} found`,
        });
      }
    }
  }

  getContext(text, index, length = 50) {
    const start = Math.max(0, index - length);
    const end = Math.min(text.length, index + length);
    return text.substring(start, end);
  }

  extractWSProtocols(body) {
    const protocols = [];
    const matches = body.match(/["'](wss?://[^"']+)["']/gi);
    if (matches) {
      matches.forEach(m => {
        protocols.push(m.replace(/["']/g, ''));
      });
    }
    return protocols;
  }

  getSeverity(type) {
    const severity = {
      'SQL_INJECTION': 'critical',
      'XSS': 'high',
      'LFI': 'high',
      'RCE': 'critical',
    };
    return severity[type] || 'medium';
  }

  stop() {
    this.isRunning = false;
    this.store.addLog('Scan stopped by user', 'warning');
  }

  getProgress() {
    const total = this.queue.length;
    const processed = this.processed.size;
    return {
      total,
      processed,
      percentage: total > 0 ? (processed / total) * 100 : 0,
    };
  }
}

// ============================================================
// PART 4: SECRET SCANNER
// ============================================================

class SecretScanner {
  constructor(store) {
    this.store = store;
    this.isRunning = false;
  }

  async scanText(text, source = 'unknown') {
    const secrets = [];
    const allPatterns = { ...Patterns.SECRETS, ...Patterns.SENSITIVE };
    
    for (const [type, pattern] of Object.entries(allPatterns)) {
      if (pattern instanceof RegExp) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
          const value = match[0];
          if (this.isValidSecret(value)) {
            secrets.push({
              type,
              value,
              source,
              index: match.index,
              context: this.getContext(text, match.index),
              entropy: Utils.calculateEntropy(value),
            });
          }
        }
      }
    }
    
    return secrets;
  }

  isValidSecret(value) {
    if (!value || value.length < 8) return false;
    if (value.length > 200) return false;
    if (Utils.looksLikeSecret(value)) {
      const entropy = Utils.calculateEntropy(value);
      return entropy > CONFIG.MIN_ENTROPY_THRESHOLD;
    }
    return false;
  }

  getContext(text, index, length = 80) {
    const start = Math.max(0, index - length);
    const end = Math.min(text.length, index + length);
    return text.substring(start, end);
  }

  async scanURL(url) {
    this.isRunning = true;
    this.store.addLog(`Scanning URL for secrets: ${url}`, 'info');
    
    try {
      const response = await fetch(url, {
        headers: CONFIG.DEFAULT_HEADERS,
      });
      
      if (response.ok) {
        const text = await response.text();
        const secrets = await this.scanText(text, url);
        
        for (const secret of secrets) {
          this.store.addSecret(secret);
        }
        
        this.store.addLog(`Found ${secrets.length} secrets in ${url}`, 'info');
        return secrets;
      }
    } catch (error) {
      this.store.addLog(`Failed to scan ${url}: ${error.message}`, 'error');
    }
    
    this.isRunning = false;
    return [];
  }

  async scanAllEndpoints(endpoints) {
    this.isRunning = true;
    this.store.addLog(`Scanning ${endpoints.length} endpoints for secrets`, 'info');
    
    const results = [];
    await Utils.batchProcess(
      endpoints,
      async (endpoint) => {
        const secrets = await this.scanURL(endpoint.url);
        if (secrets.length > 0) {
          results.push({ endpoint: endpoint.url, secrets });
        }
      },
      CONFIG.SECRET_SCAN_BATCH_SIZE
    );
    
    this.isRunning = false;
    this.store.addLog(`Secret scan complete: ${results.length} endpoints with secrets`, 'info');
    return results;
  }

  stop() {
    this.isRunning = false;
    this.store.addLog('Secret scan stopped', 'warning');
  }
}

// ============================================================
// PART 4B: GRAPHQL SCANNER
// ============================================================

class GraphQLScanner {
  constructor(store) {
    this.store = store;
    this.isRunning = false;
  }

  async scan(endpoint) {
    this.store.addLog(`Scanning GraphQL endpoint: ${endpoint}`, 'info');
    
    const queries = [
      '{ __schema { types { name fields { name } } } }',
      '{ __type(name: "Query") { fields { name } } }',
      'query { __schema { queryType { fields { name } } } }',
      '{ __schema { mutationType { fields { name } } } }',
    ];
    
    const results = [];
    
    for (const query of queries) {
      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            ...CONFIG.DEFAULT_HEADERS,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ query }),
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.data) {
            results.push({
              query,
              data: data.data,
              introspection: true,
            });
            
            this.store.addGraphQL({
              url: endpoint,
              introspection: true,
              schema: data.data,
              timestamp: Date.now(),
            });
          }
        }
      } catch (error) {
        this.store.addLog(`GraphQL scan failed for ${endpoint}: ${error.message}`, 'warning');
      }
    }
    
    return results;
  }

  async scanAll(graphqlEndpoints) {
    this.isRunning = true;
    this.store.addLog(`Scanning ${graphqlEndpoints.length} GraphQL endpoints`, 'info');
    
    const results = [];
    for (const endpoint of graphqlEndpoints) {
      const result = await this.scan(endpoint.url);
      if (result.length > 0) {
        results.push({ endpoint: endpoint.url, results: result });
      }
    }
    
    this.isRunning = false;
    this.store.addLog(`GraphQL scan complete: ${results.length} endpoints with introspection`, 'info');
    return results;
  }

  stop() {
    this.isRunning = false;
    this.store.addLog('GraphQL scan stopped', 'warning');
  }
}

// ============================================================
// PART 5: WEBSOCKET SCANNER
// ============================================================

class WebSocketScanner {
  constructor(store) {
    this.store = store;
    this.isRunning = false;
    this.connections = new Map();
  }

  async scan(wsUrl) {
    this.store.addLog(`Scanning WebSocket: ${wsUrl}`, 'info');
    
    return new Promise((resolve) => {
      try {
        const ws = new WebSocket(wsUrl);
        this.connections.set(wsUrl, ws);
        
        const timeout = setTimeout(() => {
          ws.close();
          this.store.addLog(`WebSocket ${wsUrl} timed out`, 'warning');
          resolve({ url: wsUrl, status: 'timeout' });
        }, 5000);
        
        ws.onopen = () => {
          clearTimeout(timeout);
          this.store.addWebSocket({
            url: wsUrl,
            status: 'open',
            timestamp: Date.now(),
          });
          
          // Send test message
          ws.send(JSON.stringify({ type: 'ping', data: 'test' }));
          resolve({ url: wsUrl, status: 'open' });
        };
        
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.store.addLog(`WebSocket message from ${wsUrl}: ${event.data}`, 'debug');
            this.store.data.websockets.forEach(w => {
              if (w.url === wsUrl) {
                w.messages = w.messages || [];
                w.messages.push(data);
              }
            });
          } catch (e) {
            // Non-JSON message
          }
        };
        
        ws.onerror = (error) => {
          clearTimeout(timeout);
          this.store.addLog(`WebSocket error ${wsUrl}: ${error}`, 'error');
          resolve({ url: wsUrl, status: 'error', error });
        };
        
        ws.onclose = () => {
          clearTimeout(timeout);
          this.store.addLog(`WebSocket closed: ${wsUrl}`, 'info');
        };
      } catch (error) {
        this.store.addLog(`Failed to connect to WebSocket ${wsUrl}: ${error.message}`, 'error');
        resolve({ url: wsUrl, status: 'error', error: error.message });
      }
    });
  }

  async scanAll(wsUrls) {
    this.isRunning = true;
    this.store.addLog(`Scanning ${wsUrls.length} WebSocket endpoints`, 'info');
    
    const results = [];
    for (const url of wsUrls) {
      const result = await this.scan(url);
      results.push(result);
    }
    
    this.isRunning = false;
    this.store.addLog(`WebSocket scan complete: ${results.filter(r => r.status === 'open').length} open`, 'info');
    return results;
  }

  stop() {
    this.isRunning = false;
    for (const [url, ws] of this.connections) {
      try {
        ws.close();
      } catch (e) {}
    }
    this.connections.clear();
    this.store.addLog('WebSocket scan stopped', 'warning');
  }
}

// ============================================================
// PART 5B: UI COMPONENTS
// ============================================================

class UIComponents {
  constructor(store) {
    this.store = store;
    this.container = null;
    this.components = new Map();
    this.rendered = false;
  }

  init(containerId = 'recon-ui') {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = containerId;
      document.body.prepend(this.container);
    }
    this.render();
    this.rendered = true;
    this.setupEventListeners();
  }

  render() {
    if (!this.container) return;
    
    this.container.innerHTML = `
      <div class="recon-container">
        <div class="recon-header">
          <h1>🔍 Recon Scanner v${CONFIG.VERSION}</h1>
          <div class="recon-controls">
            <input type="text" id="recon-url-input" placeholder="Enter target URL..." />
            <button id="recon-scan-btn">Start Scan</button>
            <button id="recon-stop-btn" style="display:none">Stop</button>
            <button id="recon-export-btn">Export</button>
            <button id="recon-import-btn">Import</button>
            <button id="recon-clear-btn">Clear</button>
          </div>
        </div>
        
        <div class="recon-stats">
          <div class="stat-item">
            <span class="stat-label">Endpoints</span>
            <span class="stat-value" id="stat-endpoints">0</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Secrets</span>
            <span class="stat-value" id="stat-secrets">0</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">GraphQL</span>
            <span class="stat-value" id="stat-graphql">0</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">WebSockets</span>
            <span class="stat-value" id="stat-websockets">0</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Vulnerabilities</span>
            <span class="stat-value" id="stat-vulns">0</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Requests</span>
            <span class="stat-value" id="stat-requests">0</span>
          </div>
        </div>
        
        <div class="recon-tabs">
          <button class="tab-btn active" data-tab="endpoints">Endpoints</button>
          <button class="tab-btn" data-tab="secrets">Secrets</button>
          <button class="tab-btn" data-tab="graphql">GraphQL</button>
          <button class="tab-btn" data-tab="websockets">WebSockets</button>
          <button class="tab-btn" data-tab="vulnerabilities">Vulnerabilities</button>
          <button class="tab-btn" data-tab="logs">Logs</button>
        </div>
        
        <div class="recon-content">
          <div id="tab-endpoints" class="tab-content active">
            <div class="recon-table-container">
              <table class="recon-table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Status Code</th>
                    <th>Content Type</th>
                    <th>Last Checked</th>
                  </tr>
                </thead>
                <tbody id="endpoints-table-body"></tbody>
              </table>
            </div>
          </div>
          
          <div id="tab-secrets" class="tab-content">
            <div class="recon-table-container">
              <table class="recon-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Location</th>
                    <th>Entropy</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody id="secrets-table-body"></tbody>
              </table>
            </div>
          </div>
          
          <div id="tab-graphql" class="tab-content">
            <div class="recon-table-container">
              <table class="recon-table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Introspection</th>
                    <th>Methods</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody id="graphql-table-body"></tbody>
              </table>
            </div>
          </div>
          
          <div id="tab-websockets" class="tab-content">
            <div class="recon-table-container">
              <table class="recon-table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Protocols</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody id="websockets-table-body"></tbody>
              </table>
            </div>
          </div>
          
          <div id="tab-vulnerabilities" class="tab-content">
            <div class="recon-table-container">
              <table class="recon-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Location</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody id="vulnerabilities-table-body"></tbody>
              </table>
            </div>
          </div>
          
          <div id="tab-logs" class="tab-content">
            <div class="recon-logs-container" id="logs-container"></div>
          </div>
        </div>
      </div>
    `;
    
    // Apply styles
    this.injectStyles();
  }

  injectStyles() {
    const styleId = 'recon-styles';
    if (document.getElementById(styleId)) return;
    
    const styles = `
      .recon-container { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 100%; padding: 20px; background: #f5f7fa; color: #333; }
      .recon-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
      .recon-header h1 { margin: 0; font-size: 24px; color: #2c3e50; }
      .recon-controls { display: flex; gap: 10px; flex-wrap: wrap; }
      .recon-controls input { padding: 8px 12px; border: 1px solid #dce1e8; border-radius: 4px; font-size: 14px; min-width: 200px; }
      .recon-controls button { padding: 8px 16px; border: none; border-radius: 4px; background: #3498db; color: white; cursor: pointer; font-size: 14px; transition: background 0.2s; }
      .recon-controls button:hover { background: #2980b9; }
      .recon-controls button#recon-stop-btn { background: #e74c3c; }
      .recon-controls button#recon-stop-btn:hover { background: #c0392b; }
      .recon-controls button#recon-export-btn { background: #2ecc71; }
      .recon-controls button#recon-export-btn:hover { background: #27ae60; }
      .recon-controls button#recon-import-btn { background: #f39c12; }
      .recon-controls button#recon-import-btn:hover { background: #e67e22; }
      .recon-controls button#recon-clear-btn { background: #95a5a6; }
      .recon-controls button#recon-clear-btn:hover { background: #7f8c8d; }
      .recon-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; margin-bottom: 20px; }
      .stat-item { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
      .stat-label { display: block; font-size: 12px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; }
      .stat-value { display: block; font-size: 24px; font-weight: bold; color: #2c3e50; }
      .recon-tabs { display: flex; gap: 5px; margin-bottom: 15px; flex-wrap: wrap; border-bottom: 2px solid #dce1e8; padding-bottom: 0; }
      .tab-btn { padding: 10px 20px; border: none; background: transparent; cursor: pointer; font-size: 14px; color: #7f8c8d; border-bottom: 3px solid transparent; transition: all 0.2s; }
      .tab-btn:hover { color: #2c3e50; }
      .tab-btn.active { color: #3498db; border-bottom-color: #3498db; }
      .tab-content { display: none; background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .tab-content.active { display: block; }
      .recon-table-container { overflow-x: auto; max-height: 400px; overflow-y: auto; }
      .recon-table { width: 100%; border-collapse: collapse; font-size: 13px; }
      .recon-table th { background: #f8f9fa; padding: 10px; text-align: left; border-bottom: 2px solid #dce1e8; position: sticky; top: 0; z-index: 10; }
      .recon-table td { padding: 8px 10px; border-bottom: 1px solid #ecf0f1; word-break: break-word; }
      .recon-table tr:hover { background: #f8f9fa; }
      .recon-logs-container { max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 12px; background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; }
      .log-entry { padding: 2px 0; border-bottom: 1px solid #34495e; }
      .log-entry.error { color: #e74c3c; }
      .log-entry.warning { color: #f39c12; }
      .log-entry.success { color: #2ecc71; }
      .log-entry.info { color: #3498db; }
      .status-success { color: #2ecc71; }
      .status-failed { color: #e74c3c; }
      .status-pending { color: #f39c12; }
      .severity-critical { color: #e74c3c; font-weight: bold; }
      .severity-high { color: #e67e22; }
      .severity-medium { color: #f39c12; }
      .severity-low { color: #3498db; }
      @media (max-width: 768px) {
        .recon-header { flex-direction: column; align-items: stretch; }
        .recon-controls { flex-direction: column; }
        .recon-controls input { min-width: auto; }
        .recon-stats { grid-template-columns: repeat(3, 1fr); }
        .recon-tabs { overflow-x: auto; flex-wrap: nowrap; }
      }
    `;
    
    const styleEl = document.createElement('style');
    styleEl.id = styleId;
    styleEl.textContent = styles;
    document.head.appendChild(styleEl);
  }

  setupEventListeners() {
    // Scan button
    const scanBtn = document.getElementById('recon-scan-btn');
    const stopBtn = document.getElementById('recon-stop-btn');
    const urlInput = document.getElementById('recon-url-input');
    const exportBtn = document.getElementById('recon-export-btn');
    const importBtn = document.getElementById('recon-import-btn');
    const clearBtn = document.getElementById('recon-clear-btn');

    scanBtn?.addEventListener('click', () => {
      const url = urlInput?.value.trim();
      if (url) {
        this.store.emit('ui:scan-start', { url });
      } else {
        alert('Please enter a target URL');
      }
    });

    stopBtn?.addEventListener('click', () => {
      this.store.emit('ui:scan-stop', {});
    });

    exportBtn?.addEventListener('click', () => {
      this.store.emit('ui:export', {});
    });

    importBtn?.addEventListener('click', () => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.json';
      input.onchange = (e) => {
        const file = e.target.files[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = (event) => {
            try {
              const data = JSON.parse(event.target.result);
              this.store.emit('ui:import', { data });
            } catch (err) {
              alert('Invalid JSON file');
            }
          };
          reader.readAsText(file);
        }
      };
      input.click();
    });

    clearBtn?.addEventListener('click', () => {
      if (confirm('Clear all data?')) {
        this.store.emit('ui:clear', {});
      }
    });

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        const tabId = btn.dataset.tab;
        const content = document.getElementById(`tab-${tabId}`);
        if (content) content.classList.add('active');
      });
    });

    // Store events
    this.store.subscribe('endpoint:added', () => this.updateStats());
    this.store.subscribe('secret:added', () => this.updateStats());
    this.store.subscribe('graphql:added', () => this.updateStats());
    this.store.subscribe('websocket:added', () => this.updateStats());
    this.store.subscribe('vulnerability:added', () => this.updateStats());
    this.store.subscribe('log:added', (log) => this.addLog(log));
    this.store.subscribe('scan:complete', () => {
      scanBtn.style.display = 'inline-block';
      stopBtn.style.display = 'none';
      this.updateStats();
      this.updateAllTables();
    });

    // Update UI periodically
    setInterval(() => {
      this.updateStats();
      this.updateAllTables();
    }, CONFIG.UI_UPDATE_INTERVAL);
  }

  updateStats() {
    const stats = this.store.getStats();
    document.getElementById('stat-endpoints')?.textContent = stats.totalEndpoints;
    document.getElementById('stat-secrets')?.textContent = stats.secrets;
    document.getElementById('stat-graphql')?.textContent = stats.graphql;
    document.getElementById('stat-websockets')?.textContent = stats.websockets;
    document.getElementById('stat-vulns')?.textContent = stats.vulnerabilities;
    document.getElementById('stat-requests')?.textContent = stats.totalRequests;
  }

  updateAllTables() {
    this.updateEndpointsTable();
    this.updateSecretsTable();
    this.updateGraphQLTable();
    this.updateWebSocketsTable();
    this.updateVulnerabilitiesTable();
  }

  updateEndpointsTable() {
    const tbody = document.getElementById('endpoints-table-body');
    if (!tbody) return;
    const endpoints = this.store.getEndpoints().slice(-100);
    tbody.innerHTML = endpoints.map(e => `
      <tr>
        <td>${Utils.escapeHTML(e.url)}</td>
        <td class="status-${e.status}">${e.status || 'pending'}</td>
        <td>${e.statusCode || '-'}</td>
        <td>${e.contentType || '-'}</td>
        <td>${e.lastChecked ? Utils.formatTimestamp(e.lastChecked) : '-'}</td>
      </tr>
    `).join('');
  }

  updateSecretsTable() {
    const tbody = document.getElementById('secrets-table-body');
    if (!tbody) return;
    const secrets = this.store.getSecrets().slice(-50);
    tbody.innerHTML = secrets.map(s => `
      <tr>
        <td>${s.type}</td>
        <td><code>${Utils.escapeHTML(s.value.substring(0, 50))}${s.value.length > 50 ? '...' : ''}</code></td>
        <td>${Utils.escapeHTML(s.location || 'unknown')}</td>
        <td>${s.entropy ? s.entropy.toFixed(2) : '-'}</td>
        <td>${Utils.formatTimestamp(s.timestamp)}</td>
      </tr>
    `).join('');
  }

  updateGraphQLTable() {
    const tbody = document.getElementById('graphql-table-body');
    if (!tbody) return;
    const graphql = this.store.getGraphQL().slice(-50);
    tbody.innerHTML = graphql.map(g => `
      <tr>
        <td>${Utils.escapeHTML(g.url)}</td>
        <td>${g.introspection ? '✅' : '❌'}</td>
        <td>${g.methods ? g.methods.join(', ') : '-'}</td>
        <td>${Utils.formatTimestamp(g.timestamp)}</td>
      </tr>
    `).join('');
  }

  updateWebSocketsTable() {
    const tbody = document.getElementById('websockets-table-body');
    if (!tbody) return;
    const ws = this.store.getWebSockets().slice(-50);
    tbody.innerHTML = ws.map(w => `
      <tr>
        <td>${Utils.escapeHTML(w.url)}</td>
        <td>${w.status || 'unknown'}</td>
        <td>${w.protocols ? w.protocols.join(', ') : '-'}</td>
        <td>${Utils.formatTimestamp(w.timestamp)}</td>
      </tr>
    `).join('');
  }

  updateVulnerabilitiesTable() {
    const tbody = document.getElementById('vulnerabilities-table-body');
    if (!tbody) return;
    const vulns = this.store.getVulnerabilities().slice(-50);
    tbody.innerHTML = vulns.map(v => `
      <tr>
        <td>${v.type}</td>
        <td>${Utils.escapeHTML(v.location)}</td>
        <td class="severity-${v.severity}">${v.severity}</td>
        <td>${v.description}</td>
        <td>${Utils.formatTimestamp(v.timestamp)}</td>
      </tr>
    `).join('');
  }

  addLog(log) {
    const container = document.getElementById('logs-container');
    if (!container) return;
    const entry = document.createElement('div');
    entry.className = `log-entry ${log.level}`;
    entry.textContent = `[${Utils.formatTimestamp(log.timestamp)}] ${log.message}`;
    container.prepend(entry);
    if (container.children.length > CONFIG.MAX_LOG_ENTRIES) {
      container.removeChild(container.lastChild);
    }
  }

  setScanning(isScanning) {
    const scanBtn = document.getElementById('recon-scan-btn');
    const stopBtn = document.getElementById('recon-stop-btn');
    if (scanBtn) scanBtn.style.display = isScanning ? 'none' : 'inline-block';
    if (stopBtn) stopBtn.style.display = isScanning ? 'inline-block' : 'none';
  }

  showNotification(message, type = 'info') {
    const container = this.container;
    if (!container) return;
    const notification = document.createElement('div');
    notification.className = `recon-notification recon-notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed; top: 20px; right: 20px; padding: 12px 20px;
      background: ${type === 'error' ? '#e74c3c' : type === 'success' ? '#2ecc71' : '#3498db'};
      color: white; border-radius: 4px; z-index: 1000;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      animation: slideIn 0.3s ease-out;
    `;
    container.appendChild(notification);
    setTimeout(() => {
      notification.style.opacity = '0';
      notification.style.transition = 'opacity 0.3s';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
}

// ============================================================
// PART 6: BOOKMARK MANAGER
// ============================================================

class BookmarkManager {
  constructor(store) {
    this.store = store;
    this.bookmarks = new Map();
    this.loadBookmarks();
  }

  addBookmark(name, data) {
    const id = Utils.generateId();
    this.bookmarks.set(id, {
      id,
      name,
      data,
      createdAt: Date.now(),
    });
    this.saveBookmarks();
    this.store.emit('bookmark:added', { id, name });
    return id;
  }

  getBookmark(id) {
    return this.bookmarks.get(id);
  }

  getAllBookmarks() {
    return Array.from(this.bookmarks.values());
  }

  removeBookmark(id) {
    if (this.bookmarks.delete(id)) {
      this.saveBookmarks();
      this.store.emit('bookmark:removed', { id });
      return true;
    }
    return false;
  }

  saveBookmarks() {
    try {
      const serialized = Array.from(this.bookmarks.entries());
      localStorage.setItem(CONFIG.STORAGE_KEYS.BOOKMARKS, JSON.stringify(serialized));
    } catch (e) {
      console.warn('Failed to save bookmarks:', e);
    }
  }

  loadBookmarks() {
    try {
      const raw = localStorage.getItem(CONFIG.STORAGE_KEYS.BOOKMARKS);
      if (raw) {
        const entries = JSON.parse(raw);
        this.bookmarks = new Map(entries);
      }
    } catch (e) {
      console.warn('Failed to load bookmarks:', e);
    }
  }

  exportBookmarks() {
    return {
      bookmarks: this.getAllBookmarks(),
      exportedAt: Date.now(),
      version: CONFIG.VERSION,
    };
  }

  importBookmarks(data) {
    if (data.bookmarks) {
      data.bookmarks.forEach(b => {
        this.bookmarks.set(b.id, b);
      });
      this.saveBookmarks();
      this.store.emit('bookmark:imported', { count: data.bookmarks.length });
      return true;
    }
    return false;
  }
}

// ============================================================
// PART 6B: EXTERNAL SCRIPT SCANNER
// ============================================================

class ExternalScriptScanner {
  constructor(store) {
    this.store = store;
  }

  async scan(pageUrl) {
    this.store.addLog(`Scanning external scripts on: ${pageUrl}`, 'info');
    
    try {
      const response = await fetch(pageUrl, {
        headers: CONFIG.DEFAULT_HEADERS,
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const html = await response.text();
      const scripts = this.extractScripts(html, pageUrl);
      
      const results = [];
      for (const script of scripts) {
        const analysis = await this.analyzeScript(script);
        results.push(analysis);
      }
      
      this.store.addLog(`Found ${scripts.length} external scripts on ${pageUrl}`, 'info');
      return results;
    } catch (error) {
      this.store.addLog(`Failed to scan scripts on ${pageUrl}: ${error.message}`, 'error');
      return [];
    }
  }

  extractScripts(html, baseUrl) {
    const scripts = [];
    const scriptPattern = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    const integrityPattern = /integrity=["']([^"']+)["']/gi;
    const crossOriginPattern = /crossorigin=["']([^"']+)["']/gi;
    
    let match;
    while ((match = scriptPattern.exec(html)) !== null) {
      const src = match[1];
      const fullUrl = src.startsWith('http') ? src : new URL(src, baseUrl).href;
      
      // Check for integrity
      const integrityMatch = integrityPattern.exec(html);
      const crossOriginMatch = crossOriginPattern.exec(html);
      
      scripts.push({
        url: fullUrl,
        src: src,
        integrity: integrityMatch ? integrityMatch[1] : null,
        crossOrigin: crossOriginMatch ? crossOriginMatch[1] : null,
      });
    }
    
    return scripts;
  }

  async analyzeScript(script) {
    const analysis = {
      ...script,
      status: 'unknown',
      contentLength: 0,
      hasIntegrity: !!script.integrity,
      isSecure: false,
      isExternal: false,
      domain: null,
    };
    
    try {
      const url = new URL(script.url);
      analysis.domain = url.hostname;
      analysis.isExternal = url.hostname !== window.location.hostname;
      
      const response = await fetch(script.url, {
        headers: CONFIG.DEFAULT_HEADERS,
      });
      
      if (response.ok) {
        analysis.status = 'success';
        analysis.contentLength = parseInt(response.headers.get('content-length') || '0');
        analysis.isSecure = url.protocol === 'https:';
        analysis.statusCode = response.status;
        
        // Check for potential vulnerabilities in script
        const content = await response.text();
        analysis.hasDangerousFunctions = this.checkDangerousFunctions(content);
        analysis.hasSensitiveData = Utils.looksLikeSecret(content);
        
        // Check integrity
        if (analysis.hasIntegrity) {
          analysis.integrityValid = await this.verifyIntegrity(content, script.integrity);
        }
      }
    } catch (error) {
      analysis.status = 'failed';
      analysis.error = error.message;
    }
    
    return analysis;
  }

  checkDangerousFunctions(content) {
    const dangerous = [
      /eval(/,
      /Function(/,
      /document.write(/,
      /innerHTMLs*=/,
      /outerHTMLs*=/,
      /setTimeouts*(/,
      /setIntervals*(/,
    ];
    return dangerous.some(pattern => pattern.test(content));
  }

  async verifyIntegrity(content, integrity) {
    // Simple integrity verification (would use crypto.subtle in browser)
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-384', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      const expectedHash = integrity.replace(/^sha384-/, '');
      return hashHex === expectedHash;
    } catch {
      return false;
    }
  }

  getSummary(results) {
    const total = results.length;
    const secure = results.filter(r => r.isSecure).length;
    const hasIntegrity = results.filter(r => r.hasIntegrity).length;
    const external = results.filter(r => r.isExternal).length;
    const dangerous = results.filter(r => r.hasDangerousFunctions).length;
    const failed = results.filter(r => r.status === 'failed').length;
    
    return {
      total,
      secure,
      hasIntegrity,
      external,
      dangerous,
      failed,
      successRate: total > 0 ? ((total - failed) / total * 100).toFixed(1) : 0,
    };
  }
}

// ============================================================
// PART 6C: MAIN APPLICATION
// ============================================================

class ReconApp {
  constructor() {
    this.store = new DataStore();
    this.ui = new UIComponents(this.store);
    this.endpointScanner = new EndpointScanner(this.store);
    this.secretScanner = new SecretScanner(this.store);
    this.graphqlScanner = new GraphQLScanner(this.store);
    this.wsScanner = new WebSocketScanner(this.store);
    this.bookmarkManager = new BookmarkManager(this.store);
    this.scriptScanner = new ExternalScriptScanner(this.store);
    
    this.setupEventListeners();
    this.init();
  }

  init() {
    this.store.addLog('🚀 Recon Scanner initialized', 'info');
    this.store.addLog(`Version: ${CONFIG.VERSION}`, 'info');
    
    // Initialize UI
    this.ui.init();
    
    // Load saved state
    const savedState = this.loadState();
    if (savedState) {
      this.store.importData(savedState);
      this.store.addLog('Loaded saved state', 'info');
    }
    
    this.ui.updateStats();
    this.ui.updateAllTables();
  }

  setupEventListeners() {
    // UI events
    this.store.subscribe('ui:scan-start', async ({ url }) => {
      await this.startScan(url);
    });
    
    this.store.subscribe('ui:scan-stop', () => {
      this.stopScan();
    });
    
    this.store.subscribe('ui:export', () => {
      this.exportData();
    });
    
    this.store.subscribe('ui:import', ({ data }) => {
      this.importData(data);
    });
    
    this.store.subscribe('ui:clear', () => {
      this.clearAll();
    });
  }

  async startScan(baseUrl) {
    if (!baseUrl) {
      this.store.addLog('No URL provided for scan', 'error');
      return;
    }
    
    this.ui.setScanning(true);
    this.store.addLog(`Starting full scan on: ${baseUrl}`, 'info');
    this.store.data.stats.startTime = Date.now();
    
    try {
      // Validate URL
      new URL(baseUrl);
    } catch {
      this.store.addLog('Invalid URL format', 'error');
      this.ui.setScanning(false);
      return;
    }
    
    try {
      // Phase 1: Endpoint discovery
      this.store.addLog('Phase 1: Discovering endpoints...', 'info');
      await this.endpointScanner.scan(baseUrl);
      
      // Phase 2: Secret scanning
      this.store.addLog('Phase 2: Scanning for secrets...', 'info');
      const endpoints = this.store.getEndpoints();
      await this.secretScanner.scanAllEndpoints(endpoints);
      
      // Phase 3: GraphQL scanning
      this.store.addLog('Phase 3: Scanning GraphQL endpoints...', 'info');
      const graphqlEndpoints = this.store.getGraphQL();
      if (graphqlEndpoints.length > 0) {
        await this.graphqlScanner.scanAll(graphqlEndpoints);
      }
      
      // Phase 4: WebSocket scanning
      this.store.addLog('Phase 4: Scanning WebSocket endpoints...', 'info');
      const wsEndpoints = this.store.getWebSockets();
      if (wsEndpoints.length > 0) {
        await this.wsScanner.scanAll(wsEndpoints.map(w => w.url));
      }
      
      // Phase 5: External script scanning
      this.store.addLog('Phase 5: Scanning external scripts...', 'info');
      await this.scriptScanner.scan(baseUrl);
      
      this.store.data.stats.endTime = Date.now();
      this.store.addLog('✅ Full scan completed successfully!', 'success');
      this.store.emit('scan:complete', this.store.getStats());
      
    } catch (error) {
      this.store.addLog(`Scan failed: ${error.message}`, 'error');
      console.error('Scan error:', error);
    }
    
    this.ui.setScanning(false);
  }

  stopScan() {
    this.endpointScanner.stop();
    this.secretScanner.stop();
    this.graphqlScanner.stop();
    this.wsScanner.stop();
    this.store.addLog('⏹️ Scan stopped by user', 'warning');
    this.ui.setScanning(false);
  }

  exportData() {
    const data = this.store.exportData();
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon_export_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    this.store.addLog('📤 Data exported successfully', 'success');
  }

  importData(data) {
    try {
      this.store.importData(data);
      this.store.addLog('📥 Data imported successfully', 'success');
      this.ui.updateStats();
      this.ui.updateAllTables();
    } catch (error) {
      this.store.addLog(`Import failed: ${error.message}`, 'error');
    }
  }

  clearAll() {
    this.store.clear();
    this.ui.updateStats();
    this.ui.updateAllTables();
    this.ui.showNotification('All data cleared', 'info');
    this.store.addLog('🗑️ All data cleared', 'info');
  }

  loadState() {
    try {
      const saved = localStorage.getItem(CONFIG.STORAGE_KEYS.SAVED_RESULTS);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.warn('Failed to load state:', e);
    }
    return null;
  }

  getVersion() {
    return CONFIG.VERSION;
  }
}

// ============================================================
// BOOTSTRAP
// ============================================================

// Auto-initialize when DOM is ready
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      window.recon = new ReconApp();
    });
  } else {
    window.recon = new ReconApp();
  }
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ReconApp,
    CONFIG,
    Utils,
    Patterns,
  };
}
