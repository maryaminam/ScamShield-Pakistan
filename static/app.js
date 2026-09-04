(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => root.querySelectorAll(selector);
  const esc = (value) => String(value ?? '—').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
  const levelClass = (level = 'Low') => ({ Critical: 'bg-red-500/15 text-red-300 ring-red-500/30', High: 'bg-orange-500/15 text-orange-300 ring-orange-500/30', Medium: 'bg-yellow-400/15 text-yellow-200 ring-yellow-400/30', Low: 'bg-green-500/15 text-green-300 ring-green-500/30', Safe: 'bg-green-500/15 text-green-300 ring-green-500/30' })[level] || 'bg-slate-700 text-slate-200 ring-slate-600';
  const scoreColor = score => score >= 75 ? 'var(--sev-critical, #ef4444)' : score >= 50 ? 'var(--sev-high, #f97316)' : score >= 25 ? 'var(--sev-medium, #facc15)' : 'var(--sev-low, #22c55e)';
  const clampScore = score => Math.min(Math.max(Number(score) || 0, 0), 100);
  const badge = level => `<span class="inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${levelClass(level)}">${esc(level)}</span>`;
  const card = (title, value, accent) => `<div class="rounded-2xl border border-slate-800 bg-panel p-5 shadow-xl shadow-black/10"><p class="text-sm text-slate-400">${esc(title)}</p><p class="mt-2 text-3xl font-semibold ${accent}">${esc(value)}</p></div>`;
  const empty = text => `<p class="rounded-lg border border-dashed border-slate-700 p-5 text-sm text-slate-400">${esc(text)}</p>`;
  const value = item => item === null || item === undefined || item === '' ? '—' : item;
  const status = state => { const normalized = String(state || 'not present').toLowerCase(); return normalized === 'pass' ? 'text-green-300' : /fail|softfail|suspicious/.test(normalized) ? 'text-red-300' : 'text-yellow-200'; };

  /* ── Technical term glossary ────────────────────────────────── */
  const GLOSSARY = {
    'SPF': 'Sender Policy Framework — a DNS record listing which IP addresses are authorized to send email for a domain. A "fail" means the sender is not on that list.',
    'DKIM': 'DomainKeys Identified Mail — a cryptographic signature that proves the message was not altered in transit and genuinely came from the claimed domain.',
    'DMARC': 'Domain-based Message Authentication, Reporting, and Conformance — a policy that tells receivers what to do when SPF or DKIM checks fail.',
    'CompAuth': 'Composite Authentication — Microsoft\'s combined check that the visible From address aligns with the authenticated sending domain. A failure suggests spoofing.',
    'Homograph': 'A domain that visually mimics a legitimate one using lookalike Unicode characters (e.g., replacing Latin "a" with Cyrillic "а").',
    'IOC': 'Indicator of Compromise — a technical artifact (IP, domain, hash) that suggests malicious activity.',
    'WHOIS': 'A protocol for querying domain registration data to discover the registrar, creation date, and owner of a domain.',
    'AbuseIPDB': 'A community-driven database that tracks IP addresses reported for malicious behaviour such as brute-force attacks or spam.',
    'VirusTotal': 'A service by Google that scans URLs and domains against 70+ antivirus engines and security blocklists.',
    'Reply-To': 'An email header that redirects replies to a different address than the sender, often abused to route victims to a scammer.',
    'Return-Path': 'The envelope-level address where bounce messages go. If it diverges from From, the sender may be spoofing identity.',
    'Received': 'A hop-by-hop trace added by each mail server. Analyzing the chain reveals the true origin and any relay anomalies.',
    'X-Headers': 'Non-standard email headers (X-Mailer, X-Spam-Status) that can reveal the sending software or spam-filter decisions.',
    'Softfail': 'A tentative SPF failure — the sender is not explicitly authorized but not explicitly denied either.',
    'Phishing': 'A social-engineering attack that impersonates a trusted entity to steal credentials, money, or sensitive data.',
    'Spoofing': 'Falsifying email headers or display names to make a message appear to come from a trusted source.',
    'ML classification': 'A zero-shot neural text classifier (DeBERTa) running locally to detect urgency, credential theft, and social manipulation beyond regex patterns.',
  };

  /** Generate an inline "?" tooltip span for a technical term. */
  function tt(term, definition) {
    return `<span class="tt-trigger" tabindex="0" aria-label="${esc(definition)}"><span class="tt-icon" aria-hidden="true">?</span><span class="tt-bubble" role="tooltip">${esc(definition)}</span></span>`;
  }

  /** Wrap known technical terms in rendered HTML with tooltip spans. */
  function injectTooltips(html) {
    const safeTerms = Object.keys(GLOSSARY).map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).sort((a, b) => b.length - a.length);
    const pattern = new RegExp(`\\b(${safeTerms.join('|')})\\b`, 'g');
    return html.replace(pattern, (match) => {
      const def = GLOSSARY[match];
      return def ? `${match}${tt(match, def)}` : match;
    });
  }

  /* ── Concern categorisation (client-side, no backend change) ── */
  function categorizeConcern(text) {
    const t = (text || '').toLowerCase();
    if (/^no\b|none\b|not detected\b|no suspicious\b|no malicious\b/.test(t)) return { severity: 'low', label: 'Safe finding' };
    if (/spoof|impersonat|display.*name|from.*mismatch|sender.*ident/.test(t)) return { severity: 'critical', label: 'Spoofing' };
    if (/dkim|spf|dmarc|auth/.test(t)) return { severity: 'high', label: 'Authentication' };
    if (/url|link|href|mismatch.*url|click|phishing.*link|malicious.*link/.test(t)) return { severity: 'critical', label: 'Malicious links' };
    if (/urgent|urgency|threat|demand|immediate|suspend|account.*lock/.test(t)) return { severity: 'medium', label: 'Urgent language' };
    if (/credential|password|login|verify.*account|personal.*info|ssn/.test(t)) return { severity: 'medium', label: 'Credential request' };
    if (/brand|paypal|amazon|microsoft|google|apple|bank/.test(t)) return { severity: 'high', label: 'Brand impersonation' };
    if (/attach|exe|zip|macro|script/.test(t)) return { severity: 'high', label: 'Suspicious file' };
    if (/domain|young|recent.*regist|whois/.test(t)) return { severity: 'medium', label: 'Domain reputation' };
    if (/reply.*to|return.*path|header/.test(t)) return { severity: 'high', label: 'Header anomaly' };
    if (/ip|abuse|blocklist/.test(t)) return { severity: 'medium', label: 'IP reputation' };
    return { severity: 'medium', label: 'Finding' };
  }

  /* ── Tab icon SVGs (15×15 stroke icons) ───────────────────── */
  const TAB_ICONS = {
    overview: '<svg class="tab-icon" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
    ai: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M9.8 15.9 9 18.75l-.81-2.85a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.85-.81a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.81 2.85a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.85.81a4.5 4.5 0 0 0-3.09 3.09Z"/><path d="M18.26 8.72 18 9.75l-.26-1.03a3.38 3.38 0 0 0-2.45-2.46L14.25 6l1.04-.26a3.38 3.38 0 0 0 2.45-2.46L18 2.25l.26 1.03a3.38 3.38 0 0 0 2.45 2.46L21.75 6l-1.04.26a3.38 3.38 0 0 0-2.45 2.46Z"/></svg>',
    auth: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    spoofing: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M20 12c0 1.66-2.24 3.39-5 4.15V18a3 3 0 0 1-6 0v-1.85c-2.76-.76-5-2.49-5-4.15"/><circle cx="9" cy="10" r=".75"/><circle cx="15" cy="10" r=".75"/><path d="M12 2a8 8 0 0 0-8 8c0 1.5.5 3 1.5 4.2"/></svg>',
    headers: '<svg class="tab-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    urls: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.1-.1l-2 2a5 5 0 0 0 7.1 7.1l1.1-1.1"/></svg>',
    attachments: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>',
    domain: '<svg class="tab-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    patterns: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    iocs: '<svg class="tab-icon" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
    report: '<svg class="tab-icon" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>'
  };

  /* ── Verdict text helper ─────────────────────────────────── */
  function verdictText(level) {
    return ({ Critical: 'This is almost certainly a phishing attempt', High: 'This email shows strong phishing indicators', Medium: 'This email has some suspicious characteristics', Low: 'This email appears legitimate' })[level] || 'Analysis complete';
  }

  /* ── Severity CSS class helper ───────────────────────────── */
  function severityClass(level) {
    return ({ Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' })[level] || 'low';
  }

  /* ── AI Explanation cache & helpers ──────────────────────── */
  let _aiEmailCache = null;   // cached per last email analysis
  let _aiUrlCache = null;     // cached per last url analysis

  function providerLabel(provider) {
    if (provider === 'groq') return `<span class="inline-flex items-center gap-1.5 rounded-full bg-sky-500/10 px-2.5 py-1 text-xs font-semibold text-sky-300 ring-1 ring-sky-500/30"><svg class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>AI-generated explanation · Groq</span>`;
    if (provider === 'gemini') return `<span class="inline-flex items-center gap-1.5 rounded-full bg-sky-500/10 px-2.5 py-1 text-xs font-semibold text-sky-300 ring-1 ring-sky-500/30"><svg class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>AI-generated explanation · Gemini</span>`;
    return `<span class="inline-flex items-center gap-1.5 rounded-full bg-yellow-400/15 px-2.5 py-1 text-xs font-semibold text-yellow-200 ring-1 ring-yellow-400/30"><svg class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>Automated summary (AI unavailable)</span>`;
  }

  function renderAiContent(ai, riskLevel) {
    const isSafe = riskLevel === 'Low';
    const concernIcons = isSafe ? [
      '<svg class="ai-concern-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z" clip-rule="evenodd"/></svg>',
      '<svg class="ai-concern-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z" clip-rule="evenodd"/></svg>'
    ] : [
      '<svg class="ai-concern-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.168 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 6zm0 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" clip-rule="evenodd"/></svg>',
      '<svg class="ai-concern-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0zm-7-4a1 1 0 1 1-2 0 1 1 0 0 1 2 0zM9 9a.75.75 0 0 0 0 1.5h.25a.25.25 0 0 1 .25.25v1.5a.25.25 0 0 1-.25.25H9a.75.75 0 0 0 0 1.5h2a.75.75 0 0 0 0-1.5h-.25a.25.25 0 0 1-.25-.25v-2.5A.75.75 0 0 0 9.75 9H9z" clip-rule="evenodd"/></svg>',
    ];

    /* ── Render concern chips (scan-first format) ────────────── */
    const concernChips = (ai.key_concerns || []).map((c, i) => {
      const cat = categorizeConcern(c);
      return `<span class="concern-chip concern-chip--${cat.severity}" style="animation-delay:${.08 + i * .06}s" onclick="this.classList.toggle('expanded')">
        <span class="concern-chip-dot"></span>
        <span class="concern-chip-label">${esc(cat.label)}</span>
        <span class="concern-chip-detail">${esc(c)}</span>
      </span>`;
    }).join('');

    const actions = (ai.recommended_actions || []).map((a, i) => {
      return `<div class="ai-action-step" style="animation-delay:${0.2 + i * 0.08}s">
        <div class="ai-action-number">${i + 1}</div>
        <p>${esc(a)}</p>
      </div>`;
    }).join('');
    return `<div class="ai-explanation-container">

      <div class="ai-provider-row">${providerLabel(ai.provider)}</div>

      <div class="ai-summary-hero" style="animation-delay:.05s">
        <div class="ai-hero-header">
          <svg class="ai-hero-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09ZM18.259 8.715 18 9.75l-.259-1.035a3.375 3.375 0 0 0-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 0 0 2.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 0 0 2.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 0 0-2.455 2.456ZM16.894 20.567 16.5 21.75l-.394-1.183a2.25 2.25 0 0 0-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 0 0 1.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 0 0 1.423 1.423l1.183.394-1.183.394a2.25 2.25 0 0 0-1.423 1.423Z"/></svg>
          <h3>Summary</h3>
        </div>
        <p class="ai-hero-text">${esc(ai.plain_summary)}</p>
      </div>

      <div class="ai-concerns-section" style="animation-delay:.1s">
        <div class="ai-section-header">
          ${isSafe
        ? `<svg class="ai-section-icon ai-section-icon--safe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/></svg>`
        : `<svg class="ai-section-icon ai-section-icon--warn" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/></svg>`
      }
          <h3>${isSafe ? 'Analysis highlights' : 'Key concerns'}</h3>
          ${ai.key_concerns?.length ? `<span class="ai-concern-count ${isSafe ? 'ai-concern-count--safe' : ''}">${ai.key_concerns.length}</span>` : ''}
        </div>
        ${concernChips ? `<div class="concern-chips">${concernChips}</div>` : '<p class="ai-empty-note">No specific findings identified.</p>'}
      </div>

      <div class="ai-meaning-panel" style="animation-delay:.16s">
        <div class="ai-meaning-glow"></div>
        <div class="ai-meaning-content">
          <div class="ai-section-header">
            <svg class="ai-section-icon ai-section-icon--info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 18v-5.25m0 0a6.01 6.01 0 0 0 1.5-.189m-1.5.189a6.01 6.01 0 0 1-1.5-.189m3.75 7.478a12.06 12.06 0 0 1-4.5 0m3.75 2.383a14.406 14.406 0 0 1-3 0M14.25 18v-.192c0-.983.658-1.823 1.508-2.316a7.5 7.5 0 1 0-7.517 0c.85.493 1.509 1.333 1.509 2.316V18"/></svg>
            <h3>What this means</h3>
          </div>
          <p>${esc(ai.what_this_means)}</p>
        </div>
      </div>

      <div class="ai-actions-section" style="animation-delay:.22s">
        <div class="ai-section-header">
          <svg class="ai-section-icon ai-section-icon--action" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/></svg>
          <h3>Recommended actions</h3>
        </div>
        <div class="ai-actions-track">
          ${actions}
        </div>
      </div>

    </div>`;
  }

  function aiLoadingState() {
    return `<div class="grid place-items-center gap-4 rounded-2xl border border-slate-800 bg-panel p-10 shadow-xl shadow-black/10"><div class="skeleton-ring"></div><p class="text-sm font-medium text-slate-400">Generating AI explanation…</p><p class="text-xs text-slate-500">This may take a few seconds.</p></div>`;
  }

  async function fetchAiExplanation(analysisData, source) {
    try {
      const body = { analysis: analysisData, source };
      const res = await fetch('/api/explain', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error('AI explanation request failed');
      return await res.json();
    } catch (err) {
      return { plain_summary: 'Unable to generate AI explanation at this time.', key_concerns: [], what_this_means: 'The AI explanation service is temporarily unavailable. All forensic analysis tabs above remain fully functional.', recommended_actions: ['Review the other analysis tabs for detailed findings.'], provider: 'fallback' };
    }
  }

  function gauge(score, level) {
    const clamped = clampScore(score);
    const radius = 62, circumference = 2 * Math.PI * radius, offset = circumference * (1 - clamped / 100);
    const sev = severityClass(level);
    return `<div class="hero-gauge-wrap">
      <div class="hero-gauge-glow hero-gauge-glow--${sev}" data-glow></div>
      <svg viewBox="0 0 148 148" class="hero-gauge-svg" style="width:192px;height:192px" class="-rotate-90">
        <defs><linearGradient id="gg" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="${scoreColor(clamped)}" stop-opacity=".45"/><stop offset="100%" stop-color="${scoreColor(clamped)}"/></linearGradient></defs>
        <circle cx="74" cy="74" r="${radius}" fill="none" stroke-width="9" transform="rotate(-90 74 74)"/>
        <circle class="gauge-progress" data-gauge="${offset}" cx="74" cy="74" r="${radius}" fill="none" stroke="url(#gg)" stroke-width="9" stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference}" transform="rotate(-90 74 74)"/>
      </svg>
      <div style="position:absolute;inset:0;display:grid;place-items:center;text-align:center">
        <div><strong class="hero-score-num" style="color:${scoreColor(clamped)}">${esc(clamped)}</strong><span class="hero-score-max">/ 100</span></div>
      </div>
    </div>`;
  }

  function animateGauges(root) {
    requestAnimationFrame(() => {
      root.querySelectorAll('[data-gauge]').forEach(el => { el.style.strokeDashoffset = el.dataset.gauge; });
      root.querySelectorAll('[data-glow]').forEach(el => { el.classList.add('active'); });
    });
  }

  async function jsonFetch(url, options = {}) {
    const response = await fetch(url, options);
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  async function loadDashboard() {
    try {
      const data = await jsonFetch('/api/dashboard-stats');
      $('#stat-cards').innerHTML = [
        card('Total Analyses', data.total_analyses, 'text-sky-300'),
        card('High Risk', (data.by_threat_level.High || 0) + (data.by_threat_level.Critical || 0), 'text-orange-300'),
        card('Medium Risk', data.by_threat_level.Medium || 0, 'text-yellow-200'),
        card('Safe / Low', data.by_threat_level.Low || 0, 'text-green-300'),
      ].join('');
      $('#activity-table').innerHTML = data.recent_activity.length ? data.recent_activity.map(row => `<tr class="text-slate-300"><td class="px-3 py-3 text-slate-400">${esc(new Date(row.timestamp).toLocaleString())}</td><td class="px-3 py-3 capitalize">${esc(row.type)}</td><td class="max-w-xs truncate px-3 py-3 font-mono text-xs">${esc(row.target)}</td><td class="px-3 py-3">${esc(clampScore(row.risk_score))}</td><td class="px-3 py-3">${badge(row.threat_level)}</td></tr>`).join('') : `<tr><td colspan="5" class="px-3 py-8 text-center text-slate-500">No analyses yet. Start with an email or URL scan.</td></tr>`;
    } catch (error) { $('#activity-table').innerHTML = `<tr><td colspan="5" class="px-3 py-6 text-red-300">${esc(error.message)}</td></tr>`; }
  }

  function rows(items, cells, noItems = 'No findings.') {
    return items?.length ? items.map(item => `<tr class="border-b border-slate-800 last:border-0">${cells(item)}</tr>`).join('') : `<tr><td colspan="99" class="px-3 py-5 text-slate-500">${esc(noItems)}</td></tr>`;
  }
  function section(title, body, extra = '') { return `<div class="rounded-2xl border border-slate-800 bg-panel p-5 shadow-xl shadow-black/10 ${extra}"><h3 class="mb-4 font-semibold">${esc(title)}</h3>${injectTooltips(body)}</div>`; }
  function chips(items, hashMode = false) { return items?.length ? `<div class="flex flex-wrap gap-2">${items.map(item => { const content = hashMode ? `${item.filename}: ${item.sha256}` : item; return `<button data-copy="${esc(content)}" class="max-w-full truncate rounded-md bg-slate-800 px-2.5 py-1.5 font-mono text-xs text-slate-300 hover:bg-slate-700" title="Click to copy">${esc(content)}</button>`; }).join('')}</div>` : '<span class="text-sm text-slate-500">None found</span>'; }

  function emailTabContent(tab, data) {
    const risk = data.threat_intel.risk, dns = data.threat_intel.dns || {}, patterns = data.threat_intel.patterns || {};
    if (tab === 'overview') {
      const actions = _aiEmailCache?.recommended_actions || data.recommendations || ["View 'AI Summary' tab for detailed recommendations."];
      const sev = severityClass(risk.level);
      const spoofCount = (data.spoofing.findings || []).length;
      const urlMismatchCount = (data.urls || []).filter(u => u.mismatch).length;
      const riskyAttach = (data.attachments || []).filter(a => a.risky).length;
      return `<div class="grid gap-5 lg:grid-cols-[320px_1fr]">
        <div class="flex flex-col items-center justify-center gap-4 rounded-2xl p-6" style="background:var(--surface-soft);border:1px solid var(--line)">
          ${gauge(risk.score, risk.level)}
          <div class="text-center">${badge(risk.level)}</div>
        </div>
        <div class="space-y-5">
          <div class="rounded-2xl p-5" style="background:var(--surface-solid);border:1px solid var(--line);box-shadow:var(--shadow)">
            <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:1rem">
              <svg class="result-section-icon" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              <h3 style="font-size:1rem;font-weight:700;letter-spacing:-.02em;margin:0">Recommended response</h3>
            </div>
            <ul style="list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:.65rem">
              ${actions.map(item => `<li style="display:flex;align-items:flex-start;gap:.6rem;font-size:.9rem;color:var(--text);line-height:1.5"><span style="color:var(--accent);font-weight:700;flex-shrink:0;margin-top:1px">›</span>${esc(item)}</li>`).join('')}
            </ul>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem">
            <div class="quick-stat-card">
              <span class="quick-stat-label"><svg class="quick-stat-icon" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>Sender</span>
              <span class="quick-stat-value" style="font-family:var(--font-mono,monospace);font-size:.82rem;word-break:break-all">${esc(data.spoofing.from_address || '—')}</span>
            </div>
            <div class="quick-stat-card">
              <span class="quick-stat-label"><svg class="quick-stat-icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Auth status</span>
              <span class="quick-stat-value"><span style="color:${data.auth.spf === 'pass' ? 'var(--sev-low)' : 'var(--sev-critical)'}">SPF ${esc(data.auth.spf || '—')}</span> · <span style="color:${data.auth.dkim === 'pass' ? 'var(--sev-low)' : 'var(--sev-critical)'}">DKIM ${esc(data.auth.dkim || '—')}</span></span>
            </div>
            <div class="quick-stat-card">
              <span class="quick-stat-label"><svg class="quick-stat-icon" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Findings</span>
              <span class="quick-stat-value">${esc(spoofCount)} spoofing · ${esc(urlMismatchCount)} URL mismatch${riskyAttach ? ` · ${esc(riskyAttach)} risky file` : ''}</span>
            </div>
            <div class="quick-stat-card">
              <span class="quick-stat-label"><svg class="quick-stat-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>Domain</span>
              <span class="quick-stat-value" style="font-size:.85rem">${esc(data.domain_rep.domain || '—')} ${data.domain_rep.is_young ? '<span style="color:var(--sev-high);font-size:.75rem;font-weight:600"> (young)</span>' : ''}</span>
            </div>
          </div>
        </div>
      </div>`;
    }
    if (tab === 'auth') return `<div class="grid gap-5 xl:grid-cols-2">${section('Observed authentication', `<div class="grid gap-3 sm:grid-cols-3">${['spf', 'dkim', 'dmarc'].map(key => `<div class="rounded-xl bg-slate-900 p-4"><p class="text-xs uppercase text-slate-400">${key}</p><p class="mt-2 font-semibold ${status(data.auth[key])}">${esc(value(data.auth[key]))}</p></div>`).join('')}</div><p class="mt-4 text-sm ${data.auth.is_suspicious ? 'text-red-300' : 'text-green-300'}">${data.auth.is_suspicious ? 'Authentication signals are suspicious.' : 'No suspicious authentication result reported.'}</p>`)}${section('Published DNS records', `<div class="space-y-3">${['spf', 'dkim', 'dmarc'].map(key => `<div class="rounded-lg bg-slate-900 p-3"><div class="flex justify-between"><b class="uppercase">${key}</b>${dns[key]?.exists ? badge('Low') : badge('Medium')}</div><p class="mt-2 break-all font-mono text-xs text-slate-400">${esc(dns[key]?.record || 'No record found')}</p></div>`).join('')}</div>`)}</div>`;
    if (tab === 'spoofing') return `<div class="grid gap-5 xl:grid-cols-2">${section('Sender identity', `<dl class="space-y-3 text-sm"><div><dt class="text-slate-400">Display name</dt><dd>${esc(data.spoofing.from_display)}</dd></div><div><dt class="text-slate-400">Actual sender</dt><dd class="font-mono">${esc(data.spoofing.from_address)}</dd></div><div><dt class="text-slate-400">Reply-To</dt><dd class="font-mono">${esc(data.spoofing.reply_to)}</dd></div><div><dt class="text-slate-400">Return-Path</dt><dd class="font-mono">${esc(data.spoofing.return_path)}</dd></div></dl>`)}${section('Spoofing findings', `<div class="space-y-3">${data.spoofing.findings?.length ? data.spoofing.findings.map(f => `<div class="rounded-lg bg-slate-900 p-3"><div class="flex items-center justify-between gap-3"><b>${esc(f.type)}</b>${badge(String(f.severity || 'low').replace(/^./, c => c.toUpperCase()))}</div><p class="mt-2 text-sm text-slate-300">${esc(f.message)}</p></div>`).join('') : empty('No sender identity anomalies found.')}</div>`)}</div>`;
    if (tab === 'headers') return `<div class="space-y-5">${section('Header anomalies', data.header_analysis?.anomalies?.length ? `<ul class="space-y-2 text-sm text-slate-300">${data.header_analysis.anomalies.map(a => `<li>• ${esc(typeof a === 'string' ? a : JSON.stringify(a))}</li>`).join('')}</ul>` : empty('No header anomalies found.'))}${section('Routing path', `<div class="scrollbar overflow-x-auto"><table class="w-full min-w-[620px] text-left text-sm"><thead class="text-xs uppercase text-slate-400"><tr><th class="p-2">Hop</th><th class="p-2">From</th><th class="p-2">By</th><th class="p-2">IP</th><th class="p-2">Timestamp</th></tr></thead><tbody>${rows(data.routing, hop => `<td class="p-2">${esc(hop.hop)}</td><td class="p-2">${esc(hop.from)}</td><td class="p-2">${esc(hop.by)}</td><td class="p-2 font-mono">${esc(hop.ip)}</td><td class="p-2">${esc(hop.timestamp)}</td>`, 'No Received headers found.')}</tbody></table></div>`)}${section('Timing & X-Headers', `<pre class="scrollbar max-h-72 overflow-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-300">${esc(JSON.stringify({ timestamps: data.header_analysis?.timestamps, x_headers: data.header_analysis?.x_headers }, null, 2))}</pre>`)}</div>`;
    if (tab === 'urls') return section('Extracted URLs & links', `<div class="scrollbar overflow-x-auto"><table class="w-full min-w-[700px] text-left text-sm"><thead class="text-xs uppercase text-slate-400"><tr><th class="p-2">URL</th><th class="p-2">Display Text</th><th class="p-2">Domain</th><th class="p-2">Mismatch</th></tr></thead><tbody>${rows(data.urls, u => `<td class="max-w-sm truncate p-2 font-mono text-xs ${u.mismatch ? 'text-red-300' : ''}">${esc(u.url)}</td><td class="p-2">${esc(u.display_text)}</td><td class="p-2">${esc(u.domain)}</td><td class="p-2">${u.mismatch ? badge('Critical') : badge('Low')}</td>`, 'No URLs found.')}</tbody></table></div>`);
    if (tab === 'attachments') return section('Attachments', `<div class="scrollbar overflow-x-auto"><table class="w-full min-w-[850px] text-left text-sm"><thead class="text-xs uppercase text-slate-400"><tr><th class="p-2">File</th><th class="p-2">Type / Size</th><th class="p-2">MD5</th><th class="p-2">SHA-256</th><th class="p-2">Risk</th></tr></thead><tbody>${rows(data.attachments, a => `<td class="p-2 ${a.risky ? 'text-red-300' : ''}">${esc(a.filename)}</td><td class="p-2">${esc(a.mime_type)}<br><span class="text-xs text-slate-400">${esc(a.size)} bytes</span></td><td class="p-2 font-mono text-xs">${esc(a.md5)}</td><td class="p-2 font-mono text-xs">${esc(a.sha256)}</td><td class="p-2">${a.risky ? badge('High') : badge('Low')}</td>`, 'No attachments found.')}</tbody></table></div>`);
    if (tab === 'domain') return `<div class="grid gap-5 lg:grid-cols-2">${section('Domain reputation', `<dl class="space-y-3 text-sm">${[['Domain', data.domain_rep.domain], ['Registrar', data.domain_rep.registrar], ['Creation date', data.domain_rep.creation_date], ['Domain age', data.domain_rep.domain_age_days == null ? null : `${data.domain_rep.domain_age_days} days`]].map(([k, v]) => `<div class="flex justify-between gap-5"><dt class="text-slate-400">${esc(k)}</dt><dd class="text-right">${esc(value(v))}</dd></div>`).join('')}<div class="flex justify-between"><dt class="text-slate-400">Recently registered</dt><dd>${data.domain_rep.is_young ? badge('High') : badge('Low')}</dd></div></dl>${data.domain_rep.error ? `<p class="mt-4 text-sm text-yellow-200">${esc(data.domain_rep.error)}</p>` : ''}`)}${section('Risk score rationale', `<div class="space-y-3">${Object.entries(risk.breakdown || {}).map(([signal, item]) => `<div class="rounded-lg bg-slate-900 p-3"><div class="flex justify-between"><b class="capitalize">${esc(signal.replaceAll('_', ' '))}</b><span class="text-sky-300">+${esc(item[0])}</span></div><p class="mt-1 text-xs text-slate-400">${esc(item[1])}</p></div>`).join('') || empty('No risk contributions.')}</div>`)}</div>`;
    if (tab === 'patterns') { const abuse = data.threat_intel.abuse || {}; return `<div class="grid gap-5 xl:grid-cols-2">${section('Phishing language', `<div class="space-y-4">${['urgency', 'credential', 'impersonation'].map(key => `<div><p class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">${key}</p>${chips(patterns[key])}</div>`).join('')}<p class="text-sm text-slate-400">Total flags: ${esc(patterns.total_flags || 0)}</p></div>`)}${section('Originating IP intelligence', abuse.error ? `<p class="text-sm text-yellow-200">${esc(abuse.error)}</p>` : `<dl class="space-y-3 text-sm">${[['IP', abuse.ip], ['Abuse score', abuse.abuse_score], ['Reports', abuse.total_reports], ['Country', abuse.country_code], ['ISP', abuse.isp]].map(([k, v]) => `<div class="flex justify-between gap-4"><dt class="text-slate-400">${k}</dt><dd class="font-mono text-right">${esc(value(v))}</dd></div>`).join('')}<div class="flex justify-between"><dt class="text-slate-400">Flagged</dt><dd>${abuse.is_flagged ? badge('High') : badge('Low')}</dd></div></dl>`)}</div>`; }
    if (tab === 'iocs') return section('Indicators of compromise', `<div class="grid gap-5 md:grid-cols-2">${[['IPs', data.iocs.ips], ['Domains', data.iocs.domains], ['URLs', data.iocs.urls], ['Emails', data.iocs.emails], ['Hashes', data.iocs.hashes, true]].map(([name, items, isHash]) => `<div><p class="mb-2 text-sm text-slate-400">${name}</p>${chips(items, isHash)}</div>`).join('')}</div><p class="mt-5 text-xs text-slate-500">Click an indicator to copy it.</p>`);
    const reasons = Object.values(risk.breakdown || {}).slice(0, 3).map(item => item[1]);
    return `<div class="grid gap-5 xl:grid-cols-2">${section('Executive summary', `<p class="text-sm leading-7 text-slate-300">This email was assessed as <b>${esc(risk.level)}</b> risk with a score of <b>${esc(clampScore(risk.score))}/100</b>. ${reasons.length ? `Primary signals: ${esc(reasons.join(' '))}` : 'No major risk signals were scored.'} Sender spoofing severity is <b>${esc(data.spoofing.severity || 'low')}</b>.</p>`)}${section('Forensic report', `<p class="mb-4 text-sm text-slate-400">Build a full standalone HTML report only when you need it for offline review or a case record.</p><button id="download-report" class="btn-primary">Export Report (.html)</button><p id="download-status" class="mt-3 text-sm text-red-300" aria-live="polite"></p>`)}</div>`;
  }

  function renderEmail(data) {
    const result = $('#email-results');
    const risk = data.threat_intel.risk;
    const sev = severityClass(risk.level);
    const tabs = [['overview', 'Overview'], ['ai', 'AI Summary'], ['auth', 'Authentication'], ['spoofing', 'Spoofing & Identity'], ['headers', 'Headers & Timing'], ['urls', 'URLs & Links'], ['attachments', 'Attachments'], ['domain', 'Domain Reputation'], ['patterns', 'Threat Patterns'], ['iocs', 'IOCs'], ['report', 'Report']];

    /* ── Hero Section ──────────────────────────────────────── */
    const heroHtml = `<div class="results-hero mb-6">
      <div class="hero-severity-wash hero-severity-wash--${sev}"></div>
      <div style="position:relative;z-index:1;display:flex;align-items:center;gap:3rem;flex-wrap:wrap">
        ${gauge(risk.score, risk.level)}
        <div style="flex:1;min-width:280px">
          <p style="font-size:.75rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sev-${sev});margin:0 0 .75rem">${esc(risk.level)} Risk</p>
          <p class="hero-verdict">${esc(verdictText(risk.level))}</p>
          <p class="hero-subject">Subject: ${esc(data.metadata.Subject || 'No subject supplied')}</p>
        </div>
      </div>
    </div>`;

    /* ── Tab bar with icons ────────────────────────────────── */
    const tabButtons = tabs.map(([id, label], index) => {
      const icon = TAB_ICONS[id] || '';
      return `<button data-email-tab="${id}" role="tab" aria-selected="${index === 0}" class="tab-button whitespace-nowrap px-4 py-3 text-sm ${index === 0 ? 'active' : ''}" style="display:inline-flex;align-items:center;gap:.4rem">${icon}${esc(label)}</button>`;
    }).join('');

    result.innerHTML = `${heroHtml}<div class="mb-2 xl:hidden"><span style="font-size:.7rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)">Scroll for more tabs &rarr;</span></div><div class="email-tabs mb-5 overflow-x-auto" role="tablist" aria-label="Email analysis sections">${tabButtons}</div><div id="email-tab-content"></div>`;
    animateGauges(result);
    const content = $('#email-tab-content');
    let currentTab = null;
    const showTab = tab => { currentTab = tab; content.classList.remove('tab-fade-in'); void content.offsetWidth; content.classList.add('tab-fade-in'); if (tab === 'ai') { if (_aiEmailCache) { content.innerHTML = renderAiContent(_aiEmailCache, data.threat_intel.risk.level); } else { content.innerHTML = aiLoadingState(); fetchAiExplanation(data, 'email').then(ai => { _aiEmailCache = ai; if (currentTab === 'ai') { content.innerHTML = renderAiContent(ai, data.threat_intel.risk.level); } }); } return; } content.innerHTML = emailTabContent(tab, data); animateGauges(content); content.querySelectorAll('[data-copy]').forEach(btn => btn.onclick = async () => { await navigator.clipboard?.writeText(btn.dataset.copy); btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = btn.dataset.copy; }, 900); }); if (tab === 'report') $('#download-report').onclick = async () => { const button = $('#download-report'); const label = button.textContent; button.disabled = true; button.textContent = 'Building report…'; try { const response = await fetch('/api/export-report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ report_id: data.report_id }) }); if (!response.ok) { const error = await response.json().catch(() => ({})); throw new Error(error.error || 'Report export failed.'); } const blob = await response.blob(), link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'scamshield-forensic-report.html'; link.click(); URL.revokeObjectURL(link.href); } catch (error) { $('#download-status').textContent = error.message; } finally { button.disabled = false; button.textContent = label; } }; };
    result.querySelectorAll('[data-email-tab]').forEach(button => button.onclick = () => { result.querySelectorAll('[data-email-tab]').forEach(b => { b.classList.toggle('active', b === button); b.setAttribute('aria-selected', String(b === button)); }); showTab(button.dataset.emailTab); });
    showTab('overview'); _aiEmailCache = null; result.classList.remove('hidden'); result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderUrl(data) {
    const dns = data.dns || {}, result = $('#url-results');
    const na = v => v == null ? '<span class="italic text-slate-500">Not available</span>' : esc(v);
    const domainAgeBadge = data.domain_info.is_young ? badge('High') : '<span class="inline-flex rounded-full bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-400">Not flagged</span>';
    const domainInfoList = [['Registrar', data.domain_info.registrar], ['Creation date', data.domain_info.creation_date], ['Domain age', data.domain_info.domain_age_days == null ? null : `${data.domain_info.domain_age_days} days`]].map(([k, v]) => `<div class="flex justify-between gap-4"><dt class="text-slate-400">${k}</dt><dd class="text-right">${na(v)}</dd></div>`).join('');
    const verdictCard = `<div class="mb-5 rounded-2xl border border-slate-800 bg-panel p-6 shadow-xl shadow-black/10"><div class="flex flex-col items-center gap-6 md:flex-row md:items-start lg:gap-10"><div class="flex shrink-0 flex-col items-center">${gauge(data.risk_score, data.threat_level)}<div class="mt-4">${badge(data.threat_level)}</div></div><div class="flex-1 space-y-5 pt-2 text-center md:text-left"><div><p class="text-xs font-semibold uppercase tracking-wide text-slate-400">Target URL</p><p class="mt-1 break-all font-mono text-sm text-slate-200">${esc(data.domain)}</p></div><div class="inline-block border-l-2 border-sky-500 pl-4 text-left"><p class="text-xs font-semibold uppercase tracking-wide text-sky-300">Recommendation</p><p class="mt-1 text-sm leading-relaxed text-slate-300">${esc(data.recommendation)}</p></div></div></div></div>`;
    const indicatorTags = data.indicators?.length ? `<div class="flex flex-wrap gap-2 pt-1">${data.indicators.map(i => `<span class="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300"><span class="h-1.5 w-1.5 rounded-full ${String(i.severity).toLowerCase() === 'high' ? 'bg-red-400' : String(i.severity).toLowerCase() === 'medium' ? 'bg-yellow-400' : 'bg-slate-400'}"></span>${esc(i.flag)}</span>`).join('')}</div>` : empty('No suspicious URL indicators found.');

    result.innerHTML = `${verdictCard}<div class="mb-5 grid gap-5 lg:grid-cols-2">${section('Domain information', `<dl class="space-y-4 text-sm">${domainInfoList}<div class="flex justify-between"><dt class="text-slate-400">Domain age risk</dt><dd>${domainAgeBadge}</dd></div></dl>`)}${section('Suspicious indicators', indicatorTags)}</div>`;
    animateGauges(result); result.classList.remove('hidden'); _aiUrlCache = null;
    /* ── AI Summary toggle for URL analysis ──────────────── */
    const aiToggle = document.createElement('div');
    aiToggle.className = 'mt-5 flex justify-center';
    aiToggle.innerHTML = `<button id="url-ai-toggle" class="flex items-center gap-2 rounded-xl border border-slate-700 bg-panel px-5 py-2.5 text-sm font-semibold text-slate-200 transition hover:bg-slate-800"><svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>Show AI Summary</button><div id="url-ai-content" class="mt-5 hidden w-full text-left"></div>`;
    result.appendChild(aiToggle);
    $('#url-ai-toggle').onclick = async () => {
      const box = $('#url-ai-content');
      if (!box.classList.contains('hidden')) { box.classList.add('hidden'); $('#url-ai-toggle').innerHTML = `<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>Show AI Summary`; return; }
      box.classList.remove('hidden');
      if (_aiUrlCache) { box.innerHTML = renderAiContent(_aiUrlCache, data.threat_level); $('#url-ai-toggle').innerHTML = `<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>Hide AI Summary`; } else { box.innerHTML = aiLoadingState(); $('#url-ai-toggle').innerHTML = `<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>Generating AI Summary…`; const ai = await fetchAiExplanation(data, 'url'); _aiUrlCache = ai; if (!box.classList.contains('hidden')) { box.innerHTML = renderAiContent(ai, data.threat_level); $('#url-ai-toggle').innerHTML = `<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 0 1 4 4v1a3 3 0 0 1 3 3v1a2 2 0 0 1-2 2h-1l-1 6H9l-1-6H7a2 2 0 0 1-2-2v-1a3 3 0 0 1 3-3V6a4 4 0 0 1 4-4z"/></svg>Hide AI Summary`; } }
    };
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function showAnalysisLoading(type) {
    const result = $(`#${type}-results`);
    const label = type === 'email' ? 'Inspecting email signals' : 'Inspecting link signals';
    const detail = type === 'email' ? 'Checking sender identity, headers, links, and attachments.' : 'Checking the destination, domain history, and DNS protections.';
    result.innerHTML = `<div class="analysis-skeleton" role="status" aria-live="polite" aria-label="${label}"><div class="skeleton-card" style="display:flex;align-items:center;gap:1.5rem"><div class="skeleton-ring" aria-hidden="true"></div><div style="flex:1;max-width:34rem"><div class="skeleton-line" style="width:9rem"></div><p style="margin:.9rem 0 .35rem;font-weight:650">${label}…</p><p class="skeleton-label" style="margin:0">${detail}</p></div></div><div id="analysis-progress-steps" class="analysis-progress-steps"></div><div style="display:grid;gap:1.25rem;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))"><div class="skeleton-card"><div class="skeleton-line" style="width:35%"></div><div class="skeleton-line" style="width:82%;margin-top:1.25rem"></div><div class="skeleton-line" style="width:63%;margin-top:.8rem"></div><div class="skeleton-line" style="width:74%;margin-top:.8rem"></div></div><div class="skeleton-card"><div class="skeleton-line" style="width:42%"></div><div class="skeleton-line" style="width:93%;margin-top:1.25rem"></div><div class="skeleton-line" style="width:76%;margin-top:.8rem"></div><div class="skeleton-line" style="width:57%;margin-top:.8rem"></div></div></div></div>`;
    result.classList.remove('hidden');
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function updateProgressUI(phase, label, detail) {
    const container = $('#analysis-progress-steps');
    if (!container) return;
    /* Mark previous steps as complete */
    container.querySelectorAll('.progress-step:not(.progress-step--done)').forEach(el => {
      el.classList.add('progress-step--done');
      el.querySelector('.progress-step-icon').innerHTML = '<svg viewBox="0 0 20 20" fill="currentColor" class="w-4 h-4"><path fill-rule="evenodd" d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z" clip-rule="evenodd"/></svg>';
    });
    const step = document.createElement('div');
    step.className = 'progress-step progress-step--active';
    step.innerHTML = `<span class="progress-step-icon"><span class="progress-spinner"></span></span><div><p class="progress-step-label">${esc(label)}</p><p class="progress-step-detail">${esc(detail)}</p></div>`;
    container.appendChild(step);
  }

  function showAnalysisError(type, message) {
    const result = $(`#${type}-results`);
    result.innerHTML = `<div class="analysis-error" role="alert"><strong>We couldn’t complete this scan.</strong><p style="margin:.35rem 0 0" class="text-sm">${esc(message)}</p></div>`;
    result.classList.remove('hidden');
  }

  function setLoading(form, statusElement, active, text) {
    const button = $('button', form);
    if (!button.dataset.label) button.dataset.label = button.textContent.trim();
    button.disabled = active;
    form.setAttribute('aria-busy', String(active));
    button.innerHTML = active ? `<span class="button-loader" aria-hidden="true"></span><span>${form.id === 'url-form' ? 'Scanning' : 'Analyzing'}…</span>` : button.dataset.label;
    if (text !== undefined) {
      statusElement.textContent = text;
      statusElement.className = `text-sm ${active ? 'text-sky-300' : 'text-red-300'}`;
    }
  }
  function showPage(page) { document.querySelectorAll('.page').forEach(section => section.classList.toggle('hidden', section.dataset.page !== page)); document.querySelectorAll('[data-page-target]').forEach(button => button.classList.toggle('active', button.dataset.pageTarget === page)); if (page === 'dashboard') loadDashboard(); }

  function setTheme(theme) {
    const isDark = theme === 'dark';
    document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', isDark ? '#292c31' : '#f5f5f7');
    document.querySelectorAll('[data-theme-label]').forEach(label => { label.textContent = isDark ? 'Light appearance' : 'Dark appearance'; });
    document.querySelectorAll('[data-theme-icon]').forEach(icon => {
      icon.innerHTML = isDark
        ? '<path d="M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4"/><circle cx="12" cy="12" r="4"/>'
        : '<path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5 8.5 8.5 0 1 0 20.5 14.5Z"/>';
    });
    try { localStorage.setItem('scamshield-theme', isDark ? 'dark' : 'light'); } catch (_) { /* Storage is optional. */ }
  }

  /* ── Pill Nav Animations ────────────────────────────────── */
  function initPillNav() {
    if (!window.gsap) return;
    const ease = 'power3.easeOut';
    const pills = document.querySelectorAll('.pill');
    const tlRefs = [];
    const activeTweenRefs = [];

    const layout = () => {
      pills.forEach((pill, index) => {
        const circle = pill.querySelector('.hover-circle');
        const label = pill.querySelector('.pill-label');
        const hover = pill.querySelector('.pill-label-hover');
        if (!circle) return;

        const rect = pill.getBoundingClientRect();
        const { width: w, height: h } = rect;
        if (!w || !h) return; // Hidden on mobile sometimes

        const R = ((w * w) / 4 + h * h) / (2 * h);
        const D = Math.ceil(2 * R) + 2;
        const delta = Math.ceil(R - Math.sqrt(Math.max(0, R * R - (w * w) / 4))) + 6;
        const originY = D - delta;

        circle.style.width = `${D}px`;
        circle.style.height = `${D}px`;
        circle.style.bottom = `-${delta}px`;

        gsap.set(circle, {
          xPercent: -50,
          scale: 0,
          transformOrigin: `50% ${originY}px`
        });

        if (label) gsap.set(label, { y: 0 });
        if (hover) gsap.set(hover, { y: h + 12, opacity: 0 });

        if (tlRefs[index]) tlRefs[index].kill();
        const tl = gsap.timeline({ paused: true });

        tl.to(circle, { scale: 1.2, xPercent: -50, duration: 2, ease, overwrite: 'auto' }, 0);
        if (label) tl.to(label, { y: -(h + 8), duration: 2, ease, overwrite: 'auto' }, 0);

        if (hover) {
          gsap.set(hover, { y: Math.ceil(h + 100), opacity: 0 });
          tl.to(hover, { y: 0, opacity: 1, duration: 2, ease, overwrite: 'auto' }, 0);
        }
        tlRefs[index] = tl;
      });
    };

    if (document.fonts?.ready) {
      document.fonts.ready.then(layout).catch(() => { });
    }
    layout();
    window.addEventListener('resize', layout);

    pills.forEach((pill, i) => {
      pill.addEventListener('mouseenter', () => {
        const tl = tlRefs[i];
        if (!tl) return;
        if (activeTweenRefs[i]) activeTweenRefs[i].kill();
        activeTweenRefs[i] = tl.tweenTo(tl.duration(), { duration: 0.3, ease, overwrite: 'auto' });
      });
      pill.addEventListener('mouseleave', () => {
        const tl = tlRefs[i];
        if (!tl) return;
        if (activeTweenRefs[i]) activeTweenRefs[i].kill();
        activeTweenRefs[i] = tl.tweenTo(0, { duration: 0.2, ease, overwrite: 'auto' });
      });
    });

    const logo = document.getElementById('pill-logo');
    let logoTween = null;
    if (logo) {
      if (document.querySelector('.pill-logo svg')) {
        gsap.set(document.querySelector('.pill-logo svg'), { scale: 0 });
        gsap.to(document.querySelector('.pill-logo svg'), { scale: 1, duration: 0.6, ease });
      }

      logo.addEventListener('mouseenter', () => {
        const icon = logo.querySelector('svg');
        if (!icon) return;
        if (logoTween) logoTween.kill();
        gsap.set(icon, { rotate: 0 });
        logoTween = gsap.to(icon, { rotate: 360, duration: 0.3, ease, overwrite: 'auto' });
      });
    }

    const navItems = document.getElementById('pill-nav-items');
    if (navItems) {
      gsap.set(navItems, { width: 0, overflow: 'hidden' });
      gsap.to(navItems, { width: 'auto', duration: 0.6, ease });
    }

    // Mobile menu toggle
    const hamburgerBtn = document.getElementById('hamburger-btn');
    const mobileMenu = document.getElementById('mobile-menu-ref');
    let isMenuOpen = false;

    if (hamburgerBtn && mobileMenu) {
      gsap.set(mobileMenu, { visibility: 'hidden', opacity: 0, scaleY: 1 });

      const toggleMobileMenu = () => {
        isMenuOpen = !isMenuOpen;
        const lines = hamburgerBtn.querySelectorAll('.hamburger-line');
        if (isMenuOpen) {
          gsap.to(lines[0], { rotation: 45, y: 3, duration: 0.3, ease });
          gsap.to(lines[1], { rotation: -45, y: -3, duration: 0.3, ease });

          gsap.set(mobileMenu, { visibility: 'visible' });
          gsap.fromTo(mobileMenu,
            { opacity: 0, y: 10, scaleY: 1 },
            { opacity: 1, y: 0, scaleY: 1, duration: 0.3, ease, transformOrigin: 'top center' }
          );
        } else {
          gsap.to(lines[0], { rotation: 0, y: 0, duration: 0.3, ease });
          gsap.to(lines[1], { rotation: 0, y: 0, duration: 0.3, ease });

          gsap.to(mobileMenu, {
            opacity: 0, y: 10, scaleY: 1, duration: 0.2, ease, transformOrigin: 'top center',
            onComplete: () => { gsap.set(mobileMenu, { visibility: 'hidden' }); }
          });
        }
      };

      hamburgerBtn.addEventListener('click', toggleMobileMenu);

      document.querySelectorAll('.mobile-menu-link').forEach(link => {
        link.addEventListener('click', () => {
          if (isMenuOpen) toggleMobileMenu();
        });
      });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    initPillNav();
    let savedTheme = 'light';
    try { savedTheme = localStorage.getItem('scamshield-theme') || 'light'; } catch (_) { /* Storage is optional. */ }
    setTheme(savedTheme);
    document.querySelectorAll('[data-theme-toggle]').forEach(button => button.onclick = () => {
      setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    });
    document.querySelectorAll('[data-page-target]').forEach(button => button.onclick = () => showPage(button.dataset.pageTarget));
    $('#refresh-dashboard').onclick = loadDashboard;
    $('#email-form').onsubmit = async event => { event.preventDefault(); const form = event.currentTarget, statusEl = $('#email-status'); setLoading(form, statusEl, true, 'Analyzing email…'); showAnalysisLoading('email'); try { const response = await fetch('/api/analyze-email-stream', { method: 'POST', body: new FormData(form) }); if (!response.ok) { const err = await response.json().catch(() => ({})); throw new Error(err.error || `Request failed (${response.status})`); } const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = '', data = null; while (true) { const { done, value: chunk } = await reader.read(); if (done) break; buffer += decoder.decode(chunk, { stream: true }); const lines = buffer.split('\n'); buffer = lines.pop(); let evtType = ''; for (const line of lines) { if (line.startsWith('event: ')) { evtType = line.slice(7).trim(); } else if (line.startsWith('data: ')) { try { const parsed = JSON.parse(line.slice(6)); if (evtType === 'progress') updateProgressUI(parsed.phase, parsed.label, parsed.detail); else if (evtType === 'result') data = parsed; else if (evtType === 'error') throw new Error(parsed.error); } catch (e) { if (e.message && e.message !== 'JSON.parse' && !e.message.includes('JSON')) throw e; } } } if (data) break; } if (!data) throw new Error('Analysis stream ended without results.'); statusEl.textContent = 'Analysis complete.'; statusEl.className = 'text-sm text-green-300'; renderEmail(data); form.reset(); loadDashboard(); } catch (error) { showAnalysisError('email', error.message); setLoading(form, statusEl, false, error.message); } finally { setLoading(form, statusEl, false); } };
    $('#url-form').onsubmit = async event => { event.preventDefault(); const form = event.currentTarget, statusEl = $('#url-status'); setLoading(form, statusEl, true, 'Scanning URL…'); showAnalysisLoading('url'); try { const data = await jsonFetch('/api/analyze-url', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: new FormData(form).get('url') }) }); statusEl.textContent = 'Scan complete.'; statusEl.className = 'mt-3 text-sm text-green-300'; renderUrl(data); form.reset(); loadDashboard(); } catch (error) { showAnalysisError('url', error.message); setLoading(form, statusEl, false, error.message); } finally { setLoading(form, statusEl, false); } };
    loadDashboard();
  });
})();
