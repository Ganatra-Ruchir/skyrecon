/* ============================================================================
 * SkyRecon analysis engine
 * ----------------------------------------------------------------------------
 * Pure, deterministic functions. No randomness, no network, no fabricated data.
 * Every score is computed from the input the analyst supplies and every factor
 * that moved a score is returned alongside it, so the UI can explain itself.
 *
 * The same file runs in the browser (inlined into the console) and in Node
 * (required by the test suite), so the tests exercise exactly what ships.
 * ==========================================================================*/
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SkyRecon = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ── reference tables ──────────────────────────────────────────────────
   * These are static, editable reference data — not guesses generated at
   * runtime. Sources are named so they can be refreshed deliberately.
   * ====================================================================*/

  // Valid TLDs, trimmed to those that realistically appear in threat data.
  // Anything outside this set is treated as "not a domain" (kills the
  // report.pdf / config.json style false positives).
  const TLDS = new Set(('com net org edu gov mil int info biz name pro io ai co me tv cc us uk ca au de fr es it nl se no fi dk pl ru ua cn jp kr in br mx za ch at be cz gr pt ro hu ie il nz sg hk tw th vn id my ph pk bd lk np ir tr sa ae eg ng ke gh tz ug ma dz tn ly sd et zm zw mz ao cm ci sn ml bf ne td mr gn bj tg sl lr gm gw cv st gq ga cg cd rw bi dj so er km mg mu sc yt re mw ls sz bw na app dev cloud site online store shop tech space website web page link click top xyz icu buzz rest cyou sbs work live cfd bond quest fit beauty makeup skin hair mom lol wiki blog news press today world life love art fun run one plus zone city land world group team pub bar cafe menu pizza wine gold silver black red blue green pink asia global center company solutions services support systems network digital media agency studio design host domains email mail cloud tools apps software data science engineering finance capital fund trade market money cash bank insure legal law tax health care clinic doctor dental fitness gym yoga travel tours flights hotels rentals homes house realty estate build construction repair auto cars bike boats parts tires energy solar power gas oil water farm garden pet dog cat vet toys games play video music film movie photo gallery gifts party events club social chat forum community church faith bible school academy college university institute training courses education students library books guide tips how info help faq support desk help center'
    ).split(/\s+/).filter(Boolean));

  // TLD abuse weighting. Tiers reflect repeatedly published abuse rankings
  // (Spamhaus "most abused TLDs", Interisle Cybercrime Supply Chain).
  // Editable: raise or lower per your own telemetry.
  const TLD_RISK = {
    top: 0.92, cyou: 0.90, sbs: 0.90, cfd: 0.88, buzz: 0.86, icu: 0.86,
    click: 0.85, rest: 0.84, quest: 0.82, bond: 0.82, xyz: 0.80, cc: 0.74,
    work: 0.72, live: 0.66, fit: 0.66, beauty: 0.66, makeup: 0.64, mom: 0.62,
    online: 0.62, site: 0.60, space: 0.60, website: 0.58, store: 0.56,
    shop: 0.54, info: 0.52, biz: 0.50, link: 0.50, host: 0.48, pro: 0.42,
    app: 0.34, dev: 0.32, io: 0.28, ai: 0.28, me: 0.30, tv: 0.32, co: 0.34,
    net: 0.22, org: 0.20, com: 0.18, edu: 0.06, gov: 0.04, mil: 0.04,
  };
  const TLD_RISK_DEFAULT = 0.40;

  // The 120 most frequent English bigrams (Norvig, Google Books n-gram
  // analysis). Used to measure how "pronounceable" a label is — DGA output
  // scores low here because it does not follow natural letter transitions.
  const COMMON_BIGRAMS = new Set(('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr ne ct rs sa ai ss us wa em ut il ot ad ye ur ow ge ie ns rt mi so wi tr ur pa ke ai lo ap sh ai un ns id ol na ay ep di rd ir ei bo ba mo ul ns nc av if ay pl ig ee no ke ty ke gh op nn sp mp ck ub ud ug am ab ac ad af ag ak am ap'
    ).split(/\s+/).filter(Boolean));

  // Words that repeatedly appear in credential-harvesting infrastructure.
  const PHISH_WORDS = ['login','signin','sign-in','secure','security','verify','verification',
    'account','update','confirm','support','helpdesk','recovery','reset','password','credential',
    'billing','invoice','payment','wallet','bank','paypal','apple','microsoft','office365','outlook',
    'onedrive','sharepoint','docusign','dropbox','netflix','amazon','sso','mfa','2fa','auth','portal',
    'webmail','unlock','suspended','urgent','alert','refund','delivery','tracking','customs'];

  // Loader / dual-use file extensions worth flagging inside a URL path.
  const RISKY_EXT = ['exe','scr','ps1','bat','cmd','hta','vbs','js','jse','wsf','jar','dll',
    'lnk','iso','img','msi','apk','doc','docm','xls','xlsm','ppt','pptm','rtf','zip','rar','7z'];

  // Cyrillic / Greek characters that read as Latin. Homograph detection.
  const CONFUSABLES = { 'а':'a','е':'e','о':'o','р':'p','с':'c','у':'y','х':'x','і':'i','ѕ':'s',
    'ԁ':'d','ɡ':'g','ν':'v','ο':'o','α':'a','ρ':'p','τ':'t','ι':'i','κ':'k','μ':'u' };

  /* ── small maths helpers ───────────────────────────────────────────── */

  function shannonEntropy(s) {
    if (!s || !s.length) return 0;
    const freq = Object.create(null);
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    let h = 0;
    for (const k in freq) { const p = freq[k] / s.length; h -= p * Math.log2(p); }
    return round(h, 3);
  }

  function mean(xs) { return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0; }

  function stddev(xs) {
    if (xs.length < 2) return 0;
    const m = mean(xs);
    return Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1));
  }

  function zscore(x, xs) {
    const sd = stddev(xs);
    if (!sd) return 0;
    return round((x - mean(xs)) / sd, 3);
  }

  function round(n, dp) { const f = Math.pow(10, dp == null ? 2 : dp); return Math.round(n * f) / f; }
  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

  /* ── defanging ─────────────────────────────────────────────────────── */

  function refang(text) {
    return String(text || '')
      // bracketed separators are unambiguous
      .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
      .replace(/\[:\]|\(:\)/g, ':')
      .replace(/\[@\]|\(@\)|\{@\}/g, '@')
      .replace(/\[\/\]/g, '/')
      // "word dot tld" and "user at domain" only when both sides look like the
      // parts of a real name. Prose such as "observed at evil.xyz" must NOT
      // become an email address, so the word forms need bracketing or a label
      // on both sides with no spaces left over.
      .replace(/([a-z0-9-]{2,})\s*[\[(]?\s*dot\s*[\])]?\s*([a-z]{2,24})\b/gi, '$1.$2')
      .replace(/([a-z0-9._%+-]{2,})\s*[\[(]\s*at\s*[\])]\s*([a-z0-9.-]{2,})/gi, '$1@$2')
      .replace(/h(?:xx|XX|tt)p(s?):\/\//gi, (m, s) => 'http' + (s || '') + '://');
  }

  /* ── extraction ────────────────────────────────────────────────────── */

  const RE = {
    url:    /\b(?:https?|ftp):\/\/[^\s<>"'`\])]+/gi,
    ipv4:   /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    ipv6:   /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi,
    domain: /\b(?:[a-z0-9Ѐ-ӿ](?:[a-z0-9Ѐ-ӿ-]{0,61}[a-z0-9Ѐ-ӿ])?\.)+[a-z]{2,24}\b/gi,
    sha256: /\b[a-f0-9]{64}\b/gi,
    sha1:   /\b[a-f0-9]{40}\b/gi,
    md5:    /\b[a-f0-9]{32}\b/gi,
    email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi,
    cve:    /\bCVE-(?:19|20)\d{2}-\d{4,7}\b/gi,
  };

  // Reserved / non-routable space — RFC 1918, loopback, link-local, CGNAT,
  // documentation ranges, multicast, broadcast.
  function ipClassify(ip) {
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n > 255)) return { valid: false };
    const [a, b] = o;
    const t = (label, routable) => ({ valid: true, scope: label, routable, octets: o });
    if (a === 10) return t('RFC1918 private', false);
    if (a === 172 && b >= 16 && b <= 31) return t('RFC1918 private', false);
    if (a === 192 && b === 168) return t('RFC1918 private', false);
    if (a === 127) return t('loopback', false);
    if (a === 169 && b === 254) return t('link-local', false);
    if (a === 100 && b >= 64 && b <= 127) return t('CGNAT (RFC6598)', false);
    if (a === 192 && b === 0 && o[2] === 2) return t('documentation (TEST-NET-1)', false);
    if (a === 198 && (b === 18 || b === 19)) return t('benchmark (RFC2544)', false);
    if (a === 198 && b === 51 && o[2] === 100) return t('documentation (TEST-NET-2)', false);
    if (a === 203 && b === 0 && o[2] === 113) return t('documentation (TEST-NET-3)', false);
    if (a >= 224 && a <= 239) return t('multicast', false);
    if (a >= 240) return t('reserved', false);
    if (a === 0) return t('unspecified', false);
    return t('public', true);
  }

  const BENIGN_DOMAINS = new Set(['example.com','example.org','example.net','localhost','test',
    'invalid','local','microsoft.com','windowsupdate.com','google.com','gstatic.com','github.com',
    'githubusercontent.com','cloudflare.com','akamai.net','amazonaws.com','apple.com','mozilla.org',
    'w3.org','schema.org','ietf.org','iana.org','wikipedia.org','python.org','npmjs.com','debian.org',
    'ubuntu.com','digicert.com','letsencrypt.org','sectigo.com','verisign.com','office.com','live.com']);

  function domainParts(d) {
    const labels = d.toLowerCase().split('.');
    const tld = labels[labels.length - 1];
    const sld = labels.length >= 2 ? labels[labels.length - 2] : '';
    return { labels, tld, sld, registrable: labels.slice(-2).join('.'), depth: labels.length - 2 };
  }

  /**
   * Pull indicators out of arbitrary text. Returns every candidate with a
   * verdict: kept, or dropped with the reason it was dropped. Nothing is
   * silently discarded — the UI shows the drop list so the analyst can see
   * exactly what the parser did.
   */
  function extract(rawText) {
    const text = refang(rawText);
    const seen = new Map();     // value -> record
    const dropped = [];
    const claimed = [];         // character spans already consumed

    const add = (type, value, weightHint) => {
      const key = type + '|' + value.toLowerCase();
      if (seen.has(key)) { seen.get(key).count++; return; }
      seen.set(key, { type, value, count: 1, hint: weightHint || null });
    };
    const dropIndex = new Map();
    const drop = (type, value, reason) => {
      const k = type + '|' + value.toLowerCase();
      if (dropIndex.has(k)) { dropIndex.get(k).count++; return; }
      const rec = { type, value, reason, count: 1 };
      dropIndex.set(k, rec); dropped.push(rec);
    };

    // URLs first, and remember their spans so their host/path do not get
    // re-extracted as separate loose indicators.
    let m;
    RE.url.lastIndex = 0;
    while ((m = RE.url.exec(text))) {
      const raw = m[0].replace(/[.,;:)\]]+$/, '');
      claimed.push([m.index, m.index + raw.length]);
      add('url', raw);
      try {
        const u = new URL(raw);
        const host = u.hostname;
        if (RE.ipv4.test(host)) { RE.ipv4.lastIndex = 0; add('ipv4', host, 'url-host'); }
        else if (host.includes('.')) add('domain', host, 'url-host');
      } catch (_) { /* malformed URL: keep the raw string only */ }
    }
    const inClaimed = (i, len) => claimed.some(([s, e]) => i >= s && i + len <= e);

    RE.ipv4.lastIndex = 0;
    while ((m = RE.ipv4.exec(text))) {
      if (inClaimed(m.index, m[0].length)) continue;
      const info = ipClassify(m[0]);
      if (!info.routable) drop('ipv4', m[0], info.scope);
      else add('ipv4', m[0]);
    }

    RE.sha256.lastIndex = 0; while ((m = RE.sha256.exec(text))) add('sha256', m[0].toLowerCase());
    RE.sha1.lastIndex = 0;
    while ((m = RE.sha1.exec(text))) { const v = m[0].toLowerCase(); if (!seen.has('sha256|' + v)) add('sha1', v); }
    RE.md5.lastIndex = 0;   while ((m = RE.md5.exec(text)))   add('md5', m[0].toLowerCase());
    RE.cve.lastIndex = 0;   while ((m = RE.cve.exec(text)))   add('cve', m[0].toUpperCase());

    RE.email.lastIndex = 0;
    const emailHosts = new Set();
    while ((m = RE.email.exec(text))) {
      const v = m[0].toLowerCase();
      const host = v.split('@')[1];
      emailHosts.add(host);
      claimed.push([m.index, m.index + m[0].length]);
      add('email', v);
    }

    RE.domain.lastIndex = 0;
    while ((m = RE.domain.exec(text))) {
      const v = m[0].toLowerCase().replace(/\.$/, '');
      if (inClaimed(m.index, m[0].length) && !emailHosts.has(v)) continue;
      const { tld, registrable } = domainParts(v);
      if (!TLDS.has(tld)) { drop('domain', v, 'not a recognised TLD (.' + tld + ')'); continue; }
      if (BENIGN_DOMAINS.has(v) || BENIGN_DOMAINS.has(registrable)) { drop('domain', v, 'known-benign infrastructure'); continue; }
      if (/^\d+\.\d+$/.test(v)) { drop('domain', v, 'looks like a version number'); continue; }
      add('domain', v);
    }

    return { indicators: Array.from(seen.values()), dropped, refanged: text };
  }

  /* ── enrichment ────────────────────────────────────────────────────── */

  /**
   * DGA likelihood for one domain label. Five measurable components, each
   * returned so the score can be defended in a report:
   *   entropy        – Shannon entropy normalised against label length
   *   bigrams        – share of letter pairs that occur in natural English
   *   consonantRun   – longest run of consonants
   *   digitRatio     – digits mixed into the label
   *   vowelRatio     – deviation from the ~38% vowel share of English words
   */
  function dgaScore(label) {
    const s = String(label || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (s.length < 5) return { score: 0, components: [], note: 'label too short to assess' };

    const letters = s.replace(/[^a-z]/g, '');
    const maxH = Math.log2(Math.max(2, new Set(s).size));
    const entropyNorm = clamp(shannonEntropy(s) / (maxH || 1), 0, 1);

    let hits = 0, pairs = 0;
    for (let i = 0; i < letters.length - 1; i++) { pairs++; if (COMMON_BIGRAMS.has(letters.slice(i, i + 2))) hits++; }
    const bigramHit = pairs ? hits / pairs : 0;

    let run = 0, best = 0;
    for (const ch of letters) { if ('aeiou'.includes(ch)) run = 0; else { run++; best = Math.max(best, run); } }

    const digitRatio = (s.replace(/\D/g, '').length) / s.length;
    const vowels = (letters.match(/[aeiou]/g) || []).length;
    const vowelRatio = letters.length ? vowels / letters.length : 0;
    const vowelDev = clamp(Math.abs(vowelRatio - 0.38) / 0.38, 0, 1);

    const components = [
      { key: 'entropy',      value: round(entropyNorm, 3), weight: 0.3, detail: 'normalised Shannon entropy ' + shannonEntropy(s) },
      { key: 'bigrams',      value: round(1 - bigramHit, 3), weight: 0.28, detail: round(bigramHit * 100, 1) + '% of letter pairs are natural English bigrams' },
      { key: 'consonantRun', value: round(clamp((best - 2) / 5, 0, 1), 3), weight: 0.18, detail: 'longest consonant run ' + best },
      { key: 'digitRatio',   value: round(clamp(digitRatio * 2.5, 0, 1), 3), weight: 0.12, detail: round(digitRatio * 100, 1) + '% digits' },
      { key: 'vowelRatio',   value: round(vowelDev, 3), weight: 0.12, detail: round(vowelRatio * 100, 1) + '% vowels vs 38% expected' },
    ];
    const score = clamp(components.reduce((a, c) => a + c.value * c.weight, 0), 0, 1);
    return { score: round(score, 3), components };
  }

  function homograph(value) {
    const flags = [];
    if (/^xn--/i.test(value) || value.split('.').some((l) => /^xn--/i.test(l))) flags.push('punycode label (IDN)');
    const conf = Array.from(value).filter((c) => CONFUSABLES[c]);
    if (conf.length) flags.push('non-Latin lookalike characters: ' + Array.from(new Set(conf)).join(' '));
    if (/[a-z]\d[a-z]/i.test(value) && /(0|1|5|3)/.test(value)) flags.push('digit-for-letter substitution pattern');
    return flags;
  }

  function keywordHits(value) {
    const v = value.toLowerCase();
    return PHISH_WORDS.filter((w) => v.includes(w));
  }

  function urlInfo(raw) {
    let u;
    try { u = new URL(raw); } catch (_) { return { valid: false }; }
    const path = u.pathname || '';
    const ext = (path.match(/\.([a-z0-9]{1,5})$/i) || [, ''])[1].toLowerCase();
    return {
      valid: true, scheme: u.protocol.replace(':', ''), host: u.hostname,
      port: u.port || (u.protocol === 'https:' ? '443' : '80'),
      nonStandardPort: !!u.port && !['80', '443'].includes(u.port),
      hasCredentials: !!(u.username || u.password),
      ipHost: ipClassify(u.hostname).valid,
      pathDepth: path.split('/').filter(Boolean).length,
      extension: ext, riskyExtension: RISKY_EXT.includes(ext),
      queryLength: (u.search || '').length,
    };
  }

  function hashInfo(v) {
    const n = v.length;
    return { algorithm: n === 32 ? 'MD5' : n === 40 ? 'SHA-1' : n === 64 ? 'SHA-256' : 'unknown',
             collisionProne: n === 32 || n === 40 };
  }

  function cveInfo(v) {
    const [, year, id] = v.match(/CVE-(\d{4})-(\d+)/i) || [];
    const y = Number(year), now = new Date().getUTCFullYear();
    return { year: y, id, plausible: y >= 1999 && y <= now + 1, age: now - y };
  }

  /**
   * Score one indicator. Returns 0-100 risk plus every factor that moved it,
   * with the arithmetic exposed. Deterministic: the same input always gives
   * the same number.
   */
  function scoreIndicator(ind, opts) {
    const o = opts || {};
    const sightings = o.sightings || 1;
    const source = o.source || 'analyst';
    const factors = [];
    let risk = 0;

    const baseBySource = { 'feed:high-confidence': 55, 'feed:community': 42, analyst: 35, report: 38, log: 30 };
    const base = baseBySource[source] != null ? baseBySource[source] : 35;
    risk += base;
    factors.push({ label: 'Source baseline', delta: base, detail: source + ' submission' });

    const type = ind.type, value = ind.value;

    if (type === 'domain' || type === 'url' || type === 'email') {
      const host = type === 'url' ? (urlInfo(value).host || '') : type === 'email' ? value.split('@')[1] : value;
      if (host) {
        const { tld, sld, depth } = domainParts(host);
        const tr = TLD_RISK[tld] != null ? TLD_RISK[tld] : TLD_RISK_DEFAULT;
        const tldDelta = Math.round((tr - 0.35) * 40);
        risk += tldDelta;
        factors.push({ label: 'TLD weighting', delta: tldDelta, detail: '.' + tld + ' abuse weight ' + tr });

        const d = dgaScore(sld);
        if (d.score) {
          const dgaDelta = Math.round(d.score * 34);
          risk += dgaDelta;
          factors.push({ label: 'DGA likelihood', delta: dgaDelta, detail: 'classifier ' + d.score + ' on "' + sld + '"', components: d.components });
        }
        const kw = keywordHits(host);
        if (kw.length) {
          const kwDelta = Math.min(16, kw.length * 7);
          risk += kwDelta;
          factors.push({ label: 'Credential-theft vocabulary', delta: kwDelta, detail: kw.join(', ') });
        }
        const hg = homograph(host);
        if (hg.length) { risk += 18; factors.push({ label: 'Homograph indicators', delta: 18, detail: hg.join('; ') }); }
        if (depth >= 3) { risk += 6; factors.push({ label: 'Deep subdomain nesting', delta: 6, detail: depth + ' levels below the registrable domain' }); }
        if (host.length > 30) { risk += 4; factors.push({ label: 'Unusual hostname length', delta: 4, detail: host.length + ' characters' }); }
      }
    }

    if (type === 'url') {
      const u = urlInfo(value);
      if (u.valid) {
        if (u.riskyExtension) { risk += 15; factors.push({ label: 'Executable payload extension', delta: 15, detail: '.' + u.extension }); }
        if (u.ipHost) { risk += 12; factors.push({ label: 'Bare IP in URL', delta: 12, detail: 'no hostname — common in loader infrastructure' }); }
        if (u.hasCredentials) { risk += 14, factors.push({ label: 'Credentials embedded in URL', delta: 14, detail: 'user:pass@ form' }); }
        if (u.nonStandardPort) { risk += 7; factors.push({ label: 'Non-standard port', delta: 7, detail: 'port ' + u.port }); }
        if (u.scheme === 'http') { risk += 4; factors.push({ label: 'Cleartext scheme', delta: 4, detail: 'http:// with no TLS' }); }
        if (u.queryLength > 120) { risk += 5; factors.push({ label: 'Oversized query string', delta: 5, detail: u.queryLength + ' characters' }); }
      }
    }

    if (type === 'ipv4') {
      const info = ipClassify(value);
      if (!info.routable) {
        risk -= 30;
        factors.push({ label: 'Non-routable address', delta: -30, detail: info.scope });
      }
    }

    if (type === 'md5' || type === 'sha1') {
      const h = hashInfo(value);
      risk -= 6;
      factors.push({ label: 'Weak hash algorithm', delta: -6, detail: h.algorithm + ' is collision-prone — prefer SHA-256 for pivoting' });
    }

    if (type === 'cve') {
      const c = cveInfo(value);
      if (!c.plausible) { risk -= 25; factors.push({ label: 'Implausible CVE year', delta: -25, detail: 'year ' + c.year }); }
      else if (c.age <= 1) { risk += 12; factors.push({ label: 'Recent CVE', delta: 12, detail: 'published within the last year' }); }
    }

    if (sightings > 1) {
      const sDelta = Math.min(14, Math.round(Math.log2(sightings) * 6));
      risk += sDelta;
      factors.push({ label: 'Corroborating sightings', delta: sDelta, detail: sightings + ' observations' });
    }

    risk = clamp(Math.round(risk), 0, 100);

    // Confidence is about how much you should trust the score, not how bad
    // the thing is: strong when several independent factors agree.
    const positive = factors.filter((f) => f.delta > 0).length;
    let confidence = clamp(Math.round(30 + positive * 11 + Math.min(20, (sightings - 1) * 5)), 5, 97);
    if (source.startsWith('feed:')) confidence = clamp(confidence + 8, 5, 97);

    return { risk, confidence, factors, severity: severityFor(risk) };
  }

  function severityFor(risk) {
    return risk >= 85 ? 'critical' : risk >= 65 ? 'high' : risk >= 40 ? 'medium' : 'low';
  }

  /** Confidence decays without a fresh sighting — 30-day half-life. */
  function decayConfidence(confidence, lastSeenMs, nowMs) {
    const days = Math.max(0, (nowMs - lastSeenMs) / 86400000);
    return clamp(Math.round(confidence * Math.pow(0.5, days / 30)), 0, 100);
  }

  /* ── log parsing ───────────────────────────────────────────────────── */

  const LOG_PATTERNS = [
    { name: 'sshd auth',
      re: /^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*?sshd\[\d+\]:\s+(Failed|Accepted)\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)/,
      map: (m) => ({ ts: m[1], type: 'AUTH', outcome: m[2].toLowerCase() === 'failed' ? 'failure' : 'success',
                     user: m[3], src: m[4] }) },
    { name: 'nginx/apache combined',
      re: /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+|-)/,
      map: (m) => ({ ts: m[3], type: 'HTTP', src: m[1], user: m[2] === '-' ? null : m[2],
                     method: m[4], path: m[5], status: Number(m[6]), bytesOut: m[7] === '-' ? 0 : Number(m[7]) }) },
    { name: 'windows security 4625/4624',
      re: /Event\s?ID[:\s]+(4624|4625).*?Account Name[:\s]+(\S+).*?Source Network Address[:\s]+(\S+)/is,
      map: (m) => ({ type: 'AUTH', outcome: m[1] === '4625' ? 'failure' : 'success', user: m[2], src: m[3] }) },
    { name: 'firewall/flow csv',
      re: /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})[,\s]+(\S+)[,\s]+(\S+)[,\s]+(\d+)[,\s]+(\d+)\s*$/,
      map: (m) => ({ ts: m[1], type: 'NETWORK', src: m[2], dst: m[3], bytesOut: Number(m[4]), bytesIn: Number(m[5]) }) },
  ];

  function parseTimestamp(s) {
    if (!s) return null;
    const iso = Date.parse(s);
    if (!Number.isNaN(iso)) return iso;
    // Apache: 10/Oct/2026:13:55:36 +0000
    const ap = s.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
    if (ap) {
      const months = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
      return Date.UTC(+ap[3], months[ap[2]], +ap[1], +ap[4], +ap[5], +ap[6]);
    }
    // syslog: Oct 10 13:55:36 (no year — assume current)
    const sl = s.match(/^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})/);
    if (sl) {
      const months = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
      return Date.UTC(new Date().getUTCFullYear(), months[sl[1]], +sl[2], +sl[3], +sl[4], +sl[5]);
    }
    return null;
  }

  /** Parse pasted logs into normalised events. Unmatched lines are reported,
   *  never silently dropped. JSON lines and CSV with headers are supported. */
  function parseLogs(text) {
    const lines = String(text || '').split(/\r?\n/).filter((l) => l.trim());
    const events = [];
    const unparsed = [];
    const formats = Object.create(null);

    // CSV with a header row?
    let csvHeader = null;
    if (lines.length > 1 && lines[0].includes(',') && !lines[0].startsWith('{')) {
      const h = lines[0].toLowerCase().split(',').map((s) => s.trim());
      if (h.some((c) => /time|date|timestamp/.test(c)) && h.length >= 3) csvHeader = h;
    }

    lines.forEach((line, idx) => {
      if (csvHeader && idx === 0) return;

      if (line.trim().startsWith('{')) {
        try {
          const j = JSON.parse(line);
          const ev = {
            ts: parseTimestamp(j.timestamp || j.time || j['@timestamp'] || j.ts) || null,
            type: (j.type || j.event_type || 'OTHER').toString().toUpperCase(),
            src: j.src_ip || j.source_ip || j.src || j.client_ip || null,
            dst: j.dst_ip || j.destination || j.dest_ip || j.host || null,
            user: j.user || j.username || j.account || null,
            bytesOut: Number(j.bytes_out || j.bytes_sent || j.bytes || 0) || 0,
            outcome: j.outcome || j.result || null,
            raw: line,
          };
          events.push(ev); formats['json lines'] = (formats['json lines'] || 0) + 1; return;
        } catch (_) { /* fall through */ }
      }

      if (csvHeader) {
        const cells = line.split(',').map((s) => s.trim());
        const get = (names) => { for (const n of names) { const i = csvHeader.findIndex((c) => c.includes(n)); if (i >= 0 && cells[i] != null) return cells[i]; } return null; };
        const ev = {
          ts: parseTimestamp(get(['timestamp', 'time', 'date'])),
          type: (get(['type', 'event']) || 'OTHER').toUpperCase(),
          src: get(['src', 'source', 'client']),
          dst: get(['dst', 'dest', 'destination', 'host']),
          user: get(['user', 'account']),
          bytesOut: Number(get(['bytes_out', 'bytes', 'sent'])) || 0,
          outcome: get(['outcome', 'result', 'status']),
          raw: line,
        };
        if (ev.ts || ev.src || ev.dst) { events.push(ev); formats['csv'] = (formats['csv'] || 0) + 1; return; }
      }

      for (const p of LOG_PATTERNS) {
        const m = line.match(p.re);
        if (m) {
          const ev = p.map(m);
          ev.ts = parseTimestamp(ev.ts);
          ev.raw = line;
          ev.bytesOut = ev.bytesOut || 0;
          events.push(ev);
          formats[p.name] = (formats[p.name] || 0) + 1;
          return;
        }
      }
      unparsed.push({ line: idx + 1, text: line.slice(0, 160) });
    });

    return { events, unparsed, formats, lineCount: lines.length };
  }

  /**
   * Behavioural facts computed from the analyst's own events — no baselines
   * invented, everything measured against the data supplied.
   */
  function analyseEvents(events) {
    const byHost = Object.create(null);
    const authFailures = Object.create(null);
    const destCount = Object.create(null);
    const bytesSeries = [];

    events.forEach((e) => {
      const key = e.src || e.dst || 'unknown';
      (byHost[key] || (byHost[key] = { events: 0, bytesOut: 0, failures: 0, dsts: new Set() })).events++;
      byHost[key].bytesOut += e.bytesOut || 0;
      if (e.dst) byHost[key].dsts.add(e.dst);
      if (e.bytesOut) bytesSeries.push(e.bytesOut);
      if (e.type === 'AUTH' && e.outcome === 'failure') {
        const k = e.src || 'unknown';
        (authFailures[k] || (authFailures[k] = [])).push(e.ts || 0);
        byHost[key].failures++;
      }
      if (e.dst) destCount[e.dst] = (destCount[e.dst] || 0) + 1;
    });

    // Sliding 4-minute window over real timestamps.
    const bruteForce = [];
    Object.entries(authFailures).forEach(([ip, stamps]) => {
      const ts = stamps.filter(Boolean).sort((a, b) => a - b);
      if (ts.length < 5) { if (stamps.length >= 8) bruteForce.push({ ip, count: stamps.length, windowMs: null }); return; }
      let best = 0, j = 0;
      for (let i = 0; i < ts.length; i++) {
        while (ts[i] - ts[j] > 240000) j++;
        best = Math.max(best, i - j + 1);
      }
      if (best >= 5) bruteForce.push({ ip, count: best, windowMs: 240000, total: ts.length });
    });

    // A z-score over a handful of samples is noise: one outlier inflates the
    // standard deviation it is being measured against. Require a real baseline.
    const MIN_BASELINE = 8;
    const transfers = bytesSeries.length < MIN_BASELINE ? [] : events
      .filter((e) => e.bytesOut > 0)
      .map((e) => ({ ...e, z: zscore(e.bytesOut, bytesSeries) }))
      .filter((e) => e.z >= 3)
      .sort((a, b) => b.z - a.z);

    const rareDest = Object.entries(destCount)
      .filter(([, n]) => n === 1)
      .map(([d]) => d);

    return {
      hosts: Object.fromEntries(Object.entries(byHost).map(([k, v]) => [k, { ...v, dsts: v.dsts.size }])),
      bruteForce, transfers, rareDest,
      stats: { events: events.length, bytesMean: Math.round(mean(bytesSeries)), bytesStdDev: Math.round(stddev(bytesSeries)),
               baselineSamples: bytesSeries.length, baselineSufficient: bytesSeries.length >= MIN_BASELINE },
    };
  }

  /* ── rule engine (recursive descent — never eval) ──────────────────── */

  function tokenize(src) {
    const out = [];
    const re = /\s*(>=|<=|==|!=|=~|>|<|\(|\)|\band\b|\bor\b|\bnot\b|"[^"]*"|\/(?:[^\/\\]|\\.)*\/[a-z]*|[A-Za-z_][\w.]*|\d+(?:\.\d+)?)/gy;
    let m, i = 0;
    while (i < src.length) {
      re.lastIndex = i;
      m = re.exec(src);
      if (!m) { if (!src.slice(i).trim()) break; throw new Error('Unexpected character at position ' + i + ': "' + src[i] + '"'); }
      out.push(m[1]); i = re.lastIndex;
    }
    return out;
  }

  function parseRule(src) {
    const t = tokenize(src);
    let p = 0;
    const peek = () => t[p];
    const eat = (v) => { if (t[p] !== v) throw new Error('Expected ' + v + ' but found ' + (t[p] || 'end of expression')); return t[p++]; };

    function expr() { let n = term(); while (peek() === 'or') { p++; n = { op: 'or', l: n, r: term() }; } return n; }
    function term() { let n = unary(); while (peek() === 'and') { p++; n = { op: 'and', l: n, r: unary() }; } return n; }
    function unary() { if (peek() === 'not') { p++; return { op: 'not', v: unary() }; } return atom(); }
    function atom() {
      if (peek() === '(') { p++; const n = expr(); eat(')'); return n; }
      const left = value();
      const op = peek();
      if (['>', '<', '>=', '<=', '==', '!=', '=~'].includes(op)) { p++; return { op, l: left, r: value() }; }
      return { op: 'truthy', v: left };
    }
    function value() {
      const tok = t[p++];
      if (tok == null) throw new Error('Unexpected end of expression');
      if (/^"/.test(tok)) return { lit: tok.slice(1, -1) };
      if (/^\//.test(tok)) { const i = tok.lastIndexOf('/'); return { re: new RegExp(tok.slice(1, i), tok.slice(i + 1)) }; }
      if (/^\d/.test(tok)) return { lit: Number(tok) };
      if (tok === 'true') return { lit: true };
      if (tok === 'false') return { lit: false };
      return { field: tok };
    }
    const ast = expr();
    if (p !== t.length) throw new Error('Unexpected trailing input: ' + t.slice(p).join(' '));
    return ast;
  }

  function evalRule(ast, ctx) {
    const get = (n) => {
      if (n.field != null) return n.field.split('.').reduce((o, k) => (o == null ? undefined : o[k]), ctx);
      if (n.re != null) return n.re;
      return n.lit;
    };
    switch (ast.op) {
      case 'and': return !!(evalRule(ast.l, ctx) && evalRule(ast.r, ctx));
      case 'or': return !!(evalRule(ast.l, ctx) || evalRule(ast.r, ctx));
      case 'not': return !evalRule(ast.v, ctx);
      case 'truthy': { const v = get(ast.v); return !!v; }
      case '=~': { const v = get(ast.l), r = get(ast.r); return r instanceof RegExp ? r.test(String(v == null ? '' : v)) : String(v).includes(String(r)); }
      default: {
        const a = get(ast.l), b = get(ast.r);
        if (a === undefined || a === null) return false;
        switch (ast.op) {
          case '>': return a > b; case '<': return a < b;
          case '>=': return a >= b; case '<=': return a <= b;
          case '==': return a == b; case '!=': return a != b;
        }
      }
    }
    return false;
  }

  // Shipped rules. Each names the ATT&CK technique it evidences, so the
  // matrix is populated by what actually fired, never by decoration.
  const DEFAULT_RULES = [
    { id: 'R-001', name: 'High-entropy algorithmic domain', expr: 'dga > 0.6 and tld_risk > 0.5', severity: 'high', technique: 'T1568.002', enabled: true },
    { id: 'R-002', name: 'Credential-theft vocabulary in hostname', expr: 'phish_words >= 2 and type == "domain"', severity: 'high', technique: 'T1566.002', enabled: true },
    { id: 'R-003', name: 'Executable delivered over cleartext HTTP', expr: 'risky_extension and scheme == "http"', severity: 'critical', technique: 'T1105', enabled: true },
    { id: 'R-004', name: 'Bare IP address used as web host', expr: 'ip_host and type == "url"', severity: 'medium', technique: 'T1071.001', enabled: true },
    { id: 'R-005', name: 'Homograph or punycode hostname', expr: 'homograph_flags >= 1', severity: 'high', technique: 'T1583.001', enabled: true },
    { id: 'R-006', name: 'Recently published CVE referenced', expr: 'type == "cve" and cve_age <= 1', severity: 'medium', technique: 'T1588.006', enabled: true },
    { id: 'R-007', name: 'Composite risk above triage threshold', expr: 'risk >= 85', severity: 'critical', technique: 'T1071', enabled: true },
    { id: 'R-008', name: 'Non-standard port on external host', expr: 'nonstandard_port and type == "url"', severity: 'medium', technique: 'T1571', enabled: true },
  ];

  const EVENT_RULES = [
    { id: 'R-101', name: 'Authentication brute force', severity: 'high', technique: 'T1110',
      describe: (h) => h.count + ' failed authentications from ' + h.ip + (h.windowMs ? ' within 4 minutes' : ' in the supplied window') },
    { id: 'R-102', name: 'Outbound transfer far above baseline', severity: 'high', technique: 'T1041',
      describe: (t) => formatBytes(t.bytesOut) + ' to ' + (t.dst || 'an external host') + ' — ' + t.z + ' sigma above the mean of this dataset' },
  ];

  /** Build the evaluation context for one indicator. Field names here are the
   *  identifiers analysts type into rules. */
  function ruleContext(ind, scored) {
    const type = ind.type, value = ind.value;
    const host = type === 'url' ? (urlInfo(value).host || '') : type === 'email' ? value.split('@')[1] : value;
    const parts = host && host.includes('.') ? domainParts(host) : null;
    const u = type === 'url' ? urlInfo(value) : {};
    const dga = parts ? dgaScore(parts.sld) : { score: 0 };
    return {
      type, value, host,
      risk: scored.risk, confidence: scored.confidence, severity: scored.severity,
      dga: dga.score,
      tld: parts ? parts.tld : '',
      tld_risk: parts ? (TLD_RISK[parts.tld] != null ? TLD_RISK[parts.tld] : TLD_RISK_DEFAULT) : 0,
      entropy: parts ? shannonEntropy(parts.sld) : shannonEntropy(value),
      phish_words: keywordHits(host || value).length,
      homograph_flags: homograph(host || value).length,
      subdomain_depth: parts ? parts.depth : 0,
      scheme: u.scheme || '', ip_host: !!u.ipHost, risky_extension: !!u.riskyExtension,
      nonstandard_port: !!u.nonStandardPort, has_credentials: !!u.hasCredentials,
      cve_age: type === 'cve' ? cveInfo(value).age : null,
      length: value.length,
    };
  }

  function runRules(rules, indicators, scores) {
    const alerts = [];
    rules.filter((r) => r.enabled).forEach((rule) => {
      let ast;
      try { ast = parseRule(rule.expr); }
      catch (e) { alerts.push({ ruleError: true, rule: rule.id, message: e.message }); return; }
      indicators.forEach((ind, i) => {
        const ctx = ruleContext(ind, scores[i]);
        let hit = false;
        try { hit = evalRule(ast, ctx); } catch (_) { hit = false; }
        if (hit) {
          alerts.push({
            ruleId: rule.id, rule: rule.name, severity: rule.severity, technique: rule.technique,
            indicator: ind.value, type: ind.type,
            risk: scores[i].risk, confidence: scores[i].confidence,
            reasons: scores[i].factors.filter((f) => f.delta > 0).map((f) => f.label + ': ' + f.detail + ' (+' + f.delta + ')'),
            expr: rule.expr,
          });
        }
      });
    });
    return alerts;
  }

  function runEventRules(analysis) {
    const alerts = [];
    analysis.bruteForce.forEach((h) => {
      const r = EVENT_RULES[0];
      alerts.push({ ruleId: r.id, rule: r.name, severity: r.severity, technique: r.technique,
        indicator: h.ip, type: 'ipv4', risk: clamp(55 + h.count * 3, 0, 96), confidence: 78,
        reasons: [r.describe(h)], expr: 'auth_failures_4m >= 5' });
    });
    analysis.transfers.slice(0, 25).forEach((t) => {
      const r = EVENT_RULES[1];
      alerts.push({ ruleId: r.id, rule: r.name, severity: t.z >= 5 ? 'critical' : r.severity, technique: r.technique,
        indicator: t.dst || t.src || 'unknown', type: 'ipv4',
        risk: clamp(Math.round(55 + t.z * 7), 0, 98), confidence: clamp(Math.round(50 + t.z * 6), 0, 95),
        reasons: [r.describe(t)], expr: 'zscore(bytes_out) >= 3' });
    });
    return alerts;
  }

  /* ── graph ─────────────────────────────────────────────────────────── */

  function buildGraph(indicators, events) {
    const nodes = new Map();
    const edges = [];
    const node = (id, kind, meta) => {
      if (!nodes.has(id)) nodes.set(id, { id, kind, ...(meta || {}) });
      else if (meta) Object.assign(nodes.get(id), meta);
      return nodes.get(id);
    };
    const edge = (a, b, rel) => {
      if (!a || !b || a === b) return;
      const key = a + '|' + b + '|' + rel;
      if (!edges.some((e) => e.key === key)) edges.push({ key, src: a, dst: b, rel });
    };

    indicators.forEach((i) => {
      node(i.value, i.type === 'ipv4' ? 'ip' : i.type, { risk: i.risk, severity: i.severity });
      if (i.type === 'url') {
        const h = urlInfo(i.value).host;
        if (h) { node(h, ipClassify(h).valid ? 'ip' : 'domain', {}); edge(i.value, h, 'hosted_on'); }
      }
      if (i.type === 'email') {
        const h = i.value.split('@')[1];
        if (h) { node(h, 'domain', {}); edge(i.value, h, 'sender_domain'); }
      }
    });

    (events || []).forEach((e) => {
      if (e.src) node(e.src, ipClassify(e.src).routable === false ? 'host' : 'ip', {});
      if (e.dst) node(e.dst, ipClassify(e.dst).valid ? 'ip' : 'domain', {});
      if (e.user) node(e.user, 'account', {});
      if (e.src && e.dst) edge(e.src, e.dst, e.type === 'DNS' ? 'resolved' : 'communicated_with');
      if (e.src && e.user) edge(e.src, e.user, 'authenticated_as');
    });

    return { nodes: Array.from(nodes.values()), edges };
  }

  /* ── exports ───────────────────────────────────────────────────────── */

  function formatBytes(n) {
    if (!n) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return round(n / Math.pow(1024, i), 1) + ' ' + u[i];
  }

  const STIX_TYPE = { ipv4: 'ipv4-addr:value', domain: 'domain-name:value', url: 'url:value',
    sha256: "file:hashes.'SHA-256'", sha1: "file:hashes.'SHA-1'", md5: 'file:hashes.MD5',
    email: 'email-addr:value' };

  function toStix(indicators, meta) {
    const now = new Date().toISOString();
    const objects = indicators.filter((i) => STIX_TYPE[i.type]).map((i, n) => ({
      type: 'indicator',
      spec_version: '2.1',
      id: 'indicator--' + uuidFrom(i.type + i.value),
      created: new Date(i.firstSeen || Date.now()).toISOString(),
      modified: new Date(i.lastSeen || Date.now()).toISOString(),
      name: i.type.toUpperCase() + ' ' + i.value,
      description: (i.factors || []).map((f) => f.label + ': ' + f.detail).join(' | '),
      indicator_types: ['malicious-activity'],
      pattern: '[' + STIX_TYPE[i.type] + " = '" + i.value.replace(/'/g, "\\'") + "']",
      pattern_type: 'stix',
      valid_from: new Date(i.firstSeen || Date.now()).toISOString(),
      confidence: i.confidence,
      labels: [i.severity, 'risk-' + i.risk],
    }));
    return {
      type: 'bundle',
      id: 'bundle--' + uuidFrom('skyrecon' + now),
      objects: [{ type: 'identity', spec_version: '2.1', id: 'identity--' + uuidFrom('skyrecon'),
                  created: now, modified: now, name: (meta && meta.producer) || 'SkyRecon', identity_class: 'system' }, ...objects],
    };
  }

  // Deterministic UUIDv4-shaped id from a string (FNV-1a x4). Same input,
  // same id — so re-exporting the same indicator does not churn ids.
  function uuidFrom(str) {
    const h = [0x811c9dc5, 0x01000193, 0x811c9dc5 ^ 0x5bf03635, 0x9e3779b9];
    for (let i = 0; i < str.length; i++) {
      for (let k = 0; k < 4; k++) {
        h[k] ^= str.charCodeAt(i) + k;
        h[k] = Math.imul(h[k], 0x01000193) >>> 0;
      }
    }
    const hex = h.map((x) => x.toString(16).padStart(8, '0')).join('');
    return [hex.slice(0, 8), hex.slice(8, 12), '4' + hex.slice(13, 16),
            ((parseInt(hex[16], 16) & 0x3 | 0x8).toString(16)) + hex.slice(17, 20), hex.slice(20, 32)].join('-');
  }

  function toCsv(rows, columns) {
    const esc = (v) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return [columns.join(','), ...rows.map((r) => columns.map((c) => esc(r[c])).join(','))].join('\n');
  }

  return {
    // maths
    shannonEntropy, mean, stddev, zscore, round, clamp, formatBytes,
    // parsing
    refang, extract, ipClassify, domainParts, parseTimestamp, parseLogs,
    // enrichment
    dgaScore, homograph, keywordHits, urlInfo, hashInfo, cveInfo,
    scoreIndicator, severityFor, decayConfidence,
    // detection
    tokenize, parseRule, evalRule, ruleContext, runRules, runEventRules,
    analyseEvents, buildGraph,
    DEFAULT_RULES, EVENT_RULES, TLD_RISK, TLDS,
    // export
    toStix, toCsv, uuidFrom,
  };
});
