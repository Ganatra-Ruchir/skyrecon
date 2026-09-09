/* SkyRecon engine — unit tests.
 * Run: node engine.test.js
 * No framework: assertions against known-correct values, so a wrong answer
 * fails loudly rather than a green tick meaning "it executed".
 */
const path = require('path');
const S = require(path.join(__dirname, '..', '..', 'engine', 'engine.js'));

let pass = 0, fail = 0;
const results = [];
function t(name, fn) {
  try { fn(); pass++; results.push(['PASS', name, '']); }
  catch (e) { fail++; results.push(['FAIL', name, e.message]); }
}
function eq(a, b, msg) {
  const A = JSON.stringify(a), B = JSON.stringify(b);
  if (A !== B) throw new Error((msg || '') + ' expected ' + B + ' got ' + A);
}
function near(a, b, tol, msg) {
  if (Math.abs(a - b) > (tol == null ? 0.001 : tol)) throw new Error((msg || '') + ' expected ~' + b + ' got ' + a);
}
function ok(v, msg) { if (!v) throw new Error(msg || 'expected truthy, got ' + v); }
function notOk(v, msg) { if (v) throw new Error(msg || 'expected falsy, got ' + v); }

/* ── information theory: values verifiable by hand ─────────────────── */
t('entropy of a single repeated character is 0', () => near(S.shannonEntropy('aaaaaa'), 0));
t('entropy of 4 distinct equiprobable symbols is exactly 2', () => near(S.shannonEntropy('abcd'), 2));
t('entropy of 8 distinct equiprobable symbols is exactly 3', () => near(S.shannonEntropy('abcdefgh'), 3));
t('entropy of "aabb" is 1 bit', () => near(S.shannonEntropy('aabb'), 1));
t('entropy of empty string is 0', () => near(S.shannonEntropy(''), 0));

t('mean and sample standard deviation match textbook values', () => {
  const xs = [2, 4, 4, 4, 5, 5, 7, 9];
  near(S.mean(xs), 5);
  near(S.stddev(xs), 2.13809, 0.0001);   // sample (n-1) stddev
});
t('z-score of the mean is 0', () => near(S.zscore(5, [2, 4, 4, 4, 5, 5, 7, 9]), 0));
t('z-score of a known outlier is positive and large', () => {
  const xs = [10, 12, 11, 13, 10, 12, 900];
  ok(S.zscore(900, xs) > 2, 'outlier should exceed 2 sigma');
});
t('stddev of a constant series is 0 and z-score does not divide by zero', () => {
  eq(S.stddev([5, 5, 5]), 0); eq(S.zscore(5, [5, 5, 5]), 0);
});

/* ── defanging ─────────────────────────────────────────────────────── */
t('refangs bracketed dots', () => eq(S.refang('evil[.]com'), 'evil.com'));
t('refangs hxxp scheme', () => eq(S.refang('hxxps://bad[.]tld/a'), 'https://bad.tld/a'));
t('refangs bracketed colon', () => eq(S.refang('1.2.3.4[:]8080'), '1.2.3.4:8080'));
t('leaves clean text untouched', () => eq(S.refang('https://example.com/x'), 'https://example.com/x'));

t('prose "observed at domain" does not become an email address', () => {
  const r = S.extract('Redirector observed at kq7vbnxmzwrp[.]xyz');
  notOk(r.indicators.some((i) => i.type === 'email'), JSON.stringify(r.indicators));
  ok(r.indicators.some((i) => i.type === 'domain' && i.value === 'kq7vbnxmzwrp.xyz'));
});
t('bracketed at-form still refangs', () => {
  eq(S.refang('billing[at]evil.top'), 'billing@evil.top');
});
t('bracketed dot-form still refangs', () => {
  eq(S.refang('evil[dot]top'), 'evil.top');
  eq(S.refang('evil dot top'), 'evil.top');
});
t('prose containing the word "at" is left alone', () => {
  eq(S.refang('the payload was staged at 09:00'), 'the payload was staged at 09:00');
});
t('repeated filtered values are reported once with a count', () => {
  const r = S.extract('203.0.113.9 203.0.113.9 203.0.113.9');
  const d = r.dropped.filter((x) => x.value === '203.0.113.9');
  eq(d.length, 1);
  eq(d[0].count, 3);
});

/* ── IP classification: RFC-defined, not opinion ───────────────────── */
t('RFC1918 10/8 is private', () => eq(S.ipClassify('10.1.2.3').scope, 'RFC1918 private'));
t('RFC1918 172.16/12 lower bound is private', () => eq(S.ipClassify('172.16.0.1').scope, 'RFC1918 private'));
t('172.32.0.1 is outside RFC1918 and routable', () => ok(S.ipClassify('172.32.0.1').routable));
t('192.168/16 is private', () => notOk(S.ipClassify('192.168.1.1').routable));
t('127/8 is loopback', () => eq(S.ipClassify('127.0.0.1').scope, 'loopback'));
t('169.254/16 is link-local', () => eq(S.ipClassify('169.254.1.1').scope, 'link-local'));
t('100.64/10 is CGNAT', () => eq(S.ipClassify('100.64.0.1').scope, 'CGNAT (RFC6598)'));
t('203.0.113/24 is TEST-NET-3 documentation space', () => notOk(S.ipClassify('203.0.113.9').routable));
t('224/4 is multicast', () => eq(S.ipClassify('239.255.255.250').scope, 'multicast'));
t('a real public address is routable', () => ok(S.ipClassify('45.155.205.233').routable));
t('malformed address is rejected', () => notOk(S.ipClassify('999.1.1.1').valid));

/* ── extraction ────────────────────────────────────────────────────── */
t('extracts every indicator type from one report', () => {
  const text = `Actor used hxxp://cdn-update[.]top/payload.exe hosted on 45[.]155[.]205[.]233.
  Dropper hash a83f2e9c7b41d5f0e2a1b7c4d9e0f3a2b5c8d1e4f7a0b3c6d9e2f5a8b1c4d02e.
  Phishing from billing@secure-verify[.]xyz exploiting CVE-2026-3155.`;
  const r = S.extract(text);
  const types = r.indicators.reduce((a, i) => (a[i.type] = (a[i.type] || 0) + 1, a), {});
  ok(types.url >= 1, 'url'); ok(types.ipv4 >= 1, 'ipv4'); ok(types.sha256 >= 1, 'sha256');
  ok(types.email >= 1, 'email'); ok(types.cve >= 1, 'cve'); ok(types.domain >= 1, 'domain');
});
t('drops RFC1918 addresses with a stated reason', () => {
  const r = S.extract('internal host 10.10.4.82 talked to 45.155.205.233');
  ok(r.dropped.some((d) => d.value === '10.10.4.82' && /RFC1918/.test(d.reason)));
  ok(r.indicators.some((i) => i.value === '45.155.205.233'));
});
t('does not treat a filename as a domain', () => {
  const r = S.extract('see report.pdf and config.json for details');
  notOk(r.indicators.some((i) => i.type === 'domain'));
  ok(r.dropped.some((d) => /not a recognised TLD/.test(d.reason)));
});
t('drops known-benign infrastructure', () => {
  const r = S.extract('downloaded from github.com and microsoft.com');
  notOk(r.indicators.some((i) => i.type === 'domain'));
});
t('deduplicates repeats and counts them', () => {
  const r = S.extract('evil.top evil.top evil.top');
  const d = r.indicators.find((i) => i.value === 'evil.top');
  eq(d.count, 3);
});
t('a URL host is not double-counted as a loose domain', () => {
  const r = S.extract('https://bad-domain.xyz/path');
  const domains = r.indicators.filter((i) => i.type === 'domain');
  eq(domains.length, 1);
  eq(domains[0].value, 'bad-domain.xyz');
});
t('SHA-1 is not misread as part of a SHA-256', () => {
  const sha1 = 'a'.repeat(40);
  const r = S.extract('hash ' + sha1);
  ok(r.indicators.some((i) => i.type === 'sha1' && i.value === sha1));
});

/* ── DGA scoring: relative ordering is the contract ─────────────────── */
t('an algorithmic label scores higher than a natural word', () => {
  const dga = S.dgaScore('xkqjvbzrwmpl').score;
  const word = S.dgaScore('newsletter').score;
  ok(dga > word, 'dga ' + dga + ' should exceed ' + word);
});
t('random-looking label with digits scores high', () => ok(S.dgaScore('a7f3k9zqx2vm').score > 0.5));
t('common English word scores low', () => ok(S.dgaScore('marketing').score < 0.5));
t('short labels are not scored', () => eq(S.dgaScore('cdn').score, 0));
t('DGA scoring is deterministic across calls', () => {
  eq(S.dgaScore('kqwzvxbnrm').score, S.dgaScore('kqwzvxbnrm').score);
});
t('every DGA component is returned for explainability', () => {
  const keys = S.dgaScore('kqwzvxbnrm').components.map((c) => c.key);
  eq(keys, ['entropy', 'bigrams', 'consonantRun', 'digitRatio', 'vowelRatio']);
});

/* ── homograph and keyword detection ───────────────────────────────── */
t('detects punycode labels', () => ok(S.homograph('xn--pple-43d.com').length > 0));
t('detects Cyrillic lookalike characters', () => ok(S.homograph('аpple.com').some((f) => /lookalike/.test(f))));
t('clean ASCII domain raises no homograph flags', () => eq(S.homograph('cleandomain.com').length, 0));
t('finds credential-theft vocabulary', () => {
  const hits = S.keywordHits('secure-login-verify.net');
  ok(hits.includes('secure') && hits.includes('login') && hits.includes('verify'));
});

/* ── URL / hash / CVE parsing ──────────────────────────────────────── */
t('flags an executable extension over cleartext', () => {
  const u = S.urlInfo('http://x.top/a/payload.exe');
  ok(u.riskyExtension); eq(u.scheme, 'http');
});
t('detects a bare IP host and non-standard port', () => {
  const u = S.urlInfo('http://45.155.205.233:8080/x');
  ok(u.ipHost); ok(u.nonStandardPort); eq(u.port, '8080');
});
t('detects credentials embedded in a URL', () => ok(S.urlInfo('http://user:pw@host.top/').hasCredentials));
t('identifies hash algorithms by length', () => {
  eq(S.hashInfo('a'.repeat(32)).algorithm, 'MD5');
  eq(S.hashInfo('a'.repeat(40)).algorithm, 'SHA-1');
  eq(S.hashInfo('a'.repeat(64)).algorithm, 'SHA-256');
});
t('rejects an implausible CVE year', () => notOk(S.cveInfo('CVE-1990-0001').plausible));
t('accepts a plausible CVE', () => ok(S.cveInfo('CVE-2026-3155').plausible));

/* ── scoring ───────────────────────────────────────────────────────── */
t('a hostile domain outscores a bland one', () => {
  const bad = S.scoreIndicator({ type: 'domain', value: 'secure-login-verify.top' }, { source: 'report' });
  const dull = S.scoreIndicator({ type: 'domain', value: 'quarterly-results.com' }, { source: 'report' });
  ok(bad.risk > dull.risk, bad.risk + ' should exceed ' + dull.risk);
});
t('scoring is deterministic', () => {
  const a = S.scoreIndicator({ type: 'domain', value: 'x-verify-portal.xyz' }, { source: 'report' });
  const b = S.scoreIndicator({ type: 'domain', value: 'x-verify-portal.xyz' }, { source: 'report' });
  eq(a.risk, b.risk); eq(a.confidence, b.confidence);
});
t('risk stays inside 0-100 for extreme input', () => {
  const s = S.scoreIndicator({ type: 'url', value: 'http://u:p@45.155.205.233:8080/' + 'a'.repeat(200) + '/x.exe' },
                             { source: 'feed:high-confidence', sightings: 500 });
  ok(s.risk >= 0 && s.risk <= 100, 'risk ' + s.risk);
  ok(s.confidence >= 0 && s.confidence <= 100);
});
t('every point of risk is attributed to a named factor', () => {
  const s = S.scoreIndicator({ type: 'domain', value: 'login-secure.top' }, { source: 'report' });
  const sum = s.factors.reduce((a, f) => a + f.delta, 0);
  eq(S.clamp(Math.round(sum), 0, 100), s.risk);
});
t('severity bands map to the documented thresholds', () => {
  eq(S.severityFor(85), 'critical'); eq(S.severityFor(84), 'high');
  eq(S.severityFor(65), 'high'); eq(S.severityFor(64), 'medium');
  eq(S.severityFor(40), 'medium'); eq(S.severityFor(39), 'low');
});
t('more sightings raise confidence', () => {
  const one = S.scoreIndicator({ type: 'domain', value: 'a-portal.xyz' }, { sightings: 1 });
  const many = S.scoreIndicator({ type: 'domain', value: 'a-portal.xyz' }, { sightings: 20 });
  ok(many.confidence > one.confidence);
});
t('confidence halves after 30 days without a sighting', () => {
  const now = Date.now();
  eq(S.decayConfidence(80, now - 30 * 86400000, now), 40);
  eq(S.decayConfidence(80, now, now), 80);
});

/* ── rule engine ───────────────────────────────────────────────────── */
t('tokenizes a compound expression', () => {
  eq(S.tokenize('dga > 0.6 and tld_risk > 0.5'), ['dga', '>', '0.6', 'and', 'tld_risk', '>', '0.5']);
});
t('evaluates conjunction correctly', () => {
  const ast = S.parseRule('dga > 0.6 and tld_risk > 0.5');
  ok(S.evalRule(ast, { dga: 0.8, tld_risk: 0.9 }));
  notOk(S.evalRule(ast, { dga: 0.8, tld_risk: 0.2 }));
});
t('evaluates disjunction and negation', () => {
  ok(S.evalRule(S.parseRule('a > 1 or b > 1'), { a: 0, b: 5 }));
  ok(S.evalRule(S.parseRule('not a > 1'), { a: 0 }));
});
t('respects parentheses over default precedence', () => {
  const ctx = { a: 1, b: 0, c: 0 };
  notOk(S.evalRule(S.parseRule('(a > 0 or b > 0) and c > 0'), ctx));
  ok(S.evalRule(S.parseRule('a > 0 or (b > 0 and c > 0)'), ctx));
});
t('and binds tighter than or', () => {
  ok(S.evalRule(S.parseRule('a > 0 or b > 0 and c > 0'), { a: 1, b: 0, c: 0 }));
});
t('supports string equality and regex match', () => {
  ok(S.evalRule(S.parseRule('type == "domain"'), { type: 'domain' }));
  ok(S.evalRule(S.parseRule('value =~ /login/'), { value: 'secure-login.top' }));
  notOk(S.evalRule(S.parseRule('value =~ /login/'), { value: 'benign.com' }));
});
t('a missing field evaluates false rather than throwing', () => {
  notOk(S.evalRule(S.parseRule('nonexistent > 1'), {}));
});
t('rejects malformed expressions with a useful message', () => {
  let msg = '';
  try { S.parseRule('dga > '); } catch (e) { msg = e.message; }
  ok(/Unexpected end/.test(msg), 'got: ' + msg);
});
t('rejects unbalanced parentheses', () => {
  let threw = false;
  try { S.parseRule('(a > 1'); } catch (e) { threw = true; }
  ok(threw);
});
t('never uses eval or Function', () => {
  const src = require('fs').readFileSync(path.join(__dirname, '..', '..', 'engine', 'engine.js'), 'utf8');
  notOk(/\beval\s*\(/.test(src), 'engine must not call eval');
  notOk(/new\s+Function\s*\(/.test(src), 'engine must not construct Functions');
});
t('shipped rules all parse', () => {
  S.DEFAULT_RULES.forEach((r) => { S.parseRule(r.expr); });
});
t('rules fire against real extracted indicators', () => {
  const r = S.extract('hxxp://secure-login-verify[.]top/update.exe');
  const scores = r.indicators.map((i) => S.scoreIndicator(i, { source: 'report' }));
  const alerts = S.runRules(S.DEFAULT_RULES, r.indicators, scores);
  ok(alerts.length > 0, 'expected at least one alert');
  ok(alerts.every((a) => a.reasons && a.reasons.length), 'every alert must carry its reasons');
});
t('disabled rules do not fire', () => {
  const r = S.extract('secure-login-verify.top');
  const scores = r.indicators.map((i) => S.scoreIndicator(i));
  const off = S.DEFAULT_RULES.map((x) => ({ ...x, enabled: false }));
  eq(S.runRules(off, r.indicators, scores).length, 0);
});

/* ── log parsing and behavioural analysis ──────────────────────────── */
const SSH_LOG = `Oct 10 13:55:36 web01 sshd[2311]: Failed password for invalid user admin from 203.0.113.9 port 51122 ssh2
Oct 10 13:55:41 web01 sshd[2312]: Failed password for invalid user root from 203.0.113.9 port 51124 ssh2
Oct 10 13:55:47 web01 sshd[2313]: Failed password for invalid user test from 203.0.113.9 port 51126 ssh2
Oct 10 13:56:02 web01 sshd[2314]: Failed password for invalid user oracle from 203.0.113.9 port 51130 ssh2
Oct 10 13:56:19 web01 sshd[2315]: Failed password for invalid user backup from 203.0.113.9 port 51133 ssh2
Oct 10 13:58:41 web01 sshd[2320]: Accepted password for deploy from 10.10.0.14 port 51140 ssh2`;

t('parses syslog sshd lines', () => {
  const p = S.parseLogs(SSH_LOG);
  eq(p.events.length, 6);
  eq(p.unparsed.length, 0);
  eq(p.events[0].type, 'AUTH');
  eq(p.events[0].outcome, 'failure');
  eq(p.events[0].src, '203.0.113.9');
});
t('detects brute force within a real 4-minute window', () => {
  const p = S.parseLogs(SSH_LOG);
  const a = S.analyseEvents(p.events);
  ok(a.bruteForce.some((b) => b.ip === '203.0.113.9' && b.count >= 5), JSON.stringify(a.bruteForce));
});
t('does not flag brute force below threshold', () => {
  const two = SSH_LOG.split('\n').slice(0, 2).join('\n');
  const a = S.analyseEvents(S.parseLogs(two).events);
  eq(a.bruteForce.length, 0);
});
t('parses combined web log format including bytes', () => {
  const line = '203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 512';
  const p = S.parseLogs(line);
  eq(p.events.length, 1);
  eq(p.events[0].type, 'HTTP');
  eq(p.events[0].status, 404);
  eq(p.events[0].bytesOut, 512);
  ok(p.events[0].ts > 0, 'timestamp must parse');
});
t('parses JSON lines', () => {
  const p = S.parseLogs('{"timestamp":"2026-10-10T13:55:36Z","event_type":"NETWORK","src_ip":"10.10.4.82","dst_ip":"45.155.205.233","bytes_out":43200000}');
  eq(p.events.length, 1);
  eq(p.events[0].bytesOut, 43200000);
});
t('reports unparsable lines instead of dropping them', () => {
  const p = S.parseLogs('this line is not a log entry at all');
  eq(p.events.length, 0);
  eq(p.unparsed.length, 1);
});
t('flags an outbound transfer that is a real statistical outlier', () => {
  const rows = [];
  for (let i = 0; i < 20; i++) rows.push(`2026-10-10T10:${String(i).padStart(2,'0')}:00,10.10.4.82,93.184.216.34,${12000 + i * 90},400`);
  rows.push('2026-10-10T10:21:00,10.10.4.82,45.155.205.233,43200000,900');
  const p = S.parseLogs(rows.join('\n'));
  const a = S.analyseEvents(p.events);
  ok(a.transfers.length >= 1, 'expected an outlier');
  eq(a.transfers[0].dst, '45.155.205.233');
  ok(a.transfers[0].z > 3, 'z=' + a.transfers[0].z);
});
t('refuses to report a z-score finding without a real baseline', () => {
  const rows = ['2026-10-10T10:00:00,10.0.0.1,93.184.216.34,12000,400',
                '2026-10-10T10:01:00,10.0.0.1,93.184.216.34,12500,400',
                '2026-10-10T10:02:00,10.0.0.1,45.155.205.233,43200000,900'];
  const a = S.analyseEvents(S.parseLogs(rows.join('\n')).events);
  eq(a.transfers.length, 0, 'three samples is not a baseline');
  eq(a.stats.baselineSufficient, false);
});
t('reports the baseline sample count so the analyst can judge it', () => {
  const a = S.analyseEvents(S.parseLogs('{"src_ip":"1.1.1.1","bytes_out":10}').events);
  eq(a.stats.baselineSamples, 1);
});
t('event rules produce alerts carrying their evidence', () => {
  const a = S.analyseEvents(S.parseLogs(SSH_LOG).events);
  const alerts = S.runEventRules(a);
  ok(alerts.length >= 1);
  ok(/failed authentications/.test(alerts[0].reasons[0]));
});

/* ── graph ─────────────────────────────────────────────────────────── */
t('graph links a URL to its host', () => {
  const r = S.extract('https://cdn-update.top/a.exe');
  const g = S.buildGraph(r.indicators, []);
  ok(g.edges.some((e) => e.rel === 'hosted_on'));
});
t('graph links observed source and destination', () => {
  const p = S.parseLogs('{"timestamp":"2026-10-10T10:00:00Z","event_type":"NETWORK","src_ip":"10.10.4.82","dst_ip":"45.155.205.233","bytes_out":100}');
  const g = S.buildGraph([], p.events);
  ok(g.edges.some((e) => e.src === '10.10.4.82' && e.dst === '45.155.205.233'));
});
t('graph has no duplicate edges', () => {
  const p = S.parseLogs(['{"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","event_type":"NETWORK"}',
                         '{"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","event_type":"NETWORK"}'].join('\n'));
  const g = S.buildGraph([], p.events);
  eq(g.edges.length, 1);
});

/* ── exports ───────────────────────────────────────────────────────── */
t('produces a structurally valid STIX 2.1 bundle', () => {
  const b = S.toStix([{ type: 'domain', value: 'cdn-update.top', risk: 90, confidence: 80, severity: 'critical', factors: [] }]);
  eq(b.type, 'bundle');
  const ind = b.objects.find((o) => o.type === 'indicator');
  eq(ind.pattern, "[domain-name:value = 'cdn-update.top']");
  eq(ind.spec_version, '2.1');
  ok(/^indicator--[0-9a-f-]{36}$/.test(ind.id), ind.id);
});
t('STIX ids are stable for the same indicator', () => {
  const one = S.toStix([{ type: 'domain', value: 'a.top', risk: 1, confidence: 1, severity: 'low', factors: [] }]);
  const two = S.toStix([{ type: 'domain', value: 'a.top', risk: 1, confidence: 1, severity: 'low', factors: [] }]);
  eq(one.objects[1].id, two.objects[1].id);
});
t('CSV escapes quotes and commas', () => {
  const csv = S.toCsv([{ a: 'x,y', b: 'say "hi"' }], ['a', 'b']);
  eq(csv, 'a,b\n"x,y","say ""hi"""');
});
t('formats byte sizes', () => { eq(S.formatBytes(1024), '1 KB'); eq(S.formatBytes(43200000), '41.2 MB'); });

/* ── report ────────────────────────────────────────────────────────── */
const width = Math.max(...results.map((r) => r[1].length)) + 2;
results.forEach(([status, name, msg]) => {
  const line = (status === 'PASS' ? '  ok   ' : '  FAIL ') + name.padEnd(width) + (msg || '');
  if (status === 'FAIL' || process.env.VERBOSE) console.log(line);
});
console.log('\n' + pass + ' passed, ' + fail + ' failed, ' + (pass + fail) + ' total');
if (typeof module !== 'undefined' && require.main === module) process.exit(fail ? 1 : 0);
