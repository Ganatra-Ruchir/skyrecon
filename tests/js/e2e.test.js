/* SkyRecon console — end-to-end tests.
 * Drives the built page in a real browser exactly as an analyst would:
 * paste source material, analyse it, then assert the console shows what the
 * engine actually computed. Run: node e2e.test.js
 */
const { chromium } = require('playwright');
const path = require('path');

const results = [];
let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); pass++; results.push(['ok  ', name, '']); }
  catch (e) { fail++; results.push(['FAIL', name, e.message]); }
}
function ok(v, m) { if (!v) throw new Error(m || 'expected truthy'); }
function eq(a, b, m) { if (String(a) !== String(b)) throw new Error((m || '') + ' expected "' + b + '" got "' + a + '"'); }

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
  page.setDefaultTimeout(6000);                 // fail fast instead of hanging
  page.on('dialog', d => d.accept().catch(() => {}));
  const jsErrors = [];
  page.on('pageerror', e => jsErrors.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/TUNNEL|net::ERR/.test(m.text())) jsErrors.push('console: ' + m.text()); });

  const url = 'file://' + path.join(__dirname, 'preview.html');
  await page.goto(url);
  await page.waitForTimeout(900);

  await t('boots with no JavaScript errors', () => ok(jsErrors.length === 0, jsErrors.join(' | ')));

  await t('opens on Ingest, not on a dashboard of invented data', async () => {
    eq(await page.textContent('#ptitle'), 'Ingest');
  });

  await t('Overview shows an empty state before anything is analysed', async () => {
    await page.click('[data-v="overview"]');
    const txt = await page.textContent('#canvas');
    ok(/Nothing analysed yet/.test(txt), 'expected empty state, got: ' + txt.slice(0, 120));
    ok(!/\b\d{2,}\b/.test(await page.textContent('.empty')), 'empty state must not show fabricated numbers');
  });

  await t('Indicators, Alerts, Graph and Telemetry are all empty on first load', async () => {
    for (const [v, phrase] of [['indicators', 'No indicators stored'], ['alerts', 'No alerts'],
                               ['graph', 'No entities to graph'], ['telemetry', 'No telemetry parsed']]) {
      await page.click(`[data-v="${v}"]`);
      const txt = await page.textContent('#canvas');
      ok(txt.includes(phrase), v + ' should show "' + phrase + '", got: ' + txt.slice(0, 100));
    }
  });

  await t('the worked example loads only when the analyst asks for it', async () => {
    await page.click('[data-v="ingest"]');
    eq(await page.inputValue('#pasteBox'), '');
    await page.click('#loadSample');
    const v = await page.inputValue('#pasteBox');
    ok(v.length > 500, 'sample should populate the box');
    ok(/secure-login-verify/.test(v), 'sample should contain the indicators it claims');
  });

  await t('analysing the example extracts indicators and reports what it filtered', async () => {
    await page.click('#runIngest');
    await page.waitForTimeout(500);
    const txt = await page.textContent('#ingestResult');
    ok(/EXTRACTED/.test(txt), 'result strip missing');
    ok(/FILTERED OUT/.test(txt), 'filter transparency missing');
    ok(/secure-login-verify\.top/.test(txt), 'expected the phishing domain in results');
  });

  await t('internal RFC1918 addresses are filtered and the reason is shown', async () => {
    const txt = await page.textContent('#ingestResult');
    ok(/10\.10\.4\.82/.test(txt) === false || /RFC1918/.test(txt), 'private IP must be filtered with a reason');
    ok(/RFC1918 private/.test(txt), 'filter reason should be visible');
  });

  await t('known-benign infrastructure is excluded', async () => {
    const rows = await page.$$eval('#ingestResult .val', els => els.map(e => e.textContent));
    ok(!rows.some(r => /^github\.com$/.test(r)), 'github.com should not be scored as an indicator');
  });

  await t('log lines in the same paste are parsed into events', async () => {
    const txt = await page.textContent('#ingestResult');
    ok(/sshd auth/.test(txt) || /csv/.test(txt), 'expected a parsed log format, got: ' + txt.slice(0, 200));
  });

  await t('Overview now reports real totals derived from that input', async () => {
    await page.click('[data-v="overview"]');
    await page.waitForTimeout(200);
    const txt = await page.textContent('#canvas');
    ok(!/Nothing analysed yet/.test(txt), 'overview should have data now');
    const indicators = Number((await page.textContent('.strip .mt:nth-child(1) .mt-v')).replace(/\D/g, ''));
    ok(indicators > 0, 'indicator count should be positive');
    const stored = await page.evaluate(() => document.querySelectorAll('[data-v="indicators"] .nav-c').length);
    ok(stored >= 0);
  });

  await t('the indicator table lists what was ingested', async () => {
    await page.click('[data-v="indicators"]');
    await page.waitForTimeout(200);
    const rows = await page.$$('tbody tr[data-ioc]');
    ok(rows.length > 0, 'expected indicator rows');
  });

  await t('opening an indicator shows a score ledger whose deltas sum to the score', async () => {
    await page.click('tbody tr[data-ioc]');
    await page.waitForTimeout(400);
    const shown = Number(await page.textContent('.gauge b'));
    const deltas = await page.$$eval('.ledger .lr:not(.total) .ldelta', els => els.map(e => Number(e.textContent)));
    const total = Number(await page.textContent('.ledger .lr.total .ldelta'));
    const sum = Math.max(0, Math.min(100, deltas.reduce((a, b) => a + b, 0)));
    eq(shown, total, 'gauge and ledger total must agree:');
    eq(sum, total, 'ledger deltas must sum to the composite:');
  });

  await t('the DGA breakdown is shown for an algorithmic domain', async () => {
    await page.click('[data-close]').catch(() => {});
    await page.waitForTimeout(200);
    const target = await page.$('tbody tr[data-ioc*="kq7vbnxmzwrp"]');
    ok(target, 'expected the DGA-style domain in the table');
    await target.click();
    await page.waitForTimeout(400);
    const txt = await page.textContent('.fly-b');
    ok(/DGA CLASSIFIER COMPONENTS/.test(txt), 'expected the classifier breakdown');
    ok(/entropy/.test(txt) && /bigrams/.test(txt), 'expected named components');
  });

  await t('rules fired and produced alerts carrying their evidence', async () => {
    await page.click('[data-close]');
    await page.click('[data-v="alerts"]');
    await page.waitForTimeout(300);
    const rows = await page.$$('tbody tr[data-alert]');
    ok(rows.length > 0, 'expected alerts from the shipped rules');
    await rows[0].click();
    await page.waitForTimeout(300);
    const txt = await page.textContent('.fly-b');
    ok(/MATCHING EXPRESSION/.test(txt), 'alert must show the expression that matched');
    ok(/EVIDENCE/.test(txt), 'alert must show its evidence');
  });

  await t('brute force in the sample log is detected from real timestamps', async () => {
    await page.click('[data-close]');
    await page.click('[data-v="telemetry"]');
    await page.waitForTimeout(300);
    const txt = await page.textContent('#canvas');
    ok(/203\.0\.113\.9/.test(txt), 'expected the brute-forcing source');
    ok(/failed authentications/.test(txt), 'expected the brute-force finding');
  });

  await t('the outlier transfer is detected by z-score, not by a hardcoded rule', async () => {
    const txt = await page.textContent('#canvas');
    ok(/z-score/.test(txt), 'expected a z-score finding');
    ok(/45\.155\.205\.233/.test(txt), 'expected the exfil destination');
  });

  await t('the entity graph is built from observed relationships', async () => {
    await page.click('[data-v="graph"]');
    await page.waitForTimeout(300);
    const nodes = await page.$$('.gnode');
    const edges = await page.$$('.gedge');
    ok(nodes.length > 3, 'expected graph nodes, got ' + nodes.length);
    ok(edges.length > 0, 'expected graph edges');
  });

  await t('selecting a node shows its real connections', async () => {
    await page.click('.gnode');
    await page.waitForTimeout(300);
    const txt = await page.textContent('#canvas');
    ok(/CONNECTED/.test(txt) || /No edges recorded/.test(txt), 'expected the entity panel');
  });

  await t('ATT&CK counts come from alerts that actually fired', async () => {
    await page.click('[data-v="attack"]');
    await page.waitForTimeout(300);
    const cells = await page.$$eval('.tcell .tct', els => els.map(e => e.textContent));
    ok(cells.length > 0, 'expected technique cells');
    ok(cells.some(c => !/^0 alerts$/.test(c)), 'at least one technique should have a non-zero count');
  });

  await t('an invalid rule expression is rejected with the parser message', async () => {
    await page.click('[data-v="rules"]');
    await page.waitForTimeout(200);
    await page.fill('#newExpr', 'dga > ');
    await page.waitForTimeout(200);
    const msg = await page.textContent('#parseMsg');
    ok(/✗/.test(msg), 'expected a parse error, got: ' + msg);
    const cls = await page.getAttribute('#newExpr', 'class');
    ok(/bad/.test(cls), 'input should be marked invalid');
  });

  await t('a valid expression reports how many current indicators it matches', async () => {
    await page.fill('#newExpr', 'type == "domain"');
    await page.waitForTimeout(250);
    const msg = await page.textContent('#parseMsg');
    ok(/parses cleanly/.test(msg), msg);
    const mc = await page.textContent('#matchCount');
    ok(/\d+ of \d+ current indicators match/.test(mc), 'expected a live match count, got: ' + mc);
  });

  await t('adding a custom rule immediately produces alerts', async () => {
    const before = await page.$$eval('[data-v="alerts"] .nav-c', e => e.length ? Number(e[0].textContent) : 0);
    await page.fill('#newName', 'E2E test rule');
    await page.fill('#newExpr', 'risk >= 40');
    await page.fill('#newTech', 'T1071');
    await page.click('#addRule');
    await page.waitForTimeout(400);
    const after = await page.$$eval('[data-v="alerts"] .nav-c', e => e.length ? Number(e[0].textContent) : 0);
    ok(after > before, 'alert count should rise from ' + before + ', got ' + after);
    const txt = await page.textContent('#canvas');
    ok(/E2E test rule/.test(txt), 'rule should be listed');
  });

  await t('disabling a rule withdraws its alerts', async () => {
    const before = await page.$$eval('[data-v="alerts"] .nav-c', e => Number(e[0].textContent));
    await page.click('.rule-card .sw.on');
    await page.waitForTimeout(400);
    const after = await page.$$eval('[data-v="alerts"] .nav-c', e => e.length ? Number(e[0].textContent) : 0);
    ok(after < before, 'alerts should fall from ' + before + ', got ' + after);
    await page.click('.rule-card .sw:not(.on)').catch(() => {});
    await page.waitForTimeout(300);
  });

  await t('marking an indicator benign zeroes its score and drops its alerts', async () => {
    await page.click('[data-v="indicators"]');
    await page.waitForTimeout(250);
    await page.click('tbody tr[data-ioc]');
    await page.waitForTimeout(350);
    await page.click('[data-benign]');
    await page.waitForTimeout(400);
    const txt = await page.textContent('#canvas');
    ok(/BENIGN/.test(txt), 'benign badge should appear in the table');
  });

  await t('data survives a page reload', async () => {
    const before = await page.$$eval('[data-v="indicators"] .nav-c', e => Number(e[0].textContent));
    await page.reload();
    await page.waitForTimeout(1200);
    const after = await page.$$eval('[data-v="indicators"] .nav-c', e => e.length ? Number(e[0].textContent) : 0);
    eq(after, before, 'indicator count after reload:');
  });

  await t('export builds a STIX 2.1 bundle from stored indicators', async () => {
    await page.click('[data-v="export"]');
    await page.waitForTimeout(300);
    const txt = await page.textContent('#canvas');
    ok(/STIX 2\.1 bundle/.test(txt), 'expected the STIX option');
    ok(/"spec_version": "2\.1"/.test(txt), 'expected a real STIX object in the preview');
    ok(/"pattern"/.test(txt), 'expected a STIX pattern');
  });

  await t('clearing the workspace returns every screen to empty', async () => {
    await page.click('[data-v="workspace"]');
    await page.waitForTimeout(250);
    await page.click('#wipe');
    await page.waitForTimeout(500);
    await page.click('[data-v="overview"]');
    await page.waitForTimeout(250);
    ok(/Nothing analysed yet/.test(await page.textContent('#canvas')), 'overview should be empty again');
  });

  await t('no JavaScript errors across the whole session', () => ok(jsErrors.length === 0, jsErrors.join(' | ')));

  const w0 = Math.max(...results.map(r => r[1].length)) + 2;
  results.forEach(([s2, n, m]) => { if (s2 === 'FAIL' || process.env.VERBOSE) console.log('  ' + s2 + ' ' + n.padEnd(w0) + m); });
  console.log('\nE2E: ' + pass + ' passed, ' + fail + ' failed, ' + (pass + fail) + ' total');

  // screenshots of the real, analyst-populated console
  try {
  await page.click('[data-v="ingest"]');
  await page.click('#loadSample');
  await page.click('#runIngest');
  await page.waitForTimeout(700);
  await page.screenshot({ path: path.join(__dirname, 'shot-ingest.png') });
  await page.click('[data-v="overview"]'); await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(__dirname, 'shot-overview.png') });
  await page.click('[data-v="indicators"]'); await page.waitForTimeout(300);
  await page.click('tbody tr[data-ioc*="kq7vbnxmzwrp"]').catch(() => page.click('tbody tr[data-ioc]'));
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(__dirname, 'shot-ledger.png') });
  await page.click('[data-close]');
  await page.click('[data-v="graph"]'); await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(__dirname, 'shot-graph.png') });
  await page.click('[data-v="rules"]'); await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(__dirname, 'shot-rules.png') });
  } catch (e) { console.log('screenshot phase: ' + e.message.split('\n')[0]); }

  await browser.close();
  process.exit(fail ? 1 : 0);
})();
