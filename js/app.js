import { SPECIALISTS, runSwarm } from './analyzers.js';
import { SAMPLES } from './samples.js';
import { CS_DATA, REF_DATA, SCENARIOS } from './study.js';
import { clearKey, deepAnalyze, hasKey, loadKey, redactSecrets, saveKey } from './deep.js';
import { SIGNUP_URL, TURNSTILE_SITE_KEY, shouldLoadTurnstile, shouldShowSignupForm } from './config.js';
import {
  alertsFromThreats,
  filterAlerts,
  loadAlertState,
  markDone,
  notificationDecision,
  safeHttps,
  saveAlertState,
  unseenCritical,
} from './alerts.js';
import {
  clearWalletKeys,
  detectChainInput,
  explorerLinks,
  flagAccount,
  loadWalletKeys,
  readEtherscan,
  readPublicChain,
  readSolscan,
  saveWalletKeys,
} from './wallet.js';

const VIEWS = ['home', 'swarm', 'alerts', 'threats', 'bots', 'hotfixes', 'wallet', 'study', 'pro', 'more'];
const MORE_VIEWS = new Set(['threats', 'bots', 'hotfixes', 'study', 'pro', 'more']);
let listCache = null;
let alertState = { done: {}, notify: false };
let alertSeverity = 'all';
let notifiedThisSession = false;

const REVEAL_MS = 420;
const DEVICES = [
  ['auto', 'Auto'],
  ['router', 'Router'],
  ['switch', 'Switch'],
  ['firewall', 'Firewall'],
  ['wireless', 'Wireless'],
  ['pc', 'PC'],
];

const paste = document.querySelector('#paste');
const board = document.querySelector('#swarm-board');
const report = document.querySelector('#report');
const statusText = document.querySelector('#status-text');
const devices = document.querySelector('#devices');
const samples = document.querySelector('#samples');
const toast = document.querySelector('#toast');
const settings = document.querySelector('#settings');

let deviceType = 'auto';
let lastText = '';
let runToken = 0;
let timers = [];
let settingValue = false;
let pasteStamp = 0;
let debounce = 0;
let lastResult = null;
let lastSample = null;
let deferredInstall = null;
let statusMessage = 'On this phone';

function el(tag, attrs = {}, kids = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const kid of [].concat(kids)) {
    if (kid == null) continue;
    node.append(kid);
  }
  return node;
}

function showToast(message) {
  toast.textContent = message;
  toast.setAttribute('aria-hidden', 'false');
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.classList.remove('show');
    toast.setAttribute('aria-hidden', 'true');
  }, 2400);
}

async function copyText(text, message = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = el('textarea', { text });
    area.setAttribute('readonly', '');
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  showToast(message);
}

function setStatus(message) {
  statusMessage = message;
  const offline = typeof navigator !== 'undefined' && navigator.onLine === false;
  statusText.textContent = offline ? `Offline · ${message}` : message;
}

function selectDevice(id, { focus = false } = {}) {
  const changed = deviceType !== id;
  deviceType = id;
  paintDevices();
  if (focus) devices.querySelector('.device[aria-checked="true"]')?.focus();
  if (changed && paste.value.trim().length >= 8) {
    lastText = '';
    begin(paste.value, lastSample);
  }
}

function paintDevices() {
  devices.replaceChildren();
  DEVICES.forEach(([id, label], index) => {
    const selected = id === deviceType;
    const button = el('button', {
      type: 'button',
      class: 'device',
      role: 'radio',
      'aria-checked': selected ? 'true' : 'false',
      tabindex: selected ? '0' : '-1',
      text: label,
    });
    button.addEventListener('click', () => selectDevice(id));
    button.addEventListener('keydown', (event) => {
      const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'];
      if (!keys.includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % DEVICES.length;
      else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index + DEVICES.length - 1) % DEVICES.length;
      else if (event.key === 'Home') next = 0;
      else next = DEVICES.length - 1;
      selectDevice(DEVICES[next][0], { focus: true });
    });
    devices.append(button);
  });
}

function paintSamples() {
  samples.replaceChildren();
  for (const sample of SAMPLES) {
    const button = el('button', { type: 'button', class: 'sample' }, [
      el('span', { class: 'badge', text: 'Sample' }),
      el('span', { class: 'sample-title', text: sample.title }),
      el('span', { class: 'sample-blurb', text: sample.blurb }),
    ]);
    button.addEventListener('click', () => loadSample(sample));
    samples.append(button);
  }
}

function clearTimers() {
  timers.forEach((id) => clearTimeout(id));
  timers = [];
}

function later(fn, ms) {
  const id = setTimeout(fn, ms);
  timers.push(id);
}

function showIdle() {
  clearTimers();
  runToken += 1;
  lastText = '';
  lastResult = null;
  lastSample = null;
  report.hidden = true;
  report.replaceChildren();
  board.dataset.revealed = '0';
  board.setAttribute('aria-busy', 'false');
  document.documentElement.dataset.swarm = 'idle';
  setStatus('On this phone');
  const line = el('div', { class: 'coord-line' }, [
    el('strong', { text: 'Coordinator' }),
    el('span', { text: 'Standing by' }),
  ]);
  const grid = el('div', { class: 'bot-grid' });
  for (const spec of SPECIALISTS) {
    grid.append(botCard(spec, { status: 'clear', findings: [] }, 'Standing by'));
  }
  board.replaceChildren(line, grid);
}

function botCard(spec, reportData, statusLabel) {
  const card = el('article', { class: `bot ${reportData.status || 'clear'}`, id: `bot-${spec.id}` });
  const findings = reportData.findings || [];
  const hot = findings.filter((item) => item.severity !== 'info');
  card.append(
    el('div', { class: 'bot-name', text: `${spec.glyph} ${spec.name}` }),
    el('div', { class: 'bot-role', text: spec.role }),
    el('div', { class: 'bot-status', text: statusLabel }),
  );
  if (hot.length) {
    const list = el('ul', { class: 'finding-mini' });
    for (const item of hot.slice(0, 3)) {
      list.append(el('li', { text: item.title }));
    }
    card.append(list);
  }
  return card;
}

function renderScanning() {
  const line = el('div', { class: 'coord-line', id: 'coord-line' }, [
    el('strong', { text: 'Coordinator' }),
    el('span', { text: 'Checking the rules…' }),
  ]);
  const grid = el('div', { class: 'bot-grid' });
  for (const spec of SPECIALISTS) {
    const card = botCard(spec, { status: 'scanning', findings: [] }, 'Reading the paste…');
    card.classList.add('scanning');
    grid.append(card);
  }
  board.replaceChildren(line, grid);
  board.dataset.revealed = '0';
  board.setAttribute('aria-busy', 'true');
}

function revealBot(specReport) {
  const card = document.getElementById(`bot-${specReport.id}`);
  if (!card) return;
  const count = specReport.findings.filter((item) => item.severity !== 'info').length;
  let label = 'Nothing in this paste';
  if (count === 1) label = '1 finding';
  if (count > 1) label = `${count} findings`;
  const fresh = botCard(specReport, specReport, label);
  card.replaceWith(fresh);
}

function loadSample(sample) {
  settingValue = true;
  paste.value = sample.text;
  deviceType = sample.deviceType;
  paintDevices();
  settingValue = false;
  lastText = '';
  begin(sample.text, sample, { scroll: true });
}

function begin(text, sample, { scroll = false } = {}) {
  const trimmed = text.trim();
  if (trimmed.length < 8) {
    if (!trimmed) showIdle();
    return;
  }
  if (trimmed === lastText && sample?.id === lastSample?.id) return;
  lastText = trimmed;
  lastSample = sample;
  const token = ++runToken;
  clearTimers();
  const result = runSwarm(trimmed, { deviceType });
  lastResult = result;
  const typedAtStart = paste.value;
  report.hidden = true;
  document.documentElement.dataset.swarm = 'running';
  setStatus('Reading the paste…');
  renderScanning();
  if (scroll) board.scrollIntoView({ block: 'start' });
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const step = reduce ? 0 : REVEAL_MS;
  result.reports.forEach((item, index) => {
    later(() => {
      if (token !== runToken) return;
      revealBot(item);
      board.dataset.revealed = String(index + 1);
    }, 180 + index * step);
  });
  later(() => {
    if (token !== runToken) return;
    renderReport(result, sample);
    const line = document.getElementById('coord-line');
    if (line) line.querySelector('span').textContent = 'Ranked';
    board.setAttribute('aria-busy', 'false');
    document.documentElement.dataset.swarm = 'done';
    const n = result.summary.actions.length;
    setStatus(n ? `Coordinator ranked ${n} item${n === 1 ? '' : 's'}` : 'Coordinator found nothing definite');
    const stillTyping = document.activeElement === paste && paste.value !== typedAtStart;
    if (scroll && !stillTyping) report.scrollIntoView({ block: 'start' });
  }, 180 + result.reports.length * step + (reduce ? 0 : 240));
}

function renderReport(result, sample) {
  const { summary } = result;
  report.hidden = false;
  const root = el('div', { class: 'report' });
  if (sample) {
    root.append(el('span', { class: 'badge', text: 'Sample data' }));
  }
  root.append(
    el('p', { class: 'kicker', text: 'Coordinator' }),
    el('h2', { text: summary.headline }),
    el('p', { class: 'confidence', text: `${summary.confidenceLabel} confidence · ${summary.confidence}` }),
  );
  const meter = el('div', { class: 'meter', 'aria-hidden': 'true' });
  meter.append(el('span'));
  meter.style.setProperty('--p', String(summary.confidence));
  root.append(meter, el('p', { class: 'narrative', text: summary.narrative }));

  if (summary.provisional) {
    root.append(el('p', { class: 'note', text: 'Working from the symptom only. Paste show output before you change a device.' }));
  }

  summary.actions.slice(0, 8).forEach((item, index) => {
    const block = el('article', { class: `action ${item.severity}` });
    block.append(
      el('p', { class: 'sev', text: `${index + 1} · ${item.severity} · ${item.specialist}` }),
      el('h3', { text: item.title }),
      el('p', { text: item.fix }),
    );
    if (item.evidence?.length) {
      const details = el('details');
      if (index === 0) details.open = true;
      details.append(el('summary', { text: 'Evidence' }));
      details.append(el('pre', { text: item.evidence.join('\n') }));
      block.append(details);
    }
    root.append(block);
  });

  if (summary.notes.length) {
    const note = el('p', { class: 'note', text: `Also noticed: ${summary.notes.map((item) => item.title).join(' ')}` });
    root.append(note);
  }

  const scriptHead = el('div', { class: 'script-head' }, [
    el('h3', { text: 'Fix script' }),
  ]);
  const copyBtn = el('button', { type: 'button', class: 'copy', text: 'Copy fix script' });
  copyBtn.addEventListener('click', () => copyText(summary.script));
  scriptHead.append(copyBtn);
  root.append(scriptHead, el('pre', { text: summary.script }));

  if (summary.followups.length) {
    root.append(el('h3', { text: 'Run this command next' }));
    const row = el('div', { class: 'chip-row' });
    for (const chip of summary.followups) {
      const button = el('button', { type: 'button', class: 'chip', text: chip.cmd });
      button.title = chip.why;
      button.addEventListener('click', () => {
        copyText(chip.cmd, `Copied ${chip.cmd}. Paste the output back.`);
      });
      row.append(button);
    }
    root.append(row);
  }

  const deepRow = el('div', { class: 'deep-row' });
  const deepBtn = el('button', { type: 'button', class: 'deep-btn', text: 'Optional AI analysis with your key' });
  const deepOut = el('div', { class: 'deep-box' });
  deepBtn.addEventListener('click', () => runDeep(deepBtn, deepOut));
  deepRow.append(deepBtn);
  root.append(
    deepRow,
    el('p', { class: 'note', text: 'Optional. AI analysis sends the paste to your provider. The ranked report stays on this device.' }),
    deepOut,
  );
  report.replaceChildren(root);
}

function warnBeforeAi(slot, redacted, changed) {
  slot.replaceChildren(
    el('p', { class: 'note', text: 'This sends the paste to your provider. The ranked report stays on this device.' }),
    el('p', { class: 'note', text: changed
      ? 'Lines with a password, secret, SNMP community, key, or pre-shared-key are replaced with [redacted].'
      : 'No password, secret, or key lines were found. The paste is still sent only to your provider.' }),
  );
  const go = el('button', { type: 'button', class: 'deep-btn', text: 'Send redacted paste' });
  go.addEventListener('click', () => sendDeep(go, slot, redacted));
  slot.append(go);
}

async function runDeep(button, slot) {
  if (!hasKey()) {
    showToast('Add a key in Settings. The ranked report does not need one.');
    settings.showModal();
    return;
  }
  const redacted = redactSecrets(paste.value);
  warnBeforeAi(slot, redacted, redacted !== paste.value);
}

async function sendDeep(button, slot, redacted) {
  const saved = loadKey();
  button.disabled = true;
  slot.replaceChildren(el('p', { text: 'Asking your provider…' }));
  try {
    const text = await deepAnalyze(saved, { text: redacted, summary: lastResult?.summary });
    slot.replaceChildren(el('h3', { text: 'AI analysis' }), el('p', { class: 'deep-text', text }));
  } catch (error) {
    slot.replaceChildren(el('p', { text: error.message || 'AI analysis failed.' }));
  } finally {
    button.disabled = false;
  }
}

async function ensureLists() {
  if (listCache) return listCache;
  const [threats, bots, hotfixes, flags] = await Promise.all([
    fetch('./data/threats.json').then((response) => response.json()),
    fetch('./data/bots.json').then((response) => response.json()),
    fetch('./data/hotfixes.json').then((response) => response.json()),
    fetch('./data/scam-addresses.json').then((response) => response.json()),
  ]);
  listCache = { threats, bots, hotfixes, flags };
  return listCache;
}

function ensureAlertFilters() {
  const bar = document.querySelector('#alert-filters');
  if (bar.childElementCount) return;
  for (const [id, label] of [['all', 'All'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]) {
    const button = el('button', { type: 'button', text: label });
    if (id === alertSeverity) button.classList.add('active');
    button.addEventListener('click', () => {
      alertSeverity = id;
      bar.querySelectorAll('button').forEach((node) => node.classList.toggle('active', node === button));
      paintAlerts();
    });
    bar.append(button);
  }
}

function alertCard(alert) {
  const done = Boolean(alertState.done[alert.id]);
  const card = el('article', { class: done ? 'alert-card done' : 'alert-card' });
  card.append(
    el('span', { class: `sev ${alert.severity}`, text: alert.severity }),
    el('h3', { text: alert.title }),
    el('p', { class: 'meta-line', text: alert.cve || '' }),
    el('p', { text: alert.meaning }),
  );
  const steps = el('ol', { class: 'steps' });
  for (const step of alert.steps || []) steps.append(el('li', { text: step }));
  card.append(steps);
  if (alert.cisaAction) {
    const details = el('details');
    details.append(el('summary', { text: 'CISA required action' }), el('p', { text: alert.cisaAction }));
    card.append(details);
  }
  const advisory = safeHttps(alert.advisory);
  const source = safeHttps(alert.source);
  if (advisory) card.append(el('p', {}, [el('a', { href: advisory, target: '_blank', rel: 'noreferrer', text: 'Vendor advisory' })]));
  if (source && source !== advisory) card.append(el('p', {}, [el('a', { href: source, target: '_blank', rel: 'noreferrer', text: 'Source' })]));
  const button = el('button', { type: 'button', class: 'copy', text: done ? 'Mark as open' : 'Mark as done' });
  button.addEventListener('click', () => {
    alertState = { ...alertState, done: markDone(alertState.done, alert.id, !done) };
    saveAlertState(localStorage, alertState);
    paintAlerts();
  });
  card.append(button);
  return card;
}

async function paintAlerts() {
  ensureAlertFilters();
  const root = document.querySelector('#alert-list');
  root.replaceChildren(el('p', { text: 'Loading alerts…' }));
  try {
    const lists = await ensureLists();
    const alerts = alertsFromThreats(lists.threats.entries);
    const sort = document.querySelector('#alert-sort').checked ? 'newest' : 'severity';
    const visible = filterAlerts(alerts, {
      severity: alertSeverity,
      done: alertState.done,
      showDone: document.querySelector('#alert-show-done').checked,
      sort,
    });
    root.replaceChildren();
    if (!visible.length) {
      root.append(el('p', { text: 'Nothing in this filter.' }));
    } else {
      for (const alert of visible) root.append(alertCard(alert));
    }
    maybeNotify(alerts);
  } catch {
    root.replaceChildren(el('p', { text: 'Alerts could not be loaded. Open this page once while online so the list is saved on the device.' }));
  }
}

function maybeNotify(alerts) {
  const decision = notificationDecision({
    optedIn: alertState.notify,
    permission: typeof Notification === 'undefined' ? 'denied' : Notification.permission,
    hasCritical: unseenCritical(alerts, alertState.done),
  });
  if (!decision.notify || notifiedThisSession || typeof Notification === 'undefined') return;
  notifiedThisSession = true;
  new Notification('StarSwarm', { body: 'A critical alert is still open on this device.' });
}

function entryMatches(entry, query) {
  if (!query) return true;
  return JSON.stringify(entry).toLowerCase().includes(query.toLowerCase());
}

function linkLine(href, label) {
  const safe = safeHttps(href);
  if (!safe) return null;
  return el('p', {}, [el('a', { href: safe, target: '_blank', rel: 'noreferrer', text: label })]);
}

function threatCard(entry) {
  const card = el('article', { class: 'list-card' });
  card.append(
    el('span', { class: `sev ${entry.severity}`, text: entry.severity }),
    el('h3', { text: `${entry.vendor} ${entry.product}` }),
    el('p', { class: 'meta-line', text: `${entry.cve} · added ${entry.dateAdded}` }),
    el('p', { text: entry.description }),
    el('p', { text: entry.fix }),
  );
  const advisory = linkLine(entry.advisory, 'Vendor advisory');
  const source = linkLine(entry.source, 'NVD source');
  if (advisory) card.append(advisory);
  if (source) card.append(source);
  return card;
}

function crawlerCard(entry) {
  const card = el('article', { class: 'list-card' });
  card.append(
    el('h3', { text: entry.name }),
    el('p', { class: 'meta-line', text: entry.kind }),
    el('p', { text: entry.meaning }),
    el('p', { text: 'robots.txt' }),
    el('pre', { class: 'cmd-block', text: entry.block?.robots || '' }),
    el('p', { text: 'Cloudflare WAF expression for your own zone' }),
    el('pre', { class: 'cmd-block', text: entry.block?.cloudflare || '' }),
  );
  const source = linkLine(entry.source, 'Source');
  if (source) card.append(source);
  return card;
}

function hotfixCard(entry) {
  const card = el('article', { class: 'list-card' });
  card.append(
    el('h3', { text: entry.title }),
    el('p', { class: 'meta-line', text: entry.cve ? `${entry.cve} · ${entry.dateAdded}` : `Updated ${entry.updated}` }),
    el('p', { text: entry.fix || entry.detail }),
  );
  const source = linkLine(entry.advisory || entry.source, entry.advisory ? 'Vendor advisory' : 'Source');
  if (source) card.append(source);
  return card;
}

async function paintList(name) {
  const lists = await ensureLists();
  if (name === 'threats') {
    document.querySelector('#threats-meta').textContent = `Updated ${lists.threats.updated}. Catalog ${lists.threats.catalogVersion}. ${lists.threats.entries.length} entries.`;
    fillCards('#threats-list', lists.threats.entries, document.querySelector('#threats-search').value, threatCard);
  } else if (name === 'bots') {
    document.querySelector('#bots-meta').textContent = `Updated ${lists.bots.updated}. ${lists.bots.entries.length} entries. ${lists.bots.note}`;
    fillCards('#bots-list', lists.bots.entries, document.querySelector('#bots-search').value, crawlerCard);
  } else {
    document.querySelector('#hotfixes-meta').textContent = `Updated ${lists.hotfixes.updated}. ${lists.hotfixes.entries.length} advisories and ${lists.hotfixes.checklist.length} checklist items.`;
    const query = document.querySelector('#hotfixes-search').value;
    const root = document.querySelector('#hotfixes-list');
    root.replaceChildren(el('h3', { text: 'Hardening checklist' }));
    for (const item of lists.hotfixes.checklist.filter((entry) => entryMatches(entry, query))) root.append(hotfixCard(item));
    root.append(el('h3', { text: 'Vendor advisories' }));
    for (const item of lists.hotfixes.entries.filter((entry) => entryMatches(entry, query))) root.append(hotfixCard(item));
  }
}

function fillCards(selector, entries, query, render) {
  const root = document.querySelector(selector);
  root.replaceChildren();
  const visible = entries.filter((entry) => entryMatches(entry, query));
  if (!visible.length) {
    root.append(el('p', { text: 'Nothing matches that search.' }));
    return;
  }
  for (const entry of visible) root.append(render(entry));
}

async function checkWallet() {
  const error = document.querySelector('#wallet-error');
  const result = document.querySelector('#wallet-result');
  const detected = detectChainInput(document.querySelector('#wallet-input').value);
  if (!detected.ok) {
    error.hidden = false;
    error.textContent = detected.error;
    result.replaceChildren();
    return;
  }
  error.hidden = true;
  result.replaceChildren(el('p', { text: 'Reading the public chain…' }));
  const summary = el('article', { class: 'list-card' });
  summary.append(el('h3', { text: `${detected.chain === 'evm' ? 'Ethereum' : 'Solana'} ${detected.kind}` }));
  const links = el('div', { class: 'toolbar' });
  for (const link of explorerLinks(detected)) {
    links.append(el('a', { class: 'copy', href: link.href, target: '_blank', rel: 'noreferrer', text: link.label }));
  }
  summary.append(links);
  if (detected.kind === 'tx') {
    result.replaceChildren(summary, el('p', { class: 'note', text: 'Transaction hashes open in the explorer. Balance is checked for addresses.' }));
    return;
  }
  const keys = loadWalletKeys(localStorage);
  let catalog = [];
  try {
    catalog = (await ensureLists()).flags.entries;
  } catch {
    catalog = [];
  }
  const live = await readPublicChain(detected);
  if (live.ok && !live.skipped) {
    summary.append(el('p', { text: `Balance: ${live.balance} ${live.unit}` }));
    if (live.historyNote) summary.append(el('p', { class: 'meta-line', text: live.historyNote }));
  } else if (live.error) {
    summary.append(el('p', { class: 'note', text: live.error }));
  }
  let approvals = [];
  let counterparties = [];
  let transactions = [];
  if (detected.chain === 'evm' && keys.etherscan) {
    const extra = await readEtherscan(detected.value, keys.etherscan);
    if (extra.transactions) {
      transactions = extra.transactions;
      approvals = extra.approvals || [];
      counterparties = extra.counterparties || [];
    } else if (extra.error) summary.append(el('p', { class: 'note', text: extra.error }));
  }
  if (detected.chain === 'solana' && keys.solscan) {
    const extra = await readSolscan(detected.value, keys.solscan);
    if (extra.transactions) {
      transactions = extra.transactions;
      counterparties = extra.counterparties || [];
    } else if (extra.error) summary.append(el('p', { class: 'note', text: extra.error }));
  }
  const flags = flagAccount({
    address: detected.value,
    chain: detected.chain,
    catalog,
    txCount: live.ok ? live.txCount : null,
    approvals,
    counterparties,
  });
  const flagBox = el('div');
  if (!flags.length) {
    flagBox.append(el('p', { text: 'No flag on the public list shipped with this app. That is not proof the address is safe.' }));
  }
  for (const flag of flags) {
    const card = el('article', { class: 'alert-card' });
    card.append(el('span', { class: `sev ${flag.severity}`, text: flag.severity }), el('h3', { text: flag.title }), el('p', { text: flag.meaning }));
    const source = linkLine(flag.href, flag.id === 'unlimited-approval' ? 'Review on revoke.cash' : 'Source');
    if (source) card.append(source);
    flagBox.append(card);
  }
  const txBox = el('div');
  for (const tx of transactions) {
    const href = detected.chain === 'evm' ? `https://etherscan.io/tx/${tx.hash}` : `https://solscan.io/tx/${tx.hash}`;
    const row = el('article', { class: 'list-card' });
    row.append(el('p', { text: tx.hash }));
    if (tx.from) row.append(el('p', { class: 'meta-line', text: `From ${tx.from}` }));
    if (tx.to) row.append(el('p', { class: 'meta-line', text: `To ${tx.to}` }));
    const open = linkLine(href, 'Open transaction');
    if (open) row.append(open);
    txBox.append(row);
  }
  result.replaceChildren(summary, flagBox, txBox);
}

function paintWalletKeys() {
  const saved = loadWalletKeys(localStorage);
  const parts = [];
  if (saved.etherscan) parts.push('Etherscan');
  if (saved.solscan) parts.push('Solscan');
  document.querySelector('#wallet-key-state').textContent = parts.length
    ? `${parts.join(' and ')} key saved in this browser. The fields stay blank.`
    : 'No explorer key saved.';
}

function persistWalletKeys() {
  const existing = loadWalletKeys(localStorage);
  const etherscan = document.querySelector('#etherscan-key').value.trim() || existing.etherscan;
  const solscan = document.querySelector('#solscan-key').value.trim() || existing.solscan;
  if (!etherscan && !solscan) {
    showToast('Paste an explorer key first. The check still runs without one.');
    return;
  }
  saveWalletKeys(localStorage, { etherscan, solscan });
  document.querySelector('#etherscan-key').value = '';
  document.querySelector('#solscan-key').value = '';
  paintWalletKeys();
  showToast('Explorer keys saved on this phone');
}

function showView(name) {
  if (!VIEWS.includes(name)) name = 'home';
  for (const button of document.querySelectorAll('.tab')) {
    const on = button.dataset.view === name;
    button.classList.toggle('active', on);
    button.toggleAttribute('aria-current', on);
  }
  for (const button of document.querySelectorAll('.nav-item')) {
    const on = button.dataset.view === name || (button.dataset.view === 'more' && MORE_VIEWS.has(name));
    button.classList.toggle('active', on);
  }
  for (const view of VIEWS) {
    const node = document.getElementById(`view-${view}`);
    if (node) node.hidden = view !== name;
  }
  history.replaceState(null, '', `#${name}`);
  if (name === 'alerts') paintAlerts();
  if (name === 'threats' || name === 'bots' || name === 'hotfixes') paintList(name);
}

function paintStudy() {
  const ref = document.querySelector('#study-ref');
  const lists = document.querySelector('#study-lists');
  const cards = document.querySelector('#study-cards');
  ref.replaceChildren();
  REF_DATA.forEach((item, index) => {
    const card = el('article', { class: 'ref-card' });
    const bodyId = `ref-body-${index}`;
    const head = el('button', {
      type: 'button',
      class: 'ref-head',
      'aria-expanded': 'false',
      'aria-controls': bodyId,
    }, [
      el('span', { text: item.icon, 'aria-hidden': 'true' }),
      el('span', {}, [
        el('strong', { text: item.title }),
        el('span', { class: 'bot-role', text: item.sub }),
      ]),
    ]);
    const body = el('div', { class: 'ref-body', id: bodyId });
    const tags = el('div', { class: 'tag-row' });
    for (const tag of item.tags) tags.append(el('span', { class: 'tag', text: tag.t }));
    body.append(tags);
    const prose = el('div');
    prose.innerHTML = item.body;
    body.append(prose);
    const cmd = el('pre', { class: 'cmd', text: item.cmd.trim() });
    const copy = el('button', { type: 'button', class: 'copy', text: 'Copy commands' });
    copy.addEventListener('click', (event) => {
      event.stopPropagation();
      copyText(item.cmd.trim());
    });
    body.append(copy, cmd);
    head.addEventListener('click', () => {
      const open = card.classList.toggle('open');
      head.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    card.append(head, body);
    ref.append(card);
  });

  lists.replaceChildren();
  for (const scenario of SCENARIOS) {
    const wrap = el('article', { class: 'pro-card' });
    wrap.append(el('h3', { text: `${scenario.icon} ${scenario.name}` }), el('p', { class: 'note', text: scenario.desc }));
    for (const step of scenario.steps) {
      const row = el('div', { class: 'tstep' });
      const button = el('button', { type: 'button', class: 'step-top' }, [
        el('strong', { text: String(step.n) }),
        el('span', {}, [
          el('span', { text: step.title }),
          el('span', { class: 'bot-role', text: step.desc }),
        ]),
      ]);
      button.addEventListener('click', () => row.classList.toggle('done'));
      row.append(button, el('pre', { text: step.cmd }));
      wrap.append(row);
    }
    lists.append(wrap);
  }

  const grid = el('div', { class: 'cs-grid' });
  for (const card of CS_DATA) {
    const node = el('article', { class: 'cs-card' });
    node.append(el('h3', { text: `${card.icon} ${card.name.replace(/\n/g, ' ')}` }), el('p', { class: 'note', text: card.count }));
    for (const item of card.items) {
      node.append(el('div', { class: 'cs-item' }, [
        el('div', { class: 'cs-key', text: item.k }),
        el('div', { text: item.v }),
      ]));
    }
    grid.append(node);
  }
  cards.replaceChildren(grid);
}

function paintKeyState() {
  const state = document.querySelector('#key-state');
  const saved = loadKey();
  if (!saved) {
    state.textContent = 'No key saved.';
    return;
  }
  state.textContent = `A ${saved.provider} key is saved in this browser. The field stays blank so it is not on screen.`;
  document.querySelector('#provider').value = saved.provider;
  if (saved.model) document.querySelector('#model').value = saved.model;
}

function showStudy(name) {
  document.querySelectorAll('.study-tab').forEach((tab) => {
    const on = tab.dataset.study === name;
    tab.classList.toggle('active', on);
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
  });
  for (const id of ['ref', 'lists', 'cards']) {
    document.querySelector(`#study-${id}`).hidden = id !== name;
  }
}

function persistKey() {
  const provider = document.querySelector('#provider').value;
  const model = document.querySelector('#model').value;
  const typed = document.querySelector('#api-key').value.trim();
  const existing = loadKey();
  const key = typed || existing?.key;
  if (!key) {
      showToast('Paste a key first. The ranked report still runs without one.');
    return;
  }
  saveKey({ provider, model, key });
  document.querySelector('#api-key').value = '';
  paintKeyState();
  showToast('Key saved in this browser only');
}

function wireSignup() {
  const soon = document.querySelector('#signup-soon');
  const form = document.querySelector('#signup-form');
  const status = document.querySelector('#signup-status');
  if (!shouldShowSignupForm(SIGNUP_URL)) {
    soon.hidden = false;
    form.hidden = true;
    return;
  }
  soon.hidden = true;
  form.hidden = false;
  if (shouldLoadTurnstile(SIGNUP_URL, TURNSTILE_SITE_KEY)) loadTurnstile();
  form.addEventListener('submit', (event) => submitSignup(event, status));
}

function loadTurnstile() {
  if (document.querySelector('script[data-turnstile]')) return;
  const script = document.createElement('script');
  script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
  script.async = true;
  script.defer = true;
  script.dataset.turnstile = 'true';
  script.addEventListener('load', () => {
    if (window.turnstile) window.turnstile.render('#turnstile-slot', { sitekey: TURNSTILE_SITE_KEY });
  });
  document.head.append(script);
}

async function submitSignup(event, status) {
  event.preventDefault();
  if (!navigator.onLine) {
    status.textContent = "You're offline, try again later";
    return;
  }
  const email = document.querySelector('#signup-email').value;
  const company = document.querySelector('#signup-company').value;
  const turnstile = document.querySelector('[name="cf-turnstile-response"]')?.value || '';
  status.textContent = 'Sending…';
  try {
    const response = await fetch(SIGNUP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, company, turnstile }),
    });
    if (response.status === 429) {
      status.textContent = 'Too many attempts. Try again later.';
      return;
    }
    if (!response.ok) {
      status.textContent = 'Signup did not go through. Try again later.';
      return;
    }
    status.textContent = "You're on the list.";
    document.querySelector('#signup-form').reset();
  } catch {
    status.textContent = "You're offline, try again later";
  }
}

function wire() {
  alertState = loadAlertState(localStorage);
  document.querySelectorAll('[data-view]').forEach((button) => {
    button.addEventListener('click', () => showView(button.dataset.view));
  });
  const studyTabs = [...document.querySelectorAll('.study-tab')];
  studyTabs.forEach((button, index) => {
    button.addEventListener('click', () => showStudy(button.dataset.study));
    button.addEventListener('keydown', (event) => {
      const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
      if (!keys.includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (event.key === 'ArrowRight') next = (index + 1) % studyTabs.length;
      else if (event.key === 'ArrowLeft') next = (index + studyTabs.length - 1) % studyTabs.length;
      else if (event.key === 'Home') next = 0;
      else next = studyTabs.length - 1;
      showStudy(studyTabs[next].dataset.study);
      studyTabs[next].focus();
    });
  });
  document.querySelector('#clear-btn').addEventListener('click', () => {
    paste.value = '';
    deviceType = 'auto';
    paintDevices();
    showIdle();
  });
  paste.addEventListener('paste', () => {
    pasteStamp = Date.now();
    clearTimeout(debounce);
    debounce = setTimeout(() => begin(paste.value, null, { scroll: true }), 30);
  });
  paste.addEventListener('input', () => {
    if (settingValue || Date.now() - pasteStamp < 80) return;
    clearTimeout(debounce);
    debounce = setTimeout(() => begin(paste.value, null), 480);
  });
  document.querySelector('#settings-btn').addEventListener('click', () => {
    paintKeyState();
    paintWalletKeys();
    settings.showModal();
  });
  document.querySelector('#save-wallet-keys').addEventListener('click', () => persistWalletKeys());
  document.querySelector('#clear-wallet-keys').addEventListener('click', () => {
    clearWalletKeys(localStorage);
    document.querySelector('#etherscan-key').value = '';
    document.querySelector('#solscan-key').value = '';
    paintWalletKeys();
    showToast('Explorer keys removed');
  });
  document.querySelector('#alert-sort').addEventListener('change', () => paintAlerts());
  document.querySelector('#alert-show-done').addEventListener('change', () => paintAlerts());
  document.querySelector('#alert-notify').checked = alertState.notify && typeof Notification !== 'undefined' && Notification.permission === 'granted';
  document.querySelector('#alert-notify').addEventListener('change', async () => {
    const box = document.querySelector('#alert-notify');
    if (!box.checked) {
      alertState = { ...alertState, notify: false };
      saveAlertState(localStorage, alertState);
      return;
    }
    if (typeof Notification === 'undefined') {
      box.checked = false;
      showToast('This browser has no local notifications');
      return;
    }
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      box.checked = false;
      alertState = { ...alertState, notify: false };
      saveAlertState(localStorage, alertState);
      showToast('Notifications stay off until you allow them');
      return;
    }
    alertState = { ...alertState, notify: true };
    saveAlertState(localStorage, alertState);
    try {
      maybeNotify(alertsFromThreats((await ensureLists()).threats.entries));
    } catch {
      /* the list can load later */
    }
  });
  document.querySelector('#wallet-check').addEventListener('click', () => checkWallet());
  for (const [id, view] of [['threats-search', 'threats'], ['bots-search', 'bots'], ['hotfixes-search', 'hotfixes']]) {
    document.querySelector(`#${id}`).addEventListener('input', () => {
      if (!document.getElementById(`view-${view}`).hidden) paintList(view);
    });
  }
  document.querySelector('#settings-form').addEventListener('submit', (event) => {
    event.preventDefault();
    persistKey();
  });
  document.querySelector('#close-settings').addEventListener('click', () => settings.close());
  document.querySelector('#clear-key').addEventListener('click', () => {
    clearKey();
    document.querySelector('#api-key').value = '';
    paintKeyState();
    showToast('Key removed');
  });
  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    deferredInstall = event;
    document.querySelector('#install-btn').hidden = false;
  });
  document.querySelector('#install-btn').addEventListener('click', async () => {
    if (!deferredInstall) return;
    deferredInstall.prompt();
    await deferredInstall.userChoice;
    deferredInstall = null;
    document.querySelector('#install-btn').hidden = true;
  });
  window.addEventListener('online', () => setStatus(statusMessage));
  window.addEventListener('offline', () => setStatus(statusMessage));
  const hash = location.hash.replace('#', '');
  wireSignup();
  if (VIEWS.includes(hash) && hash !== 'home') showView(hash);
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
}

paintDevices();
paintSamples();
paintStudy();
showIdle();
wire();
