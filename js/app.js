import { SPECIALISTS, runSwarm } from './analyzers.js';
import { SAMPLES } from './samples.js';
import { CS_DATA, REF_DATA, SCENARIOS } from './study.js';
import { clearKey, deepAnalyze, hasKey, loadKey, saveKey } from './deep.js';

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
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 2400);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied');
  } catch {
    const area = el('textarea', { text });
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
    showToast('Copied');
  }
}

function setStatus(message) {
  statusMessage = message;
  const offline = typeof navigator !== 'undefined' && navigator.onLine === false;
  statusText.textContent = offline ? `Offline · ${message}` : message;
}

function paintDevices() {
  devices.replaceChildren();
  for (const [id, label] of DEVICES) {
    const button = el('button', {
      type: 'button',
      class: 'device',
      role: 'radio',
      'aria-checked': id === deviceType ? 'true' : 'false',
      text: label,
    });
    button.addEventListener('click', () => {
      deviceType = id;
      paintDevices();
      if (paste.value.trim().length >= 8) {
        lastText = '';
        begin(paste.value, lastSample);
      }
    });
    devices.append(button);
  }
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
    el('span', { text: 'Listening to the swarm…' }),
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
  begin(sample.text, sample);
}

function begin(text, sample) {
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
  report.hidden = true;
  document.documentElement.dataset.swarm = 'running';
  setStatus('Swarm is reading…');
  renderScanning();
  board.scrollIntoView({ block: 'start' });
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
    report.scrollIntoView({ block: 'start' });
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
        copyText(chip.cmd);
        showToast(`Copied ${chip.cmd}. Paste the output back.`);
      });
      row.append(button);
    }
    root.append(row);
  }

  const deepRow = el('div', { class: 'deep-row' });
  const deepBtn = el('button', { type: 'button', class: 'deep-btn', text: 'Deep analysis with your key' });
  const deepOut = el('div', { class: 'deep-box' });
  deepBtn.addEventListener('click', () => runDeep(deepBtn, deepOut));
  deepRow.append(deepBtn);
  root.append(
    deepRow,
    el('p', { class: 'note', text: 'Optional. This sends the paste to your provider. The ranked report above does not.' }),
    deepOut,
  );
  report.replaceChildren(root);
}

async function runDeep(button, slot) {
  if (!hasKey()) {
    showToast('Add a key in Settings. The free swarm does not need one.');
    settings.showModal();
    return;
  }
  const saved = loadKey();
  button.disabled = true;
  slot.replaceChildren(el('p', { text: 'Asking your provider…' }));
  try {
    const text = await deepAnalyze(saved, { text: paste.value, summary: lastResult?.summary });
    slot.replaceChildren(el('h3', { text: 'Deep analysis' }), el('p', { text }));
  } catch (error) {
    slot.replaceChildren(el('p', { text: error.message || 'Deep analysis failed.' }));
  } finally {
    button.disabled = false;
  }
}

function showView(name) {
  for (const button of document.querySelectorAll('.tab')) {
    const on = button.dataset.view === name;
    button.classList.toggle('active', on);
    button.toggleAttribute('aria-current', on);
  }
  for (const view of ['swarm', 'study', 'pro']) {
    document.getElementById(`view-${view}`).hidden = view !== name;
  }
  history.replaceState(null, '', `#${name}`);
}

function paintStudy() {
  const ref = document.querySelector('#study-ref');
  const lists = document.querySelector('#study-lists');
  const cards = document.querySelector('#study-cards');
  ref.replaceChildren();
  for (const item of REF_DATA) {
    const card = el('article', { class: 'ref-card' });
    const head = el('button', { type: 'button', class: 'ref-head' }, [
      el('span', { text: item.icon, 'aria-hidden': 'true' }),
      el('span', {}, [
        el('strong', { text: item.title }),
        el('span', { class: 'bot-role', text: item.sub }),
      ]),
    ]);
    const body = el('div', { class: 'ref-body' });
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
    head.addEventListener('click', () => card.classList.toggle('open'));
    card.append(head, body);
    ref.append(card);
  }

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

function wire() {
  document.querySelectorAll('.tab').forEach((button) => {
    button.addEventListener('click', () => showView(button.dataset.view));
  });
  document.querySelectorAll('.study-tab').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('.study-tab').forEach((tab) => tab.classList.toggle('active', tab === button));
      for (const name of ['ref', 'lists', 'cards']) {
        document.querySelector(`#study-${name}`).hidden = button.dataset.study !== name;
      }
    });
  });
  document.querySelector('#clear-btn').addEventListener('click', () => {
    paste.value = '';
    showIdle();
  });
  paste.addEventListener('paste', () => {
    pasteStamp = Date.now();
    clearTimeout(debounce);
    debounce = setTimeout(() => begin(paste.value, null), 30);
  });
  paste.addEventListener('input', () => {
    if (settingValue || Date.now() - pasteStamp < 80) return;
    clearTimeout(debounce);
    debounce = setTimeout(() => begin(paste.value, null), 480);
  });
  document.querySelector('#settings-btn').addEventListener('click', () => {
    paintKeyState();
    settings.showModal();
  });
  document.querySelector('#save-key').addEventListener('click', () => {
    const provider = document.querySelector('#provider').value;
    const model = document.querySelector('#model').value;
    const typed = document.querySelector('#api-key').value.trim();
    const existing = loadKey();
    const key = typed || existing?.key;
    if (!key) {
      showToast('Paste a key first. The swarm still runs without one.');
      return;
    }
    saveKey({ provider, model, key });
    document.querySelector('#api-key').value = '';
    paintKeyState();
    showToast('Key saved in this browser only');
  });
  document.querySelector('#clear-key').addEventListener('click', () => {
    clearKey();
    document.querySelector('#api-key').value = '';
    paintKeyState();
    showToast('Key removed');
  });
  document.querySelector('#waitlist-btn').addEventListener('click', () => {
    document.querySelector('#waitlist-note').textContent = 'TODO: nothing was collected. There is no form and no payment link yet.';
    showToast('No data collected. Waitlist is not connected.');
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
  if (hash === 'study' || hash === 'pro') showView(hash);
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
}

paintDevices();
paintSamples();
paintStudy();
showIdle();
wire();
