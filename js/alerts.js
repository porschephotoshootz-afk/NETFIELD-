/** Local alert list. Done state stays in localStorage. No server. */

export const ALERTS_STORAGE_KEY = 'starswarm.alerts.v1';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 9;
}

export function sortAlerts(alerts, mode = 'severity') {
  const copy = [...(alerts || [])];
  if (mode === 'newest') {
    return copy.sort((a, b) => String(b.date || '').localeCompare(String(a.date || '')));
  }
  return copy.sort((a, b) => {
    const rank = severityRank(a.severity) - severityRank(b.severity);
    if (rank !== 0) return rank;
    return String(b.date || '').localeCompare(String(a.date || ''));
  });
}

export function filterAlerts(alerts, { severity = 'all', done = {}, showDone = true, sort = 'severity' } = {}) {
  return sortAlerts(alerts, sort).filter((alert) => {
    if (severity !== 'all' && alert.severity !== severity) return false;
    if (!showDone && done[alert.id]) return false;
    return true;
  });
}

export function markDone(done, id, value = true) {
  const next = { ...(done || {}) };
  if (value) next[id] = true;
  else delete next[id];
  return next;
}

export function loadAlertState(storage) {
  try {
    const raw = storage.getItem(ALERTS_STORAGE_KEY);
    if (!raw) return { done: {}, notify: false };
    const parsed = JSON.parse(raw);
    const done = parsed && typeof parsed.done === 'object' && parsed.done ? { ...parsed.done } : {};
    return { done, notify: Boolean(parsed && parsed.notify) };
  } catch {
    return { done: {}, notify: false };
  }
}

export function saveAlertState(storage, state) {
  storage.setItem(ALERTS_STORAGE_KEY, JSON.stringify({
    done: state.done || {},
    notify: Boolean(state.notify),
  }));
}

export function alertsFromThreats(entries) {
  return (entries || []).map((entry) => ({
    id: `threat-${entry.cve}`,
    severity: entry.severity,
    title: `${entry.vendor} ${entry.product}`,
    cve: entry.cve,
    meaning: entry.description,
    steps: String(entry.fix || '').split(/(?<=\.)\s+/).filter(Boolean),
    cisaAction: entry.cisaAction,
    source: entry.source,
    advisory: entry.advisory,
    date: entry.dateAdded,
  }));
}

export function unseenCritical(alerts, done) {
  return (alerts || []).some((alert) => alert.severity === 'critical' && !(done || {})[alert.id]);
}

export function notificationDecision({ optedIn, permission, hasCritical }) {
  if (!optedIn) return { notify: false, reason: 'opt-in is off' };
  if (permission !== 'granted') return { notify: false, reason: 'permission not granted' };
  if (!hasCritical) return { notify: false, reason: 'no open critical alert' };
  return { notify: true, reason: 'opted in' };
}

export function safeHttps(url) {
  try {
    const parsed = new URL(String(url || ''));
    if (parsed.protocol !== 'https:') return '';
    return parsed.href;
  } catch {
    return '';
  }
}
