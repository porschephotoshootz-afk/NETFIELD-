/**
 * Optional bring-your-own-key deep analysis.
 * The key lives in localStorage only. It is sent only to the provider
 * the user picked, and only after they tap Deep analysis.
 */

const STORAGE_KEY = 'netfield.byok.v1';

const ENDPOINTS = {
  anthropic: 'https://api.anthropic.com/v1/messages',
  openai: 'https://api.openai.com/v1/chat/completions',
};

export function loadKey() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.key !== 'string' || !parsed.key.trim()) return null;
    const provider = parsed.provider === 'openai' ? 'openai' : 'anthropic';
    return {
      provider,
      key: parsed.key.trim(),
      model: typeof parsed.model === 'string' ? parsed.model.trim() : '',
    };
  } catch {
    return null;
  }
}

export function saveKey({ provider, key, model }) {
  const nextProvider = provider === 'openai' ? 'openai' : 'anthropic';
  const trimmed = String(key || '').trim();
  if (!trimmed) throw new Error('Missing key');
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    provider: nextProvider,
    key: trimmed,
    model: String(model || '').trim(),
  }));
}

export function clearKey() {
  localStorage.removeItem(STORAGE_KEY);
}

export function hasKey() {
  return Boolean(loadKey());
}

const SECRET_LINE = [
  /^(\s*enable\s+(?:secret|password)(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:password|secret)(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*password(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*secret(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*snmp-server\s+community\s+)\S+(.*)$/i,
  /^(\s*(?:pre-shared-key|key-string|authentication-key)(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*crypto\s+isakmp\s+key(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*(?:tacacs-server|radius-server|radius\s+server)\s+key(?:\s+\d)?\s+)\S+(.*)$/i,
  /^(\s*ip\s+ospf\s+(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+)\S+(.*)$/i,
  /^(\s*(?:ip\s+ftp|ip\s+http\s+client|ppp\s+\S+)\s+password\s+)\S+(.*)$/i,
  /^(\s*wpa-psk\s+(?:ascii|hex)\s+)\S+(.*)$/i,
];

export function redactSecrets(text) {
  return String(text ?? '').split('\n').map((line) => {
    for (const rule of SECRET_LINE) {
      if (rule.test(line)) return line.replace(rule, '$1[redacted]$2');
    }
    return line;
  }).join('\n');
}

export async function deepAnalyze(settings, { text, summary }) {
  const provider = settings.provider === 'openai' ? 'openai' : 'anthropic';
  const key = settings.key;
  const model = settings.model || (provider === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-5');
  const prompt = buildPrompt(redactSecrets(text), summary);
  let response;
  try {
    response = await fetch(ENDPOINTS[provider], {
      method: 'POST',
      headers: headersFor(provider, key),
      body: JSON.stringify(bodyFor(provider, model, prompt)),
    });
  } catch (error) {
    throw new Error(redact(error?.message || 'The browser could not reach the provider.', key));
  }
  const raw = await response.text();
  if (!response.ok) {
    throw new Error(redact(`Provider returned ${response.status}. ${raw.slice(0, 280)}`, key));
  }
  try {
    return extractText(provider, JSON.parse(raw));
  } catch {
    throw new Error('The provider response was not readable.');
  }
}

function headersFor(provider, key) {
  if (provider === 'openai') {
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`,
    };
  }
  return {
    'Content-Type': 'application/json',
    'x-api-key': key,
    'anthropic-version': '2023-06-01',
    'anthropic-dangerous-direct-browser-access': 'true',
  };
}

function bodyFor(provider, model, prompt) {
  if (provider === 'openai') {
    return {
      model,
      temperature: 0.2,
      messages: [
        { role: 'system', content: 'You are a careful network engineer. Be concise. Do not invent show output that was not provided.' },
        { role: 'user', content: prompt },
      ],
    };
  }
  return {
    model,
    max_tokens: 900,
    messages: [{ role: 'user', content: prompt }],
  };
}

function extractText(provider, data) {
  if (provider === 'openai') {
    return data?.choices?.[0]?.message?.content?.trim() || 'No text came back.';
  }
  const blocks = Array.isArray(data?.content) ? data.content : [];
  const text = blocks.filter((block) => block.type === 'text').map((block) => block.text).join('\n').trim();
  return text || 'No text came back.';
}

function buildPrompt(text, summary) {
  const findings = (summary?.actions || []).slice(0, 8).map((item) => (
    `- [${item.severity}] ${item.title} (${item.specialist})`
  )).join('\n');
  const paste = String(text || '').slice(0, 12000);
  return [
    'Second-pass the on-device rule engine. Agree or correct it. Give the first command to run and why.',
    'Do not repeat the whole paste.',
    '',
    `Coordinator (${summary?.confidenceLabel || 'unknown'} confidence): ${summary?.headline || ''}`,
    summary?.narrative || '',
    findings,
    '',
    'Paste:',
    paste,
  ].join('\n');
}

function redact(message, key) {
  let text = String(message || 'Deep analysis failed.');
  if (key) text = text.split(key).join('[key]');
  return text;
}
