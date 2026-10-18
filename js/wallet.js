/**
 * Read-only public-chain check. No seed phrase, no private key, no wallet connect, no signing.
 */

export const WALLET_STORAGE_KEY = 'starswarm.wallet.v1';
// Tried from a browser on 2026-10-18. The first three answered getBalance. Mainnet is last because it returns 403.
export const SOLANA_RPCS = [
  'https://solana-rpc.publicnode.com',
  'https://public.rpc.solanavibestation.com',
  'https://solana.api.pocket.network',
  'https://api.mainnet-beta.solana.com',
];
export const ETH_RPCS = ['https://cloudflare-eth.com', 'https://ethereum-rpc.publicnode.com'];

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;

export function detectChainInput(raw) {
  const value = String(raw ?? '').trim();
  if (!value) return { ok: false, error: 'Paste a Solana or Ethereum address, or a transaction hash.' };
  if (/\s/.test(value)) return { ok: false, error: 'Paste one address or hash, with no spaces.' };
  if (value.includes('.')) {
    return { ok: false, error: 'This check does not look up names. Paste the public 0x address or the Solana address.' };
  }
  if (/^0x[0-9a-fA-F]{40}$/.test(value)) return { ok: true, chain: 'evm', kind: 'address', value };
  if (/^0x[0-9a-fA-F]{64}$/.test(value)) return { ok: true, chain: 'evm', kind: 'tx', value };
  if (/^0x/i.test(value)) {
    return { ok: false, error: 'That 0x value is not an Ethereum address (40 hex digits) or transaction (64 hex digits).' };
  }
  if (!BASE58.test(value)) {
    return { ok: false, error: 'Use a Solana base58 address or signature, or an Ethereum 0x address or transaction hash.' };
  }
  if (value.length >= 32 && value.length <= 44) return { ok: true, chain: 'solana', kind: 'address', value };
  if (value.length >= 86 && value.length <= 88) return { ok: true, chain: 'solana', kind: 'tx', value };
  return { ok: false, error: 'That base58 string is not a Solana address (32–44 characters) or signature (87–88 characters).' };
}

export function explorerLinks(detected) {
  if (!detected?.ok) return [];
  if (detected.chain === 'solana' && detected.kind === 'address') {
    return [{ label: 'Open on Solscan', href: `https://solscan.io/account/${detected.value}` }];
  }
  if (detected.chain === 'solana') {
    return [{ label: 'Open on Solscan', href: `https://solscan.io/tx/${detected.value}` }];
  }
  if (detected.kind === 'address') {
    return [{ label: 'Open on Etherscan', href: `https://etherscan.io/address/${detected.value}` }];
  }
  return [{ label: 'Open on Etherscan', href: `https://etherscan.io/tx/${detected.value}` }];
}

export function normalizeAddress(chain, value) {
  const text = String(value || '').trim();
  return chain === 'evm' ? text.toLowerCase() : text;
}

export function findFlagged(catalog, chain, value) {
  const needle = normalizeAddress(chain, value);
  return (catalog || []).find((entry) => entry.chain === chain && normalizeAddress(chain, entry.address) === needle) || null;
}

export function approvalFromInput(input) {
  const hex = String(input || '').toLowerCase().replace(/^0x/, '');
  if (!hex.startsWith('095ea7b3') || hex.length < 8 + 128) return null;
  const spenderWord = hex.slice(8, 8 + 64);
  const amount = hex.slice(8 + 64, 8 + 128);
  return {
    spender: `0x${spenderWord.slice(24)}`,
    unlimited: /^f{64}$/.test(amount),
  };
}

export function flagAccount({ address, chain, catalog, txCount, approvals, counterparties }) {
  const flags = [];
  const listed = findFlagged(catalog, chain, address);
  if (listed) {
    flags.push({
      id: 'listed',
      severity: 'critical',
      title: 'Address is on a public flag list',
      meaning: `This address is on a public ${listed.list} list. That is a signal, not proof.`,
      href: listed.source,
    });
  }
  if (typeof txCount === 'number' && Number.isFinite(txCount) && txCount === 0) {
    flags.push({
      id: 'new-address',
      severity: 'medium',
      title: 'No history on this chain',
      meaning: 'This address has no outgoing history yet. A brand-new address can be harmless. Treat that as a signal, not proof.',
    });
  }
  if ((approvals || []).some((item) => item && item.unlimited)) {
    flags.push({
      id: 'unlimited-approval',
      severity: 'high',
      title: 'Unlimited token approval',
      meaning: 'A transaction lets a spender move an unlimited amount of a token until you revoke it. That is a signal, not proof of theft.',
      href: chain === 'evm' ? `https://revoke.cash/address/${address}` : 'https://revoke.cash/',
    });
  }
  for (const other of counterparties || []) {
    if (normalizeAddress(chain, other) === normalizeAddress(chain, address)) continue;
    const hit = findFlagged(catalog, chain, other);
    if (!hit) continue;
    flags.push({
      id: 'touched-flagged',
      severity: 'high',
      title: 'Touches a flagged address',
      meaning: 'A recent transaction includes an address from the public flag list. That is a signal, not proof.',
      href: hit.source,
    });
    break;
  }
  return flags;
}

export function flagsAfterLookup(live, details) {
  if (!live || live.ok !== true || live.skipped) return [];
  return flagAccount({
    address: details?.address,
    chain: details?.chain,
    catalog: details?.catalog,
    txCount: live.txCount,
    approvals: details?.approvals,
    counterparties: details?.counterparties,
  });
}

export function formatUnits(raw, decimals) {
  const value = typeof raw === 'bigint' ? raw : BigInt(raw);
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = (abs % base).toString().padStart(Number(decimals), '0').slice(0, 4).replace(/0+$/, '');
  const text = frac ? `${whole.toString()}.${frac}` : whole.toString();
  return negative ? `-${text}` : text;
}

export function loadWalletKeys(storage) {
  try {
    const parsed = JSON.parse(storage.getItem(WALLET_STORAGE_KEY) || 'null');
    if (!parsed || typeof parsed !== 'object') return { etherscan: '', solscan: '' };
    return {
      etherscan: typeof parsed.etherscan === 'string' ? parsed.etherscan : '',
      solscan: typeof parsed.solscan === 'string' ? parsed.solscan : '',
    };
  } catch {
    return { etherscan: '', solscan: '' };
  }
}

export function saveWalletKeys(storage, keys) {
  storage.setItem(WALLET_STORAGE_KEY, JSON.stringify({
    etherscan: String(keys?.etherscan || '').trim(),
    solscan: String(keys?.solscan || '').trim(),
  }));
}

export function clearWalletKeys(storage) {
  storage.removeItem(WALLET_STORAGE_KEY);
}

async function rpc(url, body, fetchImpl) {
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (response.status === 429) {
    const error = new Error('rate-limit');
    error.rateLimit = true;
    throw error;
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function readSolana(address, fetchImpl) {
  let rateLimited = false;
  for (const url of SOLANA_RPCS) {
    try {
      const [balance, signatures] = await Promise.all([
        rpc(url, { jsonrpc: '2.0', id: 1, method: 'getBalance', params: [address] }, fetchImpl),
        rpc(url, { jsonrpc: '2.0', id: 2, method: 'getSignaturesForAddress', params: [address, { limit: 5 }] }, fetchImpl),
      ]);
      const message = `${balance?.error?.message || ''} ${signatures?.error?.message || ''}`;
      if (balance?.error || signatures?.error) {
        if (/rate|limit/i.test(message)) rateLimited = true;
        if (/rate|limit|forbidden|blocked|not allowed/i.test(message)) continue;
        return { ok: false, error: 'The public Solana RPC did not return this account. The Solscan link still works.' };
      }
      const lamports = balance?.result?.value ?? 0;
      const list = Array.isArray(signatures?.result) ? signatures.result : [];
      return {
        ok: true,
        balance: formatUnits(lamports, 9),
        unit: 'SOL',
        txCount: list.length === 0 ? 0 : null,
        historyNote: list.length === 0 ? 'No recent signatures.' : `${list.length} recent signature${list.length === 1 ? '' : 's'} shown.`,
      };
    } catch (error) {
      if (error.rateLimit) rateLimited = true;
    }
  }
  if (rateLimited) {
    return { ok: false, error: 'The public RPC is rate-limiting. The explorer link still works. Try again in a minute.' };
  }
  return { ok: false, error: 'The public RPC could not be reached. The explorer link still works.' };
}

export async function readPublicChain(detected, fetchImpl = fetch) {
  if (!detected?.ok || detected.kind !== 'address') return { ok: true, skipped: true };
  try {
    if (detected.chain === 'solana') return readSolana(detected.value, fetchImpl);
    let lastError = null;
    for (const url of ETH_RPCS) {
      try {
        const body = await rpc(url, [
          { jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [detected.value, 'latest'] },
          { jsonrpc: '2.0', id: 2, method: 'eth_getTransactionCount', params: [detected.value, 'latest'] },
        ], fetchImpl);
        const rows = Array.isArray(body) ? body : [body];
        const balance = rows.find((row) => row.id === 1);
        const nonce = rows.find((row) => row.id === 2);
        if (!balance?.result || nonce?.result == null) throw new Error('empty');
        const txCount = Number(BigInt(nonce.result));
        return {
          ok: true,
          balance: formatUnits(BigInt(balance.result), 18),
          unit: 'ETH',
          txCount,
          historyNote: txCount === 0 ? 'Nonce is 0. No outgoing transactions.' : `Outgoing transactions (nonce): ${txCount}.`,
        };
      } catch (error) {
        lastError = error;
        if (error.rateLimit) break;
      }
    }
    if (lastError?.rateLimit) {
      return { ok: false, error: 'The public Ethereum RPC is rate-limiting. The Etherscan link still works. Try again in a minute.' };
    }
    return { ok: false, error: 'The public Ethereum RPC did not answer. The Etherscan link still works.' };
  } catch (error) {
    if (error.rateLimit) {
      return { ok: false, error: 'The public RPC is rate-limiting. The explorer link still works. Try again in a minute.' };
    }
    return { ok: false, error: 'The public RPC could not be reached. The explorer link still works.' };
  }
}

export async function readEtherscan(address, apiKey, fetchImpl = fetch) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: true, skipped: true };
  const url = new URL('https://api.etherscan.io/v2/api');
  url.searchParams.set('chainid', '1');
  url.searchParams.set('module', 'account');
  url.searchParams.set('action', 'txlist');
  url.searchParams.set('address', address);
  url.searchParams.set('page', '1');
  url.searchParams.set('offset', '8');
  url.searchParams.set('sort', 'desc');
  url.searchParams.set('apikey', key);
  const response = await fetchImpl(url);
  if (response.status === 429) {
    return { ok: false, error: 'Etherscan is rate-limiting this key. The public balance and the Etherscan link still work.' };
  }
  const body = await response.json();
  const message = String(body?.message || body?.result || '');
  if (body?.status === '0' && /rate|limit/i.test(message)) {
    return { ok: false, error: 'Etherscan is rate-limiting this key. The public balance and the Etherscan link still work.' };
  }
  if (!Array.isArray(body?.result)) {
    return { ok: false, error: 'Etherscan did not return recent transactions. The public balance and the Etherscan link still work.' };
  }
  const transactions = body.result.slice(0, 8).map((row) => ({
    hash: row.hash,
    from: row.from,
    to: row.to,
    value: row.value,
  }));
  const approvals = body.result.map((row) => approvalFromInput(row.input)).filter(Boolean);
  const counterparties = body.result.flatMap((row) => [row.from, row.to].filter(Boolean));
  return { ok: true, transactions, approvals, counterparties };
}

export async function readSolscan(address, apiKey, fetchImpl = fetch) {
  const key = String(apiKey || '').trim();
  if (!key) return { ok: true, skipped: true };
  const url = `https://pro-api.solscan.io/v2.0/account/transactions?address=${encodeURIComponent(address)}&limit=8`;
  const response = await fetchImpl(url, { headers: { token: key } });
  if (response.status === 429) {
    return { ok: false, error: 'Solscan is rate-limiting this key. The public balance and the Solscan link still work.' };
  }
  if (!response.ok) {
    return { ok: false, error: 'Solscan did not return recent transactions. The public balance and the Solscan link still work.' };
  }
  const body = await response.json();
  const rows = Array.isArray(body?.data) ? body.data : [];
  const transactions = rows.slice(0, 8).map((row) => ({
    hash: row.tx_hash || row.txHash || row.signature || row.hash || '',
    from: row.from || '',
    to: row.to || '',
  })).filter((row) => row.hash);
  const counterparties = rows.flatMap((row) => [row.from, row.to, row.signer].filter(Boolean));
  return { ok: true, transactions, approvals: [], counterparties };
}
