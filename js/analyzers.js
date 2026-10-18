/**
 * On-device rule engine for StarSwarm Security Agentic Toolkit.
 * Parsing, rules, and heuristics only. No network and no API key.
 * The same paste always produces the same findings.
 */

export const SPECIALISTS = [
  { id: 'layer12', name: 'Layer 1/2', role: 'Interfaces, errors, duplex, VLANs, STP', glyph: '🔌' },
  { id: 'routing', name: 'Routing', role: 'Routes, OSPF, EIGRP, static, gateway', glyph: '🗺️' },
  { id: 'ip', name: 'IP & Subnetting', role: 'Addresses, masks, overlaps, gateways', glyph: '🔢' },
  { id: 'services', name: 'Services', role: 'DNS, DHCP, NAT, ACL hits', glyph: '⚙️' },
  { id: 'security', name: 'Security', role: 'Telnet, passwords, insecure config', glyph: '🔐' },
  { id: 'wireless', name: 'Wireless', role: 'Signal, channels, association', glyph: '📶' },
];

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const DEVICES = new Set(['auto', 'router', 'switch', 'firewall', 'wireless', 'pc']);
const WEAK = new Set([
  'cisco', 'cisco1', 'cisco123', 'admin', 'password', 'pass', 'public', 'private',
  '123456', '12345', '1234', 'default', 'secret', 'enable', 'root', 'guest',
  'changeme', 'test', 'letmein',
]);
const BAD_OSPF = new Set(['INIT', 'EXSTART', 'EXCHANGE', 'LOADING', 'DOWN', 'ATTEMPT']);

export function ipToInt(ip) {
  const parts = String(ip).split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
}

export function intToIp(n) {
  const v = n >>> 0;
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

export function maskToPrefix(mask) {
  const n = ipToInt(mask);
  if (n == null) return null;
  let bits = 0;
  let seenZero = false;
  for (let i = 31; i >= 0; i -= 1) {
    const on = (n >>> i) & 1;
    if (on) {
      if (seenZero) return null;
      bits += 1;
    } else {
      seenZero = true;
    }
  }
  return bits;
}

export function networkAddress(ip, prefix) {
  const n = typeof ip === 'number' ? (ip >>> 0) : ipToInt(ip);
  if (n == null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (n & mask) >>> 0;
}

export function inSubnet(ip, network, prefix) {
  const a = networkAddress(ip, prefix);
  const b = networkAddress(network, prefix);
  return a != null && a === b;
}

export function wildcardToPrefix(wildcard) {
  const n = ipToInt(wildcard);
  if (n == null) return null;
  const host = n >>> 0;
  if (host !== 0) {
    const sum = host + 1;
    if ((host & (sum >>> 0)) !== 0 && sum <= 0xffffffff) return null;
  }
  let bits = 0;
  let x = host;
  while (x) {
    bits += 1;
    x >>>= 1;
  }
  return 32 - bits;
}

export function prefixToWildcard(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 32) return '0.0.0.0';
  const host = (2 ** (32 - prefix) - 1) >>> 0;
  return intToIp(host);
}

export function confidenceLabel(n) {
  if (n >= 80) return 'High';
  if (n >= 55) return 'Medium';
  return 'Low';
}

export function runSwarm(text, options = {}) {
  const input = String(text ?? '').replace(/\r\n/g, '\n');
  const deviceType = DEVICES.has(options.deviceType) ? options.deviceType : 'auto';
  const ctx = buildContext(input, deviceType);
  const reports = SPECIALISTS.map((spec) => {
    const findings = analyze(spec.id, ctx);
    const ask = nextAsk(spec.id, ctx, findings);
    return {
      id: spec.id,
      name: spec.name,
      role: spec.role,
      glyph: spec.glyph,
      findings,
      ask,
      status: statusOf(findings),
    };
  });
  const summary = coordinate(reports, ctx);
  return {
    reports,
    summary,
    meta: { sparse: ctx.sparse, deviceType },
  };
}

function analyze(id, ctx) {
  const real = analyzeReal(id, ctx);
  if (real.length || !ctx.sparse) return real;
  return hypotheses(id, ctx);
}

function analyzeReal(id, ctx) {
  switch (id) {
    case 'layer12': return analyzeLayer12(ctx);
    case 'routing': return analyzeRouting(ctx);
    case 'ip': return analyzeIp(ctx);
    case 'services': return analyzeServices(ctx);
    case 'security': return analyzeSecurity(ctx);
    case 'wireless': return analyzeWireless(ctx);
    default: return [];
  }
}

function statusOf(findings) {
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'alert';
  if (findings.some((f) => f.severity === 'medium' || f.severity === 'low')) return 'watch';
  if (findings.length) return 'info';
  return 'clear';
}

function finding(specId, data) {
  return {
    specialistId: specId,
    hypothesis: false,
    commands: [],
    evidence: [],
    order: 0,
    ...data,
  };
}

function symptomLine(lines) {
  return lines.find((line) => line.trim()) || '';
}

function isPrivate(ip) {
  const n = ipToInt(ip);
  if (n == null) return false;
  const a = n >>> 24;
  const b = (n >>> 16) & 255;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isWeak(word) {
  return WEAK.has(String(word || '').toLowerCase());
}

function covers(outerNet, outerPrefix, innerNet, innerPrefix) {
  if (innerPrefix < outerPrefix) return false;
  return networkAddress(innerNet, outerPrefix) === networkAddress(outerNet, outerPrefix);
}

function sameSubnet(a, b) {
  return a.prefix === b.prefix && networkAddress(a.ip, a.prefix) === networkAddress(b.ip, b.prefix);
}

function rangesOverlap(a, b) {
  const a0 = networkAddress(a.ip, a.prefix);
  const b0 = networkAddress(b.ip, b.prefix);
  if (a0 == null || b0 == null) return false;
  const a1 = (a0 + 2 ** (32 - a.prefix) - 1) >>> 0;
  const b1 = (b0 + 2 ** (32 - b.prefix) - 1) >>> 0;
  return a0 <= b1 && b0 <= a1;
}

function buildContext(text, deviceType) {
  const lines = text.split('\n');
  const blocks = parseBlocks(lines);
  const brief = parseBrief(lines);
  const ifaceBlocks = parseIfaceBlocks(lines);
  const vlans = parseVlans(lines);
  const routes = parseRoutes(lines);
  const ospfNeighbors = parseOspfNeighbors(lines);
  const adapters = parseAdapters(lines);
  const configIfs = parseConfigInterfaces(blocks);
  const ospfNetworks = parseOspfNetworks(blocks);
  const symptoms = detectSymptoms(text);
  const wireless = {
    seen: /ssid|rssi|dot11|wi-?fi|wireless|capwap/i.test(text),
    rssi: parseRssi(lines),
    snr: parseSnr(lines),
    aps: parse24Aps(text),
  };
  const hasNat = /ip nat\s+(inside|outside|inside source)/i.test(text);
  const hasSecurityConfig = blocks.some((b) => b.kind === 'line')
    || /^(enable password|enable secret|username\s+\S+|snmp-server community|ip http server)\b/im.test(text);
  const rich = Boolean(
    brief.length
    || routes.sawTable
    || ifaceBlocks.length
    || blocks.length
    || adapters.length
    || ospfNeighbors.length
    || wireless.rssi
    || wireless.aps.length
    || /show\s+(ip|vlan|run|interfaces|spanning|access|client|ap)\b/i.test(text),
  );

  return {
    text,
    lines,
    deviceType,
    blocks,
    brief,
    ifaceBlocks,
    vlans,
    routes,
    ospfNeighbors,
    adapters,
    configIfs,
    ospfNetworks,
    symptoms,
    wireless,
    hasNat,
    hasSecurityConfig,
    hasVlan: vlans.length > 0,
    hasRoute: routes.sawTable,
    hasIpBrief: brief.length > 0,
    hasIfaceBlocks: ifaceBlocks.length > 0,
    hasStaticDefault: /^ip route\s+0\.0\.0\.0\s+0\.0\.0\.0\s+\d+\.\d+\.\d+\.\d+/im.test(text),
    sparse: !rich,
    symptomLine: symptomLine(lines),
    order: 0,
  };
}

function nextOrder(ctx) {
  ctx.order += 1;
  return ctx.order;
}

function namesFailWhileIpWorks(text) {
  const ipWorks = /\b(?:can|could)\s+ping\s+\d+\.\d+\.\d+\.\d+\b/i.test(text);
  const nameFails = /\b(?:cannot|can't|can not)\s+(?:open|browse|load)\b/i.test(text)
    || /\b(?:dns|nslookup|not resolv)/i.test(text);
  return ipWorks && nameFails;
}

function detectSymptoms(text) {
  const vlans = new Set();
  for (const match of text.matchAll(/\bvlan\s*0*(\d{1,4})\b/gi)) {
    const n = Number(match[1]);
    if (n >= 1 && n <= 4094) vlans.add(String(n));
  }
  const prose = text.replace(/internet address(?: is)?/gi, '');
  return {
    internet: /\binternet\b|\bwan\b|8\.8\.8\.8|google\.com|web page|\bbrowse/i.test(prose),
    reach: /can'?t reach|cannot reach|unreachable|timed out|packet loss|no connectivity|cannot ping|can't ping/i.test(text),
    slow: /\bslow\b|\bcrc\b|collision|\bduplex\b/i.test(text),
    wireless: /\bwi-?fi\b|\bssid\b|\bwireless\b|\brssi\b|\bcapwap\b|\bdot11\b/i.test(text),
    security: /\btelnet\b|\bpassword\b|\bsnmp\b|\bssh\b|\binsecure\b/i.test(text),
    ipWorksNamesFail: namesFailWhileIpWorks(text),
    vlans: [...vlans],
  };
}

function parseBlocks(lines) {
  const blocks = [];
  let current = null;
  const start = /^(interface|line|router|ip dhcp pool|ip access-list)\s+(.+)$/i;
  for (const line of lines) {
    const trimmed = line.trim();
    const head = !/^\s/.test(line) ? line.match(start) : null;
    if (head) {
      current = { kind: head[1].toLowerCase(), name: head[2].trim(), header: line, body: [], rawBody: [] };
      blocks.push(current);
      continue;
    }
    if (current && /^\s+\S/.test(line)) {
      current.body.push(trimmed);
      current.rawBody.push(line.replace(/\s+$/, ''));
      continue;
    }
    if (trimmed === '!' || trimmed === '') {
      if (trimmed === '!' && current) current = null;
      continue;
    }
    if (current && !/^\s/.test(line)) current = null;
  }
  return blocks;
}

function parseBrief(lines) {
  const re = /^([A-Za-z][\w./:-]*)\s+(\d+\.\d+\.\d+\.\d+|unassigned)\s+(YES|NO)\s+(\S+)\s+(administratively down|up|down)\s+(up|down)\s*$/i;
  const rows = [];
  for (const line of lines) {
    const match = line.trim().match(re);
    if (!match) continue;
    rows.push({
      line,
      iface: match[1],
      ip: /^unassigned$/i.test(match[2]) ? null : match[2],
      status: match[5].toLowerCase(),
      protocol: match[6].toLowerCase(),
    });
  }
  return rows;
}

function parseIfaceBlocks(lines) {
  const header = /^([A-Za-z][\w./:-]*) is (administratively )?(up|down), line protocol is (up|down)\b/i;
  const blocks = [];
  let current = null;
  const close = () => {
    if (current) blocks.push(finishIface(current));
    current = null;
  };
  for (const line of lines) {
    const match = !/^\s/.test(line) ? line.match(header) : null;
    if (match) {
      close();
      current = {
        name: match[1],
        admin: Boolean(match[2]),
        lineState: match[3].toLowerCase(),
        protocol: match[4].toLowerCase(),
        header: line,
        body: [],
      };
      continue;
    }
    if (!current) continue;
    if (/^[A-Za-z0-9_.-]+#/.test(line) || (line.trim() && !/^\s/.test(line) && !line.startsWith('%') && !line.startsWith('!'))) {
      close();
      continue;
    }
    current.body.push(line);
  }
  close();
  return blocks;
}

function finishIface(block) {
  const joined = block.body.join('\n');
  let crc = 0;
  let inputErrors = 0;
  let late = 0;
  let reliability = null;
  let mtu = null;
  let ip = null;
  let prefix = null;
  let duplex = null;
  let speed = null;
  for (const line of block.body) {
    const crcMatch = line.match(/(\d+)\s+CRC\b/i);
    if (crcMatch) crc = Math.max(crc, Number(crcMatch[1]));
    const errMatch = line.match(/(\d+)\s+input errors\b/i);
    if (errMatch) inputErrors = Math.max(inputErrors, Number(errMatch[1]));
    const lateMatch = line.match(/(\d+)\s+late collisions?\b/i);
    if (lateMatch) late = Math.max(late, Number(lateMatch[1]));
    const rel = line.match(/reliability\s+(\d+)\s*\/\s*255/i);
    if (rel) reliability = Number(rel[1]);
    const mtuMatch = line.match(/\bMTU\s+(\d+)\s+bytes/i);
    if (mtuMatch) mtu = Number(mtuMatch[1]);
    const addr = line.match(/Internet Address(?: is)?\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/i);
    if (addr) {
      ip = addr[1];
      prefix = Number(addr[2]);
    }
    if (/half-duplex/i.test(line)) duplex = 'half';
    else if (/full-duplex/i.test(line) && duplex !== 'half') duplex = 'full';
    const speedMatch = line.match(/(\d+)\s*Mb\/s/i);
    if (speedMatch) speed = Number(speedMatch[1]);
  }
  const ospf = /Process ID\s+\d+|Attached via Network Statement|Network Type/i.test(joined);
  return { ...block, crc, inputErrors, late, reliability, mtu, ip, prefix, duplex, speed, ospf };
}

function parseVlans(lines) {
  const start = lines.findIndex((line) => /VLAN\s+Name\s+Status/i.test(line));
  if (start < 0) return [];
  const vlans = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^[A-Za-z0-9_.-]+#/.test(line)) break;
    if (!line.trim() || /^----/.test(line.trim())) continue;
    const match = line.match(/^\s*(\d+)\s+(\S+)\s+(active|act\/unsup|suspend)\s*(.*)$/i);
    if (match) {
      vlans.push({
        id: String(Number(match[1])),
        name: match[2],
        status: match[3].toLowerCase(),
        ports: match[4].trim(),
        line,
      });
    } else if (vlans.length && /^\s+\S/.test(line)) {
      vlans[vlans.length - 1].ports = `${vlans[vlans.length - 1].ports} ${line.trim()}`.trim();
    } else if (line.trim() && !/^\s*\d/.test(line)) {
      break;
    }
  }
  return vlans;
}

function parseRoutes(lines) {
  const connected = [];
  let noDefault = false;
  let sawTable = false;
  let gatewayIp = null;
  for (const line of lines) {
    if (/Gateway of last resort is not set/i.test(line)) {
      noDefault = true;
      sawTable = true;
    }
    const gw = line.match(/Gateway of last resort is\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (gw) {
      sawTable = true;
      noDefault = false;
      gatewayIp = gw[1];
    }
    const connectedMatch = line.match(/^\s*([A-Z])\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\s+is directly connected,\s+(\S+)/);
    if (connectedMatch) {
      sawTable = true;
      connected.push({
        code: connectedMatch[1],
        network: connectedMatch[2],
        prefix: Number(connectedMatch[3]),
        iface: connectedMatch[4].replace(/,$/, ''),
        line,
      });
    }
  }
  return { connected, noDefault, sawTable, gatewayIp };
}

function parseOspfNeighbors(lines) {
  const rows = [];
  const re = /^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+([A-Z]+)(?:\/\S+)?\s+(\d+:\d+:\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s*$/;
  for (const line of lines) {
    const match = line.trim().match(re);
    if (!match) continue;
    rows.push({
      id: match[1],
      state: match[3],
      address: match[5],
      iface: match[6],
      line,
    });
  }
  return rows;
}

function parseAdapters(lines) {
  const adapters = [];
  let current = null;
  const flush = () => {
    if (!current) return;
    if (current.mask) current.prefix = maskToPrefix(current.mask);
    if (current.ip || current.gateway) adapters.push(current);
    current = null;
  };
  for (const line of lines) {
    if (/adapter\s+.+:\s*$/i.test(line) && !/^\s{3,}/.test(line)) {
      flush();
      current = { name: line.trim(), ip: null, mask: null, prefix: null, gateway: null, ipLine: null, maskLine: null, gwLine: null };
      continue;
    }
    if (!current) continue;
    const ip = line.match(/IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)/i);
    if (ip) {
      current.ip = ip[1];
      current.ipLine = line;
    }
    const mask = line.match(/Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)/i);
    if (mask) {
      current.mask = mask[1];
      current.maskLine = line;
    }
    const gw = line.match(/Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)/i);
    if (gw) {
      current.gateway = gw[1];
      current.gwLine = line;
    }
  }
  flush();

  if (!adapters.length) {
    const addrs = [];
    let gw = null;
    let gwLine = null;
    for (const line of lines) {
      const inet = line.match(/\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
      if (inet && !inet[1].startsWith('127.')) addrs.push({ ip: inet[1], prefix: Number(inet[2]), line });
      const via = line.match(/default via\s+(\d+\.\d+\.\d+\.\d+)/);
      if (via) {
        gw = via[1];
        gwLine = line;
      }
    }
    if (gw) {
      for (const addr of addrs) {
        adapters.push({
          name: 'linux',
          ip: addr.ip,
          prefix: addr.prefix,
          gateway: gw,
          ipLine: addr.line,
          maskLine: null,
          gwLine,
        });
      }
    }
  }
  return adapters;
}

function parseConfigInterfaces(blocks) {
  return blocks.filter((block) => block.kind === 'interface').map((block) => {
    let ip = null;
    let prefix = null;
    let nat = null;
    let addrLine = null;
    for (let i = 0; i < block.body.length; i += 1) {
      const line = block.body[i];
      const addr = line.match(/^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (addr) {
        ip = addr[1];
        prefix = maskToPrefix(addr[2]);
        addrLine = block.rawBody[i];
      }
      if (/^ip nat inside\b/i.test(line)) nat = 'inside';
      if (/^ip nat outside\b/i.test(line)) nat = 'outside';
    }
    return { name: block.name, ip, prefix, nat, addrLine, header: block.header };
  });
}

function parseOspfNetworks(blocks) {
  const networks = [];
  for (const block of blocks) {
    if (block.kind !== 'router' || !/^ospf\b/i.test(block.name)) continue;
    const processMatch = block.name.match(/(\d+)/);
    const processId = processMatch ? processMatch[1] : '1';
    for (let i = 0; i < block.body.length; i += 1) {
      const match = block.body[i].match(/^network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\S+)/i);
      if (!match) continue;
      const prefix = wildcardToPrefix(match[2]);
      if (prefix == null) continue;
      networks.push({
        network: match[1],
        wildcard: match[2],
        prefix,
        area: match[3],
        processId,
        line: block.rawBody[i],
      });
    }
  }
  return networks;
}

function parseRssi(lines) {
  for (const line of lines) {
    const match = line.match(/RSSI\)?[.\s]*(-?\d+)\s*dBm/i) || line.match(/\bRSSI\b[.\s:]*(-?\d+)\s*dBm/i);
    if (match) return { value: Number(match[1]), line };
  }
  return null;
}

function parseSnr(lines) {
  for (const line of lines) {
    const match = line.match(/Signal to Noise Ratio[.\s]*(\d+)\s*dB/i) || line.match(/\bSNR\b[.\s:]*(\d+)\s*dB/i);
    if (match) return { value: Number(match[1]), line };
  }
  return null;
}

function parse24Aps(text) {
  const idx = text.search(/dot11\s+24ghz|2\.4\s*GHz/i);
  if (idx < 0) return [];
  const aps = [];
  for (const line of text.slice(idx).split('\n').slice(0, 40)) {
    if (/^[A-Za-z0-9_.-]+#/.test(line)) break;
    const match = line.match(/^([A-Za-z][\w.-]+)\s+(\d{1,2})\s*$/);
    if (!match) continue;
    const channel = Number(match[2]);
    if (channel >= 1 && channel <= 14) aps.push({ name: match[1], channel, line });
  }
  return aps;
}

function hypotheses(id, ctx) {
  const evidence = ctx.symptomLine ? [ctx.symptomLine] : [];
  const vlan = ctx.symptoms.vlans[0];
  if (id === 'routing' && (ctx.symptoms.internet || ctx.symptoms.reach) && !ctx.symptoms.ipWorksNamesFail) {
    return [finding('routing', {
      id: 'hyp-default-route',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: 'A missing default route would explain the reachability loss',
      fix: 'Check the routing table. If the gateway of last resort is not set, add a default route toward the ISP next hop.',
      evidence,
      commands: ['show ip route', 'ip route 0.0.0.0 0.0.0.0 <isp-next-hop>'],
    })];
  }
  if (id === 'layer12' && vlan) {
    return [finding('layer12', {
      id: 'hyp-vlan',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: `VLAN ${vlan} may be missing ports, an SVI, or a forwarding path`,
      fix: `Confirm VLAN ${vlan} exists, has access ports, and is allowed on the trunks. Then check spanning tree is not blocking it.`,
      evidence,
      commands: ['show vlan brief', `show spanning-tree vlan ${vlan}`, 'show ip interface brief'],
    })];
  }
  if (id === 'layer12' && ctx.symptoms.slow) {
    return [finding('layer12', {
      id: 'hyp-duplex',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: 'Slow transfers are often duplex or CRC errors',
      fix: 'Check the busy interface for half duplex, CRC errors, and late collisions, then make both ends use the same speed and duplex.',
      evidence,
      commands: ['show interfaces', 'show interfaces status'],
    })];
  }
  if (id === 'services' && (ctx.symptoms.internet || ctx.symptoms.reach)) {
    return [finding('services', {
      id: 'hyp-nat-dns',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: 'NAT or DNS may be dropping traffic after the LAN',
      fix: 'If pings to 8.8.8.8 work but names do not, fix DNS. If the NAT table stays empty, the inside ACL or ip nat inside is missing.',
      evidence,
      commands: ['show ip nat translations', 'ping 8.8.8.8', 'ping google.com'],
    })];
  }
  if (id === 'ip' && (ctx.symptoms.internet || ctx.symptoms.reach || vlan)) {
    return [finding('ip', {
      id: 'hyp-gateway',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: 'The host mask or gateway may not match the LAN',
      fix: 'The default gateway has to be an address inside the host subnet. Compare ipconfig with the SVI address and mask.',
      evidence,
      commands: ['ipconfig /all', 'show ip interface brief'],
    })];
  }
  if (id === 'security' && ctx.symptoms.security) {
    return [finding('security', {
      id: 'hyp-security',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: 'Management access may be open or using a weak password',
      fix: 'Review VTY transport, enable secret, SNMP communities, and HTTP. Telnet and the password "cisco" should not survive a pass.',
      evidence,
      commands: ['show running-config', 'show ip ssh'],
    })];
  }
  // A chosen device is not evidence. Wireless still needs wireless text.
  if (id === 'wireless' && ctx.symptoms.wireless) {
    return [finding('wireless', {
      id: 'hyp-wireless',
      severity: 'medium',
      hypothesis: true,
      order: 1,
      title: 'Wireless drops are usually signal, overlap, or the CAPWAP path',
      fix: 'Check client RSSI and SNR, then confirm 2.4 GHz radios use channels 1, 6, and 11 only.',
      evidence,
      commands: ['show client detail <client-mac>', 'show ap dot11 24ghz summary'],
    })];
  }
  return [];
}

function analyzeLayer12(ctx) {
  const out = [];
  const cdpLines = ctx.lines.filter((line) => /DUPLEX_MISMATCH/i.test(line));
  for (const block of ctx.ifaceBlocks) {
    const half = block.duplex === 'half';
    const mismatch = block.late > 0 || cdpLines.some((line) => line.includes(block.name)) || (half && (block.crc > 0 || block.inputErrors > 0));
    if (mismatch) {
      const evidence = [block.header];
      for (const line of block.body) {
        if (/half-duplex|late collision|CRC|input errors/i.test(line)) evidence.push(line.replace(/\s+$/, ''));
      }
      for (const line of cdpLines) if (line.includes(block.name)) evidence.push(line);
      const speed = block.speed && block.speed < 1000 ? block.speed : (block.speed || 100);
      out.push(finding('layer12', {
        id: 'l12-duplex-mismatch',
        severity: 'critical',
        order: nextOrder(ctx),
        title: `${block.name} shows a duplex mismatch`,
        fix: 'Late collisions and CRC errors mean the two ends disagree on duplex. Set both sides to the same speed and duplex, then clear the counters.',
        evidence: unique(evidence),
        commands: [
          `interface ${block.name}`,
          ' duplex full',
          ` speed ${speed}`,
          `clear counters ${block.name}`,
        ],
      }));
    } else if (half) {
      out.push(finding('layer12', {
        id: 'l12-half-duplex',
        severity: 'high',
        order: nextOrder(ctx),
        title: `${block.name} is running half duplex`,
        fix: 'Half duplex on a modern link usually means a mismatch waiting to happen. Set both ends to full duplex at the same speed, or both to auto.',
        evidence: block.body.filter((line) => /half-duplex/i.test(line)).map((line) => line.replace(/\s+$/, '')),
        commands: [`interface ${block.name}`, ' duplex full', ' speed auto'],
      }));
    }
    if (block.crc > 0 || block.inputErrors >= 50) {
      const evidence = block.body
        .filter((line) => /CRC|input errors/i.test(line))
        .map((line) => line.replace(/\s+$/, ''));
      out.push(finding('layer12', {
        id: 'l12-crc',
        severity: 'high',
        order: nextOrder(ctx),
        title: `${block.name} is taking input errors${block.crc ? ` (${block.crc} CRC)` : ''}`,
        fix: 'CRC and input errors point at the cable, the SFP, or a duplex mismatch. Reseat or replace the cable, then compare error counters again.',
        evidence: evidence.length ? evidence : [block.header],
        commands: [`show interfaces ${block.name} counters errors`, `clear counters ${block.name}`],
      }));
    }
    if (block.reliability != null && block.reliability < 255) {
      const evidence = block.body
        .filter((line) => /reliability/i.test(line))
        .map((line) => line.replace(/\s+$/, ''));
      out.push(finding('layer12', {
        id: 'l12-reliability',
        severity: 'medium',
        order: nextOrder(ctx),
        title: `${block.name} reliability is ${block.reliability}/255`,
        fix: 'Reliability below 255/255 means the interface has been taking errors. Fix the physical or duplex problem, then confirm this climbs back to 255/255.',
        evidence,
        commands: [`show interfaces ${block.name}`, `clear counters ${block.name}`],
      }));
    }
    if (!block.admin && block.lineState === 'up' && block.protocol === 'down') {
      out.push(finding('layer12', {
        id: 'l12-protocol-down',
        severity: 'high',
        order: nextOrder(ctx),
        title: `${block.name} is up, line protocol is down`,
        fix: 'Layer 1 is up but keepalives or the far end are not. Check the cable, encapsulation, and clocking on the other side.',
        evidence: [block.header],
        commands: [`show interfaces ${block.name}`, `show controllers ${block.name}`],
      }));
    }
  }

  for (const row of ctx.brief) {
    if (row.status === 'up' && row.protocol === 'down' && !out.some((item) => item.id === 'l12-protocol-down' && item.evidence.includes(row.line))) {
      out.push(finding('layer12', {
        id: 'l12-protocol-down',
        severity: 'high',
        order: nextOrder(ctx),
        title: `${row.iface} is up/down`,
        fix: 'The interface is enabled but the line protocol is down. Check the cable and the device on the other end.',
        evidence: [row.line],
        commands: [`show interfaces ${row.iface}`],
      }));
    }
    if (/err-disabled/i.test(row.status) || /err-disabled/i.test(row.line)) {
      out.push(finding('layer12', {
        id: 'l12-err-disabled',
        severity: 'critical',
        order: nextOrder(ctx),
        title: `${row.iface} is err-disabled`,
        fix: 'Err-disable usually means BPDU Guard, port security, or a loop. Find the reason, fix the cause, then shut and no shut the port.',
        evidence: [row.line],
        commands: ['show errdisable recovery', `interface ${row.iface}`, ' shutdown', ' no shutdown'],
      }));
    }
  }

  for (const line of ctx.lines) {
    if (!/802\.1Q BPDU on non[- ]trunk/i.test(line)) continue;
    const ifaceMatch = line.match(/non[- ]trunk\s+(\S+)/i);
    const vlanMatch = line.match(/VLAN\s*0*(\d{1,4})/i);
    const iface = ifaceMatch ? ifaceMatch[1].replace(/[.,]$/, '') : 'the access port';
    const vlan = vlanMatch ? vlanMatch[1] : null;
    const commands = [`interface ${iface}`, ' switchport trunk encapsulation dot1q', ' switchport mode trunk'];
    if (vlan) commands.push(` switchport trunk allowed vlan add ${vlan}`);
    out.push(finding('layer12', {
      id: 'l12-bpdu-access',
      severity: 'high',
      order: nextOrder(ctx),
      title: `${iface} received a tagged BPDU on an access port`,
      fix: 'An access port is seeing 802.1Q BPDUs. Make this side a trunk if the far end is tagging, or stop tagging on the far end if it should be access.',
      evidence: [line],
      commands,
    }));
  }

  if (ctx.hasVlan) {
    for (const id of ctx.symptoms.vlans) {
      const vlan = ctx.vlans.find((item) => item.id === id);
      if (!vlan) {
        out.push(finding('layer12', {
          id: 'l12-vlan-missing',
          severity: 'high',
          order: nextOrder(ctx),
          title: `VLAN ${id} is not in the VLAN database`,
          fix: `Create VLAN ${id} on this switch and on every switch in the path. A VLAN that is only on the trunk allowed list still drops traffic if it does not exist.`,
          evidence: ctx.lines.filter((line) => new RegExp(`\\bvlan\\s*0*${id}\\b`, 'i').test(line)).slice(0, 2),
          commands: [`vlan ${id}`, ` name VLAN${id}`, 'show vlan brief'],
        }));
      } else if (vlan.status.startsWith('active') && !vlan.ports) {
        out.push(finding('layer12', {
          id: 'l12-vlan-empty',
          severity: 'high',
          order: nextOrder(ctx),
          title: `VLAN ${id} has no ports`,
          fix: `VLAN ${id} exists but no access port is in it, so users on that VLAN have no path. Assign the access ports, and allow the VLAN on the trunks.`,
          evidence: [vlan.line],
          commands: ['interface range GigabitEthernet0/1-2', ' switchport mode access', ` switchport access vlan ${id}`],
        }));
      }
    }
  }

  const blocked = ctx.lines.find((line) => /\b(Altn|BLK|Blocking)\b/.test(line) && /Gi|Fa|Te|Po|Eth/i.test(line));
  if (blocked) {
    out.push(finding('layer12', {
      id: 'l12-stp-blocking',
      severity: 'info',
      order: nextOrder(ctx),
      title: 'Spanning tree is blocking a redundant port',
      fix: 'An alternate port in BLK is normal when you have a loop-free redundant path. Worry about it only if the VLAN you need is the one being blocked.',
      evidence: [blocked],
      commands: ['show spanning-tree summary', 'show spanning-tree blockedports'],
    }));
  }

  for (const line of ctx.lines) {
    if (!/err-disabled/i.test(line)) continue;
    if (out.some((item) => item.id === 'l12-err-disabled' && item.evidence.includes(line))) continue;
    const iface = line.match(/\b((?:GigabitEthernet|FastEthernet|TenGigabitEthernet|Gi|Fa|Te|Eth)\S*)/i);
    out.push(finding('layer12', {
      id: 'l12-err-disabled',
      severity: 'critical',
      order: nextOrder(ctx),
      title: iface ? `${iface[1]} is err-disabled` : 'A port is err-disabled',
      fix: 'Err-disable usually means BPDU Guard, port security, or a loop. Find the reason, fix the cause, then shut and no shut the port.',
      evidence: [line],
      commands: ['show errdisable recovery', iface ? `interface ${iface[1]}` : 'show interfaces status', ' shutdown', ' no shutdown'],
    }));
  }

  return out;
}

function analyzeRouting(ctx) {
  const out = [];
  if (ctx.routes.noDefault && !ctx.hasStaticDefault && (ctx.symptoms.internet || ctx.hasNat)) {
    const evidence = ctx.lines.filter((line) => /Gateway of last resort is not set/i.test(line));
    out.push(finding('routing', {
      id: 'route-no-default',
      severity: ctx.symptoms.internet ? 'critical' : 'high',
      order: nextOrder(ctx),
      title: 'No default route to the internet',
      fix: 'The gateway of last resort is not set, so unknown destinations are dropped. Add a default route toward the ISP next hop.',
      evidence,
      commands: ['ip route 0.0.0.0 0.0.0.0 <isp-next-hop>', 'show ip route 0.0.0.0'],
    }));
  }

  const mtuPairs = [];
  const ospfIfs = ctx.ifaceBlocks.filter((block) => block.ospf && block.ip && block.mtu && block.prefix != null);
  for (let i = 0; i < ospfIfs.length; i += 1) {
    for (let j = i + 1; j < ospfIfs.length; j += 1) {
      const a = ospfIfs[i];
      const b = ospfIfs[j];
      if (a.ip === b.ip || a.mtu === b.mtu) continue;
      if (!sameSubnet(a, b)) continue;
      mtuPairs.push([a, b]);
    }
  }
  if (mtuPairs.length) {
    const [a, b] = mtuPairs[0];
    const low = a.mtu < b.mtu ? a : b;
    out.push(finding('routing', {
      id: 'ospf-mtu-mismatch',
      severity: 'critical',
      order: nextOrder(ctx),
      title: `OSPF MTU mismatch ${a.mtu} vs ${b.mtu}`,
      fix: `Neighbors that disagree on MTU stick in EXSTART and never exchange LSAs. Set both sides to ${Math.max(a.mtu, b.mtu)} bytes. Matching the higher side is the usual fix.`,
      evidence: [a.header, ...a.body.filter((line) => /MTU|Internet Address/i.test(line)), b.header, ...b.body.filter((line) => /MTU|Internet Address/i.test(line))]
        .map((line) => line.replace(/\s+$/, '')),
      commands: [
        `! on the side that shows MTU ${low.mtu}`,
        `interface ${low.name}`,
        ` mtu ${Math.max(a.mtu, b.mtu)}`,
        'show ip ospf neighbor',
      ],
    }));
  }

  for (const neighbor of ctx.ospfNeighbors) {
    if (!BAD_OSPF.has(neighbor.state)) continue;
    out.push(finding('routing', {
      id: 'ospf-stuck',
      severity: mtuPairs.length ? 'high' : 'critical',
      order: nextOrder(ctx),
      title: `OSPF neighbor ${neighbor.id} is stuck in ${neighbor.state}`,
      fix: neighbor.state === 'EXSTART'
        ? 'EXSTART almost always means the MTUs differ, or a duplicate router ID. Match the MTUs and confirm the router IDs are unique.'
        : `${neighbor.state} means the adjacency never finished. Check hello timers, area, authentication, MTU, and that the interface is not passive.`,
      evidence: [neighbor.line],
      commands: ['show ip ospf neighbor', `show ip ospf interface ${neighbor.iface}`, 'show ip ospf interface brief'],
    }));
  }

  for (const block of ctx.blocks) {
    if (block.kind !== 'router' || !/^ospf\b/i.test(block.name)) continue;
    let passiveDefault = false;
    const passive = [];
    const exempt = [];
    for (let i = 0; i < block.body.length; i += 1) {
      const line = block.body[i];
      if (/^passive-interface default$/i.test(line)) passiveDefault = true;
      const on = line.match(/^passive-interface\s+(\S+)/i);
      if (on && on[1].toLowerCase() !== 'default') passive.push({ iface: on[1], line: block.rawBody[i] });
      const off = line.match(/^no passive-interface\s+(\S+)/i);
      if (off) exempt.push(off[1]);
    }
    for (const neighbor of ctx.ospfNeighbors) {
      const named = passive.find((item) => item.iface.toLowerCase() === neighbor.iface.toLowerCase());
      const skipped = exempt.some((iface) => iface.toLowerCase() === neighbor.iface.toLowerCase());
      if (named || (passiveDefault && !skipped)) {
        out.push(finding('routing', {
          id: 'ospf-passive',
          severity: 'critical',
          order: nextOrder(ctx),
          title: `OSPF is passive on ${neighbor.iface}`,
          fix: 'A passive interface does not send or accept hellos, so the neighbor cannot form. Remove passive on the link that should have an adjacency.',
          evidence: named ? [named.line, neighbor.line] : [neighbor.line],
          commands: [`router ${block.name}`, ` no passive-interface ${neighbor.iface}`],
        }));
      }
    }
  }

  if (ctx.ospfNetworks.length || ctx.blocks.some((block) => block.kind === 'router' && /^ospf\b/i.test(block.name))) {
    const missing = [];
    for (const connected of ctx.routes.connected) {
      if (connected.code !== 'C' || connected.prefix > 30) continue;
      const covered = ctx.ospfNetworks.some((net) => covers(net.network, net.prefix, connected.network, connected.prefix));
      if (!covered) missing.push(connected);
    }
    if (missing.length) {
      const processId = ctx.ospfNetworks[0]?.processId
        || (ctx.blocks.find((block) => block.kind === 'router' && /^ospf\b/i.test(block.name))?.name.match(/(\d+)/)?.[1] || '1');
      const area = ctx.ospfNetworks[0]?.area || '0';
      const commands = [`router ospf ${processId}`];
      for (const item of missing) {
        commands.push(` network ${item.network} ${prefixToWildcard(item.prefix)} area ${area}`);
      }
      commands.push('show ip route ospf');
      out.push(finding('routing', {
        id: 'ospf-missing-network',
        severity: 'high',
        order: nextOrder(ctx),
        title: `OSPF is not advertising ${missing.map((item) => `${item.network}/${item.prefix}`).join(', ')}`,
        fix: 'Connected networks stay local until a network statement or ip ospf area covers them. Add the missing LAN so neighbors can learn it.',
        evidence: missing.map((item) => item.line),
        commands,
      }));
    }
  }

  const adjLines = ctx.lines.filter((line) => (
    /dead timer expired/i.test(line)
    || /neighbor down/i.test(line)
    || /stuck in (?:exstart|init|2-way|exchange|loading)/i.test(line)
    || (/hello(?:\s*\/\s*dead)? timers?/i.test(line) && /ospf|neighbor/i.test(line))
  ));
  if (adjLines.length && !out.some((item) => item.id.startsWith('ospf-'))) {
    out.push(finding('routing', {
      id: 'ospf-adjacency',
      severity: 'high',
      order: nextOrder(ctx),
      title: 'OSPF adjacency is down',
      fix: 'A neighbor that drops on a dead timer, or never leaves EXSTART, is usually a hello/dead timer mismatch, a different area, an MTU mismatch, authentication, or a network type mismatch. Compare show ip ospf interface on both ends before you change the route.',
      evidence: unique(adjLines).slice(0, 3),
      commands: ['show ip ospf neighbor', 'show ip ospf interface', 'show ip ospf interface brief'],
    }));
  }

  const sia = ctx.lines.find((line) => /stuck in active|\bSIA\b/.test(line));
  if (sia) {
    out.push(finding('routing', {
      id: 'eigrp-sia',
      severity: 'critical',
      order: nextOrder(ctx),
      title: 'EIGRP is stuck in active',
      fix: 'A route stuck in active means a query never came back. Find the neighbor that is not answering, then fix that link or summarize so queries stay bounded.',
      evidence: [sia],
      commands: ['show ip eigrp neighbors', 'show ip eigrp topology active'],
    }));
  }

  return out;
}

function analyzeIp(ctx) {
  const out = [];
  for (const adapter of ctx.adapters) {
    if (!adapter.ip || adapter.prefix == null || !adapter.gateway || adapter.gateway === '0.0.0.0') continue;
    if (inSubnet(adapter.gateway, adapter.ip, adapter.prefix)) continue;
    const network = intToIp(networkAddress(adapter.ip, adapter.prefix));
    const evidence = [adapter.ipLine, adapter.maskLine, adapter.gwLine].filter(Boolean);
    out.push(finding('ip', {
      id: 'ip-gateway-outside',
      severity: 'critical',
      order: nextOrder(ctx),
      title: `Gateway ${adapter.gateway} is outside ${network}/${adapter.prefix}`,
      fix: `A host can only ARP for a gateway inside its own subnet. Set the gateway to the router address on ${network}/${adapter.prefix}, or fix the mask if the LAN is supposed to be wider.`,
      evidence,
      commands: [
        `! host gateway must be inside ${network}/${adapter.prefix}`,
        `! Windows: netsh interface ip set address "${adapter.name.replace(/:$/, '')}" static ${adapter.ip} ${adapter.mask || prefixToMask(adapter.prefix)} <router-on-this-subnet>`,
        'show ip interface brief',
      ],
    }));
  }

  const subs = ctx.configIfs.filter((item) => item.ip && item.prefix != null && item.addrLine);
  for (let i = 0; i < subs.length; i += 1) {
    for (let j = i + 1; j < subs.length; j += 1) {
      const a = subs[i];
      const b = subs[j];
      if (a.name.toLowerCase() === b.name.toLowerCase()) continue;
      if (sameSubnet(a, b)) {
        out.push(finding('ip', {
          id: 'ip-duplicate-subnet',
          severity: 'high',
          order: nextOrder(ctx),
          title: `${a.name} and ${b.name} use the same subnet`,
          fix: 'Two interfaces in one subnet makes the router unsure where to forward. Give each link its own network.',
          evidence: [a.addrLine, b.addrLine],
          commands: [`interface ${b.name}`, ' ip address <new-network-address> <mask>'],
        }));
        continue;
      }
      if (!rangesOverlap(a, b)) continue;
      const aNet = `${intToIp(networkAddress(a.ip, a.prefix))}/${a.prefix}`;
      const bNet = `${intToIp(networkAddress(b.ip, b.prefix))}/${b.prefix}`;
      out.push(finding('ip', {
        id: 'ip-overlap',
        severity: 'critical',
        order: nextOrder(ctx),
        title: `${a.name} ${aNet} overlaps ${b.name} ${bNet}`,
        fix: `These ranges cover some of the same addresses, so forwarding is ambiguous. Renumber the wider or accidental interface so the two links no longer overlap.`,
        evidence: [a.addrLine, b.addrLine],
        commands: [
          `interface ${b.name}`,
          ` no ip address ${b.ip} ${prefixToMask(b.prefix)}`,
          ' ip address <non-overlapping-address> <mask>',
          'show ip interface brief',
        ],
      }));
    }
  }
  return out;
}

function prefixToMask(prefix) {
  if (prefix === 0) return '0.0.0.0';
  return intToIp((0xffffffff << (32 - prefix)) >>> 0);
}

function isApipaLine(line) {
  if (/\bapipa\b/i.test(line)) return true;
  const host = line.match(/\b(169\.254\.\d+\.\d+)\b/);
  if (host && host[1] !== '169.254.0.0') return true;
  return /\b169\.254\b/i.test(line) && /address|client|getting|lease|dhcp/i.test(line);
}

function isDnsLine(line) {
  return /could not find host|can't find host|cannot find host|Non-existent domain|Temporary failure in name resolution|server can't find/i.test(line)
    || /\bdns\b[^.\n]{0,48}\b(?:not resolv|fail|timeout|timed out|times out)/i.test(line)
    || /\bnslookup\b/i.test(line)
    || /\b(?:cannot|can't|can not)\s+resolve\b/i.test(line)
    || /\bname resolution (?:failed|timed out|times out)/i.test(line);
}

function analyzeServices(ctx) {
  const out = [];
  const natRules = [];
  const permits = [];
  for (const line of ctx.lines) {
    const nat = line.trim().match(/^ip nat inside source list\s+(\S+)\s+/i);
    if (nat) natRules.push({ list: nat[1], line });
    const acl = line.trim().match(/^access-list\s+(\d+)\s+permit\s+(?:(?:ip|tcp|udp|icmp)\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (acl) {
      const prefix = wildcardToPrefix(acl[3]);
      if (prefix != null) permits.push({ list: acl[1], network: acl[2], prefix, line });
    }
    const hit = line.match(/\bdeny\b.*\((\d+)\s+matches?\)/i);
    if (hit && Number(hit[1]) > 0) {
      out.push(finding('services', {
        id: 'acl-deny-hits',
        severity: 'high',
        order: nextOrder(ctx),
        title: `An ACL deny has ${hit[1]} hits`,
        fix: 'Packets are matching a deny line. If this traffic should pass, permit it above the deny. Remember there is an implicit deny at the end.',
        evidence: [line],
        commands: ['show access-lists', 'show ip interface | include access list'],
      }));
    }
  }

  if (natRules.length && permits.some((item) => natRules.some((rule) => rule.list === item.list))) {
    const missing = [];
    for (const connected of ctx.routes.connected) {
      if (connected.code !== 'C' || connected.prefix > 30 || !isPrivate(connected.network)) continue;
      const covered = permits.some((item) => natRules.some((rule) => rule.list === item.list) && covers(item.network, item.prefix, connected.network, connected.prefix));
      if (!covered) missing.push(connected);
    }
    if (missing.length) {
      const list = natRules[0].list;
      out.push(finding('services', {
        id: 'nat-subnet-missing',
        severity: 'high',
        order: nextOrder(ctx),
        title: `NAT ACL ${list} skips ${missing.map((item) => `${item.network}/${item.prefix}`).join(', ')}`,
        fix: 'Only subnets permitted by the NAT ACL are translated. Traffic from the missing subnet goes out with a private source and dies at the ISP.',
        evidence: [...permits.filter((item) => item.list === list).map((item) => item.line), ...missing.map((item) => item.line)],
        commands: missing.map((item) => `access-list ${list} permit ${item.network} ${prefixToWildcard(item.prefix)}`),
      }));
    }
  }

  const sawMark = ctx.configIfs.some((item) => item.nat);
  if (ctx.hasNat && sawMark) {
    const unmarked = [];
    for (const row of ctx.brief) {
      if (!row.ip || !isPrivate(row.ip)) continue;
      if (row.status === 'administratively down') continue;
      const cfg = ctx.configIfs.find((item) => item.name.toLowerCase() === row.iface.toLowerCase());
      if (cfg && cfg.nat) continue;
      unmarked.push(row);
    }
    if (unmarked.length) {
      const commands = [];
      for (const row of unmarked) commands.push(`interface ${row.iface}`, ' ip nat inside');
      out.push(finding('services', {
        id: 'nat-inside-missing',
        severity: 'high',
        order: nextOrder(ctx),
        title: `${unmarked.map((row) => row.iface).join(', ')} is not marked ip nat inside`,
        fix: 'NAT only translates traffic that arrives on an inside interface. Mark each user VLAN or LAN interface ip nat inside. The ISP-facing interface stays ip nat outside.',
        evidence: unmarked.map((row) => row.line),
        commands,
      }));
    }
  }

  for (const block of ctx.blocks) {
    if (block.kind !== 'ip dhcp pool') continue;
    let network = null;
    let prefix = null;
    let netLine = null;
    let gateway = null;
    let gwLine = null;
    for (let i = 0; i < block.body.length; i += 1) {
      const line = block.body[i];
      const net = line.match(/^network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+|\/?\d+)\s*$/i);
      if (net) {
        network = net[1];
        prefix = net[2].includes('.') ? maskToPrefix(net[2]) : Number(net[2].replace('/', ''));
        netLine = block.rawBody[i];
      }
      const gw = line.match(/^default-router\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (gw) {
        gateway = gw[1];
        gwLine = block.rawBody[i];
      }
    }
    if (network && gateway && prefix != null && !inSubnet(gateway, network, prefix)) {
      out.push(finding('services', {
        id: 'dhcp-bad-gateway',
        severity: 'critical',
        order: nextOrder(ctx),
        title: `DHCP pool ${block.name} hands out gateway ${gateway}`,
        fix: `The default router is not inside ${network}/${prefix}, so clients will install a gateway they cannot ARP. Point default-router at this subnet's SVI.`,
        evidence: [netLine, gwLine].filter(Boolean),
        commands: [`ip dhcp pool ${block.name}`, ` default-router <router-inside-${network}>`],
      }));
    }
  }

  const apipaLines = ctx.lines.filter(isApipaLine);
  if (apipaLines.length) {
    const host = apipaLines.join('\n').match(/\b(169\.254\.\d+\.\d+)\b/);
    const specific = host && host[1] !== '169.254.0.0' ? ` ${host[1]}` : '';
    out.push(finding('services', {
      id: 'dhcp-apipa',
      severity: 'high',
      order: nextOrder(ctx),
      title: `Clients fell back to APIPA${specific}`,
      fix: '169.254 means the client never got a DHCP lease. Check that the DHCP server is up, the scope is not exhausted, the client VLAN can reach that server, and ip helper-address is set when the server is on another subnet.',
      evidence: apipaLines.slice(0, 2),
      commands: ['show ip dhcp binding', 'show ip dhcp pool', 'ip helper-address <dhcp-server>'],
    }));
  }

  const dnsLines = ctx.lines.filter(isDnsLine);
  if (dnsLines.length || ctx.symptoms.ipWorksNamesFail) {
    const ipFails = ctx.lines.some((line) => /100%\s*(packet )?loss|Lost = \d+ \(100% loss\)|Request timed out/i.test(line));
    const namesOnly = ctx.symptoms.ipWorksNamesFail && !ipFails;
    const evidence = dnsLines.length ? dnsLines.slice(0, 2) : [ctx.symptomLine].filter(Boolean);
    out.push(finding('services', {
      id: 'dns-lookup-failed',
      severity: namesOnly || !ipFails ? 'high' : 'medium',
      order: nextOrder(ctx),
      title: namesOnly
        ? 'DNS is failing even though the IP address answers'
        : (ipFails ? 'Names fail, and numeric pings are failing too' : 'DNS lookup failed'),
      fix: namesOnly
        ? 'A ping to a numeric address works, so a missing default route is not the first problem. Set a DNS server the host can reach, on the client or in the DHCP pool, then try the name again.'
        : (ipFails
          ? 'Fix reachability first. A name lookup will keep failing while the host cannot reach a DNS server.'
          : 'The host can use addresses but not names. Set a reachable DNS server on the client or in the DHCP pool.'),
      evidence,
      commands: ['ping 8.8.8.8', 'nslookup google.com', 'show ip dhcp pool'],
    }));
  }

  const loss = ctx.lines.filter((line) => /100%\s*(packet )?loss|Lost = \d+ \(100% loss\)/i.test(line));
  if (loss.length) {
    out.push(finding('services', {
      id: 'reach-total-loss',
      severity: 'medium',
      order: nextOrder(ctx),
      title: 'Pings in this paste failed completely',
      fix: '100% loss means the path, the gateway, or the ACL is dropping everything to that destination. Fix the higher findings first, then ping again.',
      evidence: loss.slice(0, 3),
      commands: ['ping <gateway>', 'traceroute <destination>'],
    }));
  }

  return out;
}

function analyzeSecurity(ctx) {
  const out = [];
  const weakLines = [];
  const globals = ctx.lines.filter((line) => line.trim() && !/^\s/.test(line));

  for (const line of globals) {
    const trimmed = line.trim();
    if (/^no enable password\b/i.test(trimmed)) continue;
    if (/^enable\s+password\s+7\s+\S+/i.test(trimmed)) {
      out.push(finding('security', {
        id: 'sec-type7',
        severity: 'high',
        order: nextOrder(ctx),
        title: 'Enable password is Cisco type 7',
        fix: 'Type 7 is reversible. Replace it with enable secret, which stores a real hash.',
        evidence: [line],
        commands: ['no enable password', 'enable secret <strong-secret>'],
      }));
      weakLines.push(line);
    } else if (/^enable\s+password\s+(\S+)/i.test(trimmed)) {
      const word = trimmed.match(/^enable\s+password\s+(\S+)/i)[1];
      out.push(finding('security', {
        id: 'sec-enable-password',
        severity: 'high',
        order: nextOrder(ctx),
        title: 'Enable is a cleartext password, not a secret',
        fix: 'enable password stores a weak secret and loses to enable secret. Remove it and set enable secret.',
        evidence: [line],
        commands: ['no enable password', 'enable secret <strong-secret>'],
      }));
      if (isWeak(word)) weakLines.push(line);
    } else if (/^enable\s+secret\s+(5|8|9)\s+\S+/i.test(trimmed)) {
      // hashed enable secret
    } else if (/^enable\s+secret\s+(?:0\s+)?(\S+)/i.test(trimmed)) {
      const word = trimmed.match(/^enable\s+secret\s+(?:0\s+)?(\S+)/i)[1];
      if (isWeak(word)) weakLines.push(line);
    }

    const user = trimmed.match(/^username\s+(\S+)\s+password(?:\s+0)?\s+(\S+)/i);
    if (user) {
      out.push(finding('security', {
        id: 'sec-user-plaintext',
        severity: 'high',
        order: nextOrder(ctx),
        title: `User ${user[1]} has a cleartext password`,
        fix: 'username password is stored weakly. Recreate the account with secret so the hash replaces the cleartext.',
        evidence: [line],
        commands: [`username ${user[1]} privilege 15 secret <strong-secret>`],
      }));
      if (isWeak(user[2])) weakLines.push(line);
    }
    if (/^no\s+service\s+password-encryption\b/i.test(trimmed)) {
      out.push(finding('security', {
        id: 'sec-no-encryption',
        severity: 'medium',
        order: nextOrder(ctx),
        title: 'Password encryption is turned off',
        fix: 'Turn service password-encryption on so line passwords are not sitting in cleartext in show run. It is not a substitute for enable secret.',
        evidence: [line],
        commands: ['service password-encryption'],
      }));
    }
    if (/^ip http server\s*$/i.test(trimmed)) {
      out.push(finding('security', {
        id: 'sec-http',
        severity: 'high',
        order: nextOrder(ctx),
        title: 'Cleartext HTTP management is enabled',
        fix: 'ip http server accepts the admin password in cleartext. Turn it off and use HTTPS, or better, SSH only.',
        evidence: [line],
        commands: ['no ip http server', 'ip http secure-server'],
      }));
    }
  }

  const snmp = [];
  for (const line of ctx.lines) {
    const match = line.trim().match(/^snmp-server\s+community\s+(\S+)\s+(RO|RW)\b/i);
    if (match) snmp.push({ community: match[1], mode: match[2].toUpperCase(), line });
  }
  const badSnmp = snmp.filter((item) => isWeak(item.community) || item.mode === 'RW');
  if (badSnmp.length) {
    const writable = badSnmp.some((item) => item.mode === 'RW');
    out.push(finding('security', {
      id: 'sec-snmp',
      severity: writable ? 'critical' : 'high',
      order: nextOrder(ctx),
      title: writable ? 'SNMP community is writable or still a default name' : 'SNMP still uses a default community',
      fix: 'public and private are the first names every scanner tries. A RW community can change the config. Remove them and set a long read-only community, or move to SNMPv3.',
      evidence: badSnmp.map((item) => item.line),
      commands: badSnmp.map((item) => `no snmp-server community ${item.community}`).concat(['snmp-server community <read-only-secret> RO']),
    }));
  }

  const telnetLines = [];
  let vtyOpen = false;
  for (const block of ctx.blocks) {
    if (block.kind !== 'line') continue;
    const isVty = /^vty\b/i.test(block.name);
    const transports = [];
    for (let i = 0; i < block.body.length; i += 1) {
      const line = block.body[i];
      if (/^transport input\b/i.test(line)) transports.push(block.rawBody[i]);
      const pass = line.match(/^password(?:\s+0)?\s+(\S+)/i);
      if (pass && isWeak(pass[1])) weakLines.push(block.rawBody[i]);
      if (/^password\s+7\s+\S+/i.test(line)) weakLines.push(block.rawBody[i]);
    }
    if (!isVty) continue;
    if (!transports.length) vtyOpen = true;
    for (const line of transports) {
      if (/\ball\b|\btelnet\b/i.test(line)) telnetLines.push(line);
    }
  }
  if (telnetLines.length) {
    const vty = ctx.blocks.find((block) => block.kind === 'line' && /^vty\b/i.test(block.name));
    out.push(finding('security', {
      id: 'sec-telnet',
      severity: 'critical',
      order: 0,
      title: 'VTY still accepts Telnet',
      fix: 'Telnet sends the password in cleartext. Restrict VTY to SSH, and generate an RSA key if the device does not have one yet.',
      evidence: telnetLines,
      commands: [
        'ip domain-name lab.local',
        'crypto key generate rsa modulus 2048',
        'ip ssh version 2',
        vty ? `line ${vty.name}` : 'line vty 0 4',
        ' transport input ssh',
        ' login local',
        ' exec-timeout 5 0',
      ],
    }));
  } else if (vtyOpen) {
    out.push(finding('security', {
      id: 'sec-vty-open',
      severity: 'medium',
      order: nextOrder(ctx),
      title: 'VTY does not restrict transport to SSH',
      fix: 'With no transport input line, Telnet is still possible. Set transport input ssh on the VTY lines.',
      evidence: ctx.blocks.filter((block) => block.kind === 'line' && /^vty\b/i.test(block.name)).map((block) => block.header),
      commands: ['line vty 0 4', ' transport input ssh', ' login local'],
    }));
  }

  if (weakLines.length) {
    const severe = weakLines.some((line) => /\b(cisco|public|private)\b/i.test(line));
    out.push(finding('security', {
      id: 'sec-weak-password',
      severity: severe ? 'critical' : 'high',
      order: nextOrder(ctx),
      title: 'A default or well-known password is configured',
      fix: 'Replace cisco, admin, public, and private. Use enable secret and username secret with a long passphrase that is not a dictionary word.',
      evidence: unique(weakLines),
      commands: ['enable secret <strong-secret>', 'service password-encryption'],
    }));
  }

  return dedupe(out);
}

function analyzeWireless(ctx) {
  const out = [];
  const { rssi, snr, aps } = ctx.wireless;
  if (rssi || snr) {
    const rssiBad = rssi && rssi.value <= -75;
    const snrBad = snr && snr.value <= 20;
    const terrible = (rssi && rssi.value <= -80) || (snr && snr.value <= 15);
    if (rssiBad || snrBad) {
      const bits = [];
      if (rssi) bits.push(`${rssi.value} dBm`);
      if (snr) bits.push(`SNR ${snr.value} dB`);
      out.push(finding('wireless', {
        id: 'wifi-weak-signal',
        severity: terrible ? 'critical' : 'high',
        order: nextOrder(ctx),
        title: `Client signal is too weak (${bits.join(', ')})`,
        fix: 'Voice and data start to fall apart under about -75 dBm or SNR 20. Move the client, add an AP closer to the users, or remove the obstruction. Fixing overlapping channels will not repair a -82 dBm client.',
        evidence: [rssi?.line, snr?.line].filter(Boolean),
        commands: ['show client detail <client-mac>', 'show ap summary'],
      }));
    }
  }

  if (aps.length && aps.some((ap) => ![1, 6, 11].includes(ap.channel))) {
    const plan = [1, 6, 11];
    out.push(finding('wireless', {
      id: 'wifi-channel-overlap',
      severity: 'high',
      order: nextOrder(ctx),
      title: '2.4 GHz channels overlap',
      fix: 'In 2.4 GHz only channels 1, 6, and 11 do not overlap. Adjacent numbers like 1, 2, and 3 share the same airtime and look like interference to every client.',
      evidence: aps.map((ap) => ap.line),
      commands: aps.map((ap, index) => `ap name ${ap.name} dot11 24ghz channel ${plan[index % plan.length]}`),
    }));
  } else if (aps.length) {
    const counts = new Map();
    for (const ap of aps) counts.set(ap.channel, (counts.get(ap.channel) || 0) + 1);
    const crowded = [...counts.entries()].filter(([, count]) => count > 1);
    if (crowded.length && aps.length > 2) {
      out.push(finding('wireless', {
        id: 'wifi-cochannel',
        severity: 'medium',
        order: nextOrder(ctx),
        title: `More than one AP is on channel ${crowded[0][0]}`,
        fix: 'Reuse 1, 6, and 11 so neighboring APs are not on the same channel. Same-channel APs have to take turns.',
        evidence: aps.map((ap) => ap.line),
        commands: ['show ap dot11 24ghz summary'],
      }));
    }
  }
  return out;
}

function nextAsk(specId, ctx, findings) {
  const hot = findings.some((item) => !item.hypothesis && (item.severity === 'critical' || item.severity === 'high'));
  if (hot) return null;
  const hyp = findings.find((item) => item.hypothesis && item.commands?.length);
  if (hyp) {
    const cmd = hyp.commands.find((line) => /^show\s|^ipconfig\b|^ping\s/i.test(line.trim())) || hyp.commands[0];
    return { cmd: cmd.trim(), why: hyp.title, specialistId: specId };
  }
  if (ctx.sparse) return null;
  const has = (snippet) => ctx.text.toLowerCase().includes(snippet.toLowerCase());

  if (specId === 'layer12') {
    if (ctx.symptoms.vlans.length && ctx.hasVlan && !has('show spanning-tree')) {
      return { cmd: `show spanning-tree vlan ${ctx.symptoms.vlans[0]}`, why: 'See if spanning tree is blocking this VLAN', specialistId: specId };
    }
    if (ctx.symptoms.vlans.length && !ctx.hasVlan && !has('show vlan brief')) {
      return { cmd: 'show vlan brief', why: 'Confirm the VLAN exists and which ports are in it', specialistId: specId };
    }
    if (ctx.symptoms.slow && !ctx.hasIfaceBlocks && !has('show interfaces')) {
      return { cmd: 'show interfaces', why: 'Check duplex, CRC, and line protocol', specialistId: specId };
    }
    if (!ctx.hasIpBrief && !has('show ip interface brief')) {
      return { cmd: 'show ip interface brief', why: 'See which interfaces are up or down', specialistId: specId };
    }
  }
  if (specId === 'routing') {
    if ((ctx.symptoms.internet || ctx.symptoms.reach) && !ctx.hasRoute && !has('show ip route')) {
      return { cmd: 'show ip route', why: 'Check the default route and connected networks', specialistId: specId };
    }
    if (/ospf/i.test(ctx.text) && !ctx.ospfNeighbors.length && !has('show ip ospf neighbor')) {
      return { cmd: 'show ip ospf neighbor', why: 'Check whether neighbors reached FULL', specialistId: specId };
    }
  }
  if (specId === 'ip' && (ctx.deviceType === 'pc' || ctx.deviceType === 'auto')) {
    if (!ctx.adapters.length && !ctx.configIfs.some((item) => item.ip) && (ctx.symptoms.reach || ctx.symptoms.internet) && !has('ipconfig')) {
      return { cmd: 'ipconfig /all', why: 'Check the host address, mask, and gateway', specialistId: specId };
    }
  }
  if (specId === 'services') {
    if ((ctx.hasNat || ctx.symptoms.internet) && !has('show ip nat translations')) {
      return { cmd: 'show ip nat translations', why: 'See whether inside hosts are being translated', specialistId: specId };
    }
  }
  if (specId === 'security') {
    const wants = ctx.deviceType === 'router' || ctx.deviceType === 'switch' || ctx.symptoms.security;
    if (wants && !ctx.hasSecurityConfig && !has('show running-config')) {
      return { cmd: 'show running-config', why: 'Look for Telnet, SNMP, and weak passwords', specialistId: specId };
    }
  }
  if (specId === 'wireless') {
    const wants = ctx.symptoms.wireless || ctx.deviceType === 'wireless';
    if (wants && !ctx.wireless.rssi && !has('show client detail')) {
      return { cmd: 'show client detail <client-mac>', why: 'Check RSSI, SNR, and which AP the client is on', specialistId: specId };
    }
  }
  return null;
}

function coordinate(reports, ctx) {
  const all = reports.flatMap((report) => report.findings.map((item) => ({
    ...item,
    specialistId: report.id,
    specialist: report.name,
  })));
  all.sort((a, b) => (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) || (a.order - b.order));
  const actions = all.filter((item) => item.severity !== 'info');
  const notes = all.filter((item) => item.severity === 'info');
  const provisional = actions.length > 0 && actions.every((item) => item.hypothesis);
  let confidence = score(actions, ctx);
  if (provisional) confidence = Math.min(confidence, 46);
  if (!actions.length) confidence = ctx.sparse ? 18 : 52;

  const seen = new Set();
  const followups = [];
  for (const report of reports) {
    if (!report.ask) continue;
    const key = report.ask.cmd.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    followups.push({ ...report.ask, specialist: report.name });
    if (followups.length === 4) break;
  }

  return {
    headline: actions[0]?.title || (ctx.text.trim() ? 'No definite fault in this paste' : 'Paste output or a symptom'),
    narrative: buildNarrative(actions, provisional, ctx),
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    provisional,
    actions,
    notes,
    followups,
    script: buildScript(actions),
  };
}

function score(actions, ctx) {
  if (!actions.length) return 20;
  let value = 38;
  const weight = { critical: 24, high: 14, medium: 7, low: 2, info: 0 };
  for (const action of actions) value += weight[action.severity] || 0;
  const specs = new Set(actions.map((action) => action.specialistId));
  if (specs.size >= 2) value += 8;
  if (!ctx.sparse) value += 6;
  return Math.max(12, Math.min(96, value));
}

function buildNarrative(actions, provisional, ctx) {
  if (!ctx.text.trim()) return 'Paste Cisco show output, ping or ipconfig text, an error, or a one-line symptom. The rule engine reads it on this device.';
  if (!actions.length) return 'Nothing in this paste rose to a fault. If users are still down, run a suggested show command and paste the output back — analysis starts on its own.';
  const top = actions.slice(0, 3);
  const rest = top.slice(1).map((item) => item.title).join('. ');
  const extra = rest ? ` Also: ${rest}.` : '';
  const note = provisional ? ' This is a hypothesis from the symptom alone. Paste show output before changing config.' : '';
  return `${top[0].title}. ${top[0].fix}${extra}${note}`;
}

function buildScript(actions) {
  const lines = ['! StarSwarm Security Agentic Toolkit — read it, then paste on the device'];
  const list = actions.filter((item) => item.commands?.length).slice(0, 8);
  if (!list.length) {
    lines.push('! No configuration changes suggested from this paste.');
    return lines.join('\n');
  }
  const used = new Set();
  list.forEach((item, index) => {
    lines.push(`! ${index + 1}. [${item.severity}] ${item.title}`);
    for (const command of item.commands) {
      const key = command.trim();
      if (!key) continue;
      if (key.startsWith('!')) {
        lines.push(command);
        continue;
      }
      if (used.has(key)) continue;
      used.add(key);
      lines.push(command);
    }
  });
  return lines.join('\n');
}

function unique(list) {
  const seen = new Set();
  const out = [];
  for (const item of list) {
    if (!item || seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

function dedupe(list) {
  const seen = new Set();
  const out = [];
  for (const item of list) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    out.push(item);
  }
  return out;
}
