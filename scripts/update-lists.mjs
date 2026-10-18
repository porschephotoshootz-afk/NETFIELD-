/**
 * Refresh the network-gear slice of the CISA Known Exploited Vulnerabilities catalog.
 * Usage: node scripts/update-lists.mjs
 * Writes data/threats.json and the advisory entries in data/hotfixes.json.
 * The home and small-business checklist in hotfixes.json is kept as shipped.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const SINCE = '2025-01-01';
const MAX = 36;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const INCLUDE = /router|firewall|vpn|nas\b|wi-?fi|access point|camera|fortios|fortigate|fortiweb|pan-os|sonicwall|netscaler|routeros|unifi|tp-link|zyxel|d-link|qnap|synology|hikvision|connect secure|firebox|adaptive security|threat defense|gateway|sma100|watchguard|ubiquiti|mikrotik|pulse secure|draytek|linksys|netgear|asus\b|iot/i;
const EXCLUDE = /email gateway|identity services|fortimail|fortisandbox|forticlient|smartconsole|session recording|unified communications|endpoint manager/i;

const CHECKLIST = [
  {
    id: 'ncsc-updates',
    title: 'Install software and firmware updates',
    detail: 'Software and app updates contain security fixes that protect devices. On a router, firewall, VPN, or NAS, install the vendor firmware update the same way.',
    source: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online',
    updated: '2026-10-18',
  },
  {
    id: 'ncsc-mfa',
    title: 'Turn on 2-step verification',
    detail: 'NCSC recommends 2-step verification to protect online accounts. Use it on email, the router admin page, and anywhere a password is the only lock.',
    source: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online',
    updated: '2026-10-18',
  },
  {
    id: 'ncsc-password',
    title: 'Use a strong, separate password for email',
    detail: 'NCSC says a criminal who gets your email can reach many other accounts. Use a password manager, and make the email password strong and different from the rest.',
    source: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online',
    updated: '2026-10-18',
  },
  {
    id: 'ncsc-backup',
    title: 'Back up the files you cannot replace',
    detail: 'NCSC says to safeguard important data by backing it up to an external drive or cloud storage.',
    source: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online',
    updated: '2026-10-18',
  },
  {
    id: 'cis-auth',
    title: 'Turn on authentication and encryption on the router',
    detail: 'The CIS telework and small-office guide recommends enabling authentication and encryption on home routers and modems, which are the on-ramp from your network to the internet.',
    source: 'https://www.cisecurity.org/insights/blog/small-offices-big-security-new-guide-for-securing-telework-environments',
    updated: '2026-10-18',
  },
  {
    id: 'cis-services',
    title: 'Turn off router services you do not use',
    detail: 'The same CIS guide says to turn off unneeded services that an attacker can use, and to maintain the device and dispose of it with care when you replace it.',
    source: 'https://www.cisecurity.org/insights/blog/small-offices-big-security-new-guide-for-securing-telework-environments',
    updated: '2026-10-18',
  },
  {
    id: 'nist-index',
    title: 'Read the small-office network guides NIST points to',
    detail: 'NIST Small Business Cybersecurity Corner lists a firewall overview, the NSA home-network best practices, and the CIS telework guide for securing routers and modems.',
    source: 'https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/securing-network-connections',
    updated: '2026-08-24',
  },
];

function severity(entry) {
  if (entry.knownRansomwareCampaignUse === 'Known') return 'critical';
  const blob = `${entry.vendorProject} ${entry.product} ${entry.vulnerabilityName}`;
  if (/router|firewall|vpn|gateway|routeros|fortios|pan-os|netscaler|connect secure/i.test(blob)) return 'high';
  return 'medium';
}

function cleanUrl(url) {
  const parsed = new URL(url);
  for (const key of [...parsed.searchParams.keys()]) {
    if (key.toLowerCase().startsWith('utm_')) parsed.searchParams.delete(key);
  }
  return parsed.toString();
}

function advisoryUrl(notes, cve) {
  const notesFixed = String(notes || '').replace(/https:\/(?!\/)/g, 'https://');
  const urls = notesFixed.match(/https:\/\/[^\s;,)]+/g) || [];
  const vendor = urls
    .map((url) => {
      try { return cleanUrl(url); } catch { return ''; }
    })
    .find((url) => url && !/cisa\.gov|nvd\.nist\.gov/i.test(url));
  return vendor || `https://nvd.nist.gov/vuln/detail/${cve}`;
}

function plainFix(vendor, product) {
  return `Install the current security update for ${vendor} ${product}. If the vendor has no fix, take that product off the internet.`;
}

function toThreat(entry) {
  const cve = entry.cveID;
  const advisory = advisoryUrl(entry.notes, cve);
  return {
    id: cve,
    cve,
    vendor: entry.vendorProject,
    product: entry.product,
    name: entry.vulnerabilityName,
    dateAdded: entry.dateAdded,
    updated: entry.dateAdded,
    severity: severity(entry),
    knownRansomware: entry.knownRansomwareCampaignUse === 'Known',
    description: entry.shortDescription,
    fix: plainFix(entry.vendorProject, entry.product),
    cisaAction: entry.requiredAction,
    dueDate: entry.dueDate,
    advisory,
    source: `https://nvd.nist.gov/vuln/detail/${cve}`,
  };
}

function writeJson(file, data) {
  fs.writeFileSync(path.join(root, file), `${JSON.stringify(data, null, 2)}\n`);
}

const response = await fetch(FEED);
if (!response.ok) throw new Error(`CISA feed HTTP ${response.status}`);
const catalog = await response.json();
const entries = (catalog.vulnerabilities || [])
  .filter((entry) => entry.dateAdded >= SINCE)
  .filter((entry) => INCLUDE.test(`${entry.vendorProject} ${entry.product} ${entry.vulnerabilityName}`))
  .filter((entry) => !EXCLUDE.test(`${entry.vendorProject} ${entry.product}`))
  .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
  .slice(0, MAX)
  .map(toThreat);

if (!entries.length) throw new Error('No network-gear entries matched. Refusing to wipe the list.');

const released = String(catalog.dateReleased || '').slice(0, 10);
writeJson('data/threats.json', {
  name: 'Cyber threats',
  updated: released,
  source: FEED,
  catalogVersion: catalog.catalogVersion,
  dateReleased: catalog.dateReleased,
  note: `Subset of the CISA Known Exploited Vulnerabilities catalog (${catalog.count} entries in catalog ${catalog.catalogVersion}). Kept to routers, firewalls, VPNs, NAS, and similar small-network gear added on or after ${SINCE}, newest ${MAX}. Regenerated by scripts/update-lists.mjs. Descriptions and required actions are copied from that feed.`,
  entries,
});

writeJson('data/hotfixes.json', {
  name: 'Network hotfixes',
  updated: released,
  source: FEED,
  note: 'Advisory rows are the vendor or NVD link CISA published for each threat in data/threats.json. The checklist rows are short notes from public guides fetched with this list. This is defensive guidance for your own network.',
  entries: entries.map((entry) => ({
    id: `patch-${entry.cve}`,
    cve: entry.cve,
    title: `Patch ${entry.vendor} ${entry.product}`,
    vendor: entry.vendor,
    product: entry.product,
    dateAdded: entry.dateAdded,
    updated: entry.updated,
    fix: entry.fix,
    cisaAction: entry.cisaAction,
    advisory: entry.advisory,
    source: entry.advisory,
  })),
  checklist: CHECKLIST,
});

console.log(`Wrote ${entries.length} threats and hotfixes. Catalog ${catalog.catalogVersion} released ${catalog.dateReleased}.`);
