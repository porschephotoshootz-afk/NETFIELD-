import fs from 'fs';
import {
  confidenceLabel,
  inSubnet,
  networkAddress,
  runSwarm,
  wildcardToPrefix,
} from '../js/analyzers.js';
import { redactSecrets } from '../js/deep.js';
import { SAMPLES } from '../js/samples.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed += 1;
    return;
  }
  failed += 1;
  console.error(`FAIL ${message}`);
}

function ids(result) {
  return result.summary.actions.map((item) => `${item.severity}:${item.id}`).join(', ');
}

function findAction(result, id) {
  return result.summary.actions.find((item) => item.id === id);
}

function evidenceStaysInsideInput(result, text) {
  const findings = result.reports.flatMap((report) => report.findings);
  for (const item of findings) {
    assert(item.evidence.length > 0, `${item.id} has no evidence`);
    assert(item.title && item.fix, `${item.id} missing title or fix`);
    assert(Array.isArray(item.commands), `${item.id} commands not an array`);
    for (const line of item.evidence) {
      assert(text.includes(line), `${item.id} evidence is not an exact line:\n${line}`);
    }
  }
}

assert(networkAddress('192.168.1.50', 24) === networkAddress('192.168.1.1', 24), 'same /24 network');
assert(inSubnet('192.168.1.1', '192.168.1.50', 24), 'gateway inside /24');
assert(!inSubnet('192.168.2.1', '192.168.1.50', 24), 'gateway outside /24');
assert(wildcardToPrefix('0.0.0.255') === 24, 'wildcard /24');
assert(wildcardToPrefix('0.0.0.3') === 30, 'wildcard /30');
assert(confidenceLabel(90) === 'High' && confidenceLabel(46) === 'Low', 'confidence labels');

const empty = runSwarm('');
assert(empty.reports.length === 6, 'six specialists on empty input');
assert(empty.summary.actions.length === 0, 'empty input has no actions');
assert(empty.summary.confidenceLabel === 'Low', 'empty confidence is low');

const symptom = 'users on VLAN 20 can\'t reach the internet';
const plain = runSwarm(symptom);
assert(plain.summary.provisional, 'plain symptom is provisional');
assert(plain.summary.confidence < 55, `plain confidence stays low (${plain.summary.confidence})`);
assert(plain.meta.sparse, 'plain symptom is sparse');
const plainCommands = [
  ...plain.summary.actions.flatMap((item) => item.commands),
  ...plain.summary.followups.map((item) => item.cmd),
].join('\n');
assert(plainCommands.includes('show ip route'), 'plain asks for show ip route');
assert(plainCommands.includes('show vlan brief'), 'plain asks for show vlan brief');
assert(plain.summary.script.includes('ip route 0.0.0.0 0.0.0.0'), 'plain script has a default route');
evidenceStaysInsideInput(plain, symptom);

const byId = Object.fromEntries(SAMPLES.map((sample) => [sample.id, sample]));
assert(Object.keys(byId).length === 6, 'six unique samples');

for (const sample of SAMPLES) {
  const result = runSwarm(sample.text, { deviceType: sample.deviceType });
  const again = runSwarm(sample.text, { deviceType: sample.deviceType });
  assert(JSON.stringify(result) === JSON.stringify(again), `${sample.id} is deterministic`);
  evidenceStaysInsideInput(result, sample.text);
  assert(result.summary.script.startsWith('! StarSwarm Security Agentic Toolkit'), `${sample.id} script header`);
  assert(result.summary.confidence >= 80, `${sample.id} confidence ${result.summary.confidence} (${ids(result)})`);
  assert(result.summary.confidenceLabel === 'High', `${sample.id} label`);
}

const vlan = runSwarm(byId['vlan20-internet'].text, { deviceType: 'switch' });
assert(vlan.summary.actions[0].id === 'route-no-default', `vlan top is default route (${ids(vlan)})`);
assert(findAction(vlan, 'nat-subnet-missing'), `vlan nat acl (${ids(vlan)})`);
assert(findAction(vlan, 'nat-inside-missing'), `vlan nat inside (${ids(vlan)})`);
assert(!findAction(vlan, 'ip-overlap'), 'vlan sample is not an overlap');
assert(!findAction(vlan, 'sec-telnet'), 'vlan sample is not telnet');
assert(vlan.summary.script.includes('ip route 0.0.0.0 0.0.0.0'), 'vlan script default route');
assert(vlan.summary.script.includes('192.168.20.0'), 'vlan script permits guest subnet');
assert(vlan.summary.script.includes('ip nat inside'), 'vlan script marks inside');
assert(vlan.summary.followups.some((item) => item.cmd.includes('show spanning-tree')), `vlan follow-up (${JSON.stringify(vlan.summary.followups)})`);

const duplex = runSwarm(byId['duplex-mismatch'].text, { deviceType: 'switch' });
assert(duplex.summary.actions[0].id === 'l12-duplex-mismatch', `duplex top (${ids(duplex)})`);
assert(findAction(duplex, 'l12-crc'), 'duplex crc finding');
assert(findAction(duplex, 'l12-reliability'), 'duplex reliability finding');
assert(!findAction(duplex, 'route-no-default'), 'duplex has no default-route finding');
assert(duplex.reports.find((item) => item.id === 'wireless').findings.length === 0, 'duplex wireless stays quiet');
assert(duplex.summary.script.includes('interface GigabitEthernet0/1'), 'duplex script names the port');
assert(duplex.summary.script.includes('duplex full'), 'duplex script sets full');

const ospf = runSwarm(byId['ospf-exstart'].text, { deviceType: 'router' });
assert(ospf.summary.actions[0].id === 'ospf-mtu-mismatch', `ospf top (${ids(ospf)})`);
assert(findAction(ospf, 'ospf-stuck'), 'ospf stuck finding');
assert(findAction(ospf, 'ospf-missing-network'), 'ospf missing network');
assert(!findAction(ospf, 'route-no-default'), 'internal ospf case does not invent a default route');
assert(ospf.summary.script.includes('mtu 1500'), 'ospf script matches MTU');
assert(ospf.summary.script.includes('192.168.50.0'), 'ospf script advertises the LAN');

const security = runSwarm(byId['open-telnet'].text, { deviceType: 'router' });
assert(security.summary.actions[0].id === 'sec-telnet', `security top (${ids(security)})`);
for (const id of ['sec-enable-password', 'sec-weak-password', 'sec-snmp', 'sec-http', 'sec-user-plaintext', 'sec-no-encryption']) {
  assert(findAction(security, id), `security missing ${id} (${ids(security)})`);
}
assert(security.summary.script.includes('transport input ssh'), 'security script locks VTY to ssh');
assert(security.summary.script.includes('enable secret'), 'security script sets enable secret');
assert(security.summary.script.includes('no ip http server'), 'security script disables http');
assert(security.summary.script.includes('no snmp-server community public'), 'security script removes public');

const gateway = runSwarm(byId['wrong-gateway'].text, { deviceType: 'pc' });
assert(gateway.summary.actions[0].id === 'ip-gateway-outside', `gateway top (${ids(gateway)})`);
assert(findAction(gateway, 'ip-overlap'), 'overlap finding');
assert(findAction(gateway, 'dns-lookup-failed'), 'dns finding');
assert(findAction(gateway, 'reach-total-loss'), 'ping loss finding');
assert(gateway.summary.script.includes('192.168.1.50'), 'gateway script keeps the host address');
assert(gateway.summary.script.includes('interface GigabitEthernet0/1'), 'overlap script names Gi0/1');

const wifi = runSwarm(byId['wireless-drop'].text, { deviceType: 'wireless' });
assert(wifi.summary.actions[0].id === 'wifi-weak-signal', `wifi top (${ids(wifi)})`);
assert(findAction(wifi, 'wifi-channel-overlap'), 'channel overlap');
assert(findAction(wifi, 'l12-bpdu-access'), 'bpdu on access port');
assert(wifi.summary.notes.some((item) => item.id === 'l12-stp-blocking'), 'stp block is informational');
assert(wifi.summary.script.includes('dot11 24ghz channel'), 'wifi script retunes channels');
assert(wifi.summary.script.includes('interface GigabitEthernet1/0/1'), 'bpdu script names the port');

const dhcp = runSwarm(`ip dhcp pool VLAN20
 network 192.168.20.0 255.255.255.0
 default-router 192.168.10.1
`);
assert(findAction(dhcp, 'dhcp-bad-gateway'), `dhcp gateway (${ids(dhcp)})`);

const apipa = runSwarm('IPv4 Address. . . . . . . . . . . : 169.254.22.18');
assert(findAction(apipa, 'dhcp-apipa'), `apipa (${ids(apipa)})`);

const acl = runSwarm('    10 deny ip any 192.168.20.0 0.0.0.255 (248 matches)');
assert(findAction(acl, 'acl-deny-hits'), `acl hits (${ids(acl)})`);

const passive = runSwarm(`R1# show ip ospf neighbor
Neighbor ID     Pri   State           Dead Time   Address         Interface
2.2.2.2           1   INIT/DROTHER    00:00:31    10.0.0.2        GigabitEthernet0/0
router ospf 1
 passive-interface GigabitEthernet0/0
 network 10.0.0.0 0.0.0.3 area 0
`);
assert(findAction(passive, 'ospf-passive'), `passive (${ids(passive)})`);
assert(findAction(passive, 'ospf-stuck'), `init counts as stuck (${ids(passive)})`);

const healthyChannels = runSwarm(`show ap dot11 24ghz summary
AP-A  1
AP-B  6
AP-C  11
`);
assert(!findAction(healthyChannels, 'wifi-channel-overlap'), '1/6/11 is not overlap');

const junk = 'asdf qwer zxcv hello';
for (const device of ['auto', 'router', 'switch', 'firewall', 'wireless', 'pc']) {
  const result = runSwarm(junk, { deviceType: device });
  assert(result.summary.actions.length === 0, `${device} alone is not a fault (${ids(result)})`);
  assert(result.summary.headline === 'No definite fault in this paste', `${device} junk headline (${result.summary.headline})`);
  assert(!findAction(result, 'hyp-wireless'), `${device} junk does not invent a wireless action`);
  assert(result.meta.deviceType === device, `${device} is still recorded`);
}
const wifiWords = runSwarm('the wifi in the lobby keeps dropping', { deviceType: 'auto' });
assert(findAction(wifiWords, 'hyp-wireless'), `wireless words still hypothesize (${ids(wifiWords)})`);
const vlanOnRadio = runSwarm("users on VLAN 20 can't reach the internet", { deviceType: 'wireless' });
assert(!findAction(vlanOnRadio, 'hyp-wireless'), 'a wireless device does not invent a wireless fault');
assert(findAction(vlanOnRadio, 'hyp-default-route'), 'a reachability symptom still hypothesizes a route');

const dnsRankText = 'I can ping 8.8.8.8 but cannot open google.com';
const dnsRank = runSwarm(dnsRankText);
assert(dnsRank.summary.actions[0].id === 'dns-lookup-failed', `dns ranks first (${ids(dnsRank)})`);
assert(!findAction(dnsRank, 'hyp-default-route'), 'a working IP ping is not a missing default route');
assert(/DNS/i.test(dnsRank.summary.headline), `dns headline (${dnsRank.summary.headline})`);
for (const line of dnsRank.summary.actions[0].evidence) {
  assert(dnsRankText.includes(line), 'dns evidence is the symptom line');
}

const ospfAdjText = 'neighbor down, dead timer expired';
const ospfAdj = runSwarm(ospfAdjText);
assert(ospfAdj.summary.actions[0].id === 'ospf-adjacency', `ospf adjacency ranks first (${ids(ospfAdj)})`);
assert(/hello\/dead timer/i.test(ospfAdj.summary.actions[0].fix), 'ospf fix names the hello and dead timers');
assert(/area/i.test(ospfAdj.summary.actions[0].fix), 'ospf fix names the area');
assert(/\bMTU\b/.test(ospfAdj.summary.actions[0].fix), 'ospf fix names MTU');
assert(/authentication/i.test(ospfAdj.summary.actions[0].fix), 'ospf fix names authentication');
assert(/network type/i.test(ospfAdj.summary.actions[0].fix), 'ospf fix names network type');
assert(ospfAdjText.includes(ospfAdj.summary.actions[0].evidence[0]), 'ospf evidence is the symptom line');

const dnsProseText = 'DNS not resolving, nslookup times out';
const dnsProse = runSwarm(dnsProseText);
assert(dnsProse.summary.actions[0].id === 'dns-lookup-failed', `dns prose ranks first (${ids(dnsProse)})`);
assert(dnsProseText.includes(dnsProse.summary.actions[0].evidence[0]), 'dns prose evidence');

const apipaText = 'clients getting 169.254 addresses';
const apipaProse = runSwarm(apipaText);
assert(apipaProse.summary.actions[0].id === 'dhcp-apipa', `apipa prose ranks first (${ids(apipaProse)})`);
assert(/DHCP server/i.test(apipaProse.summary.actions[0].fix), 'apipa fix names the DHCP server');
assert(/scope/i.test(apipaProse.summary.actions[0].fix), 'apipa fix names the scope');
assert(/helper-address/i.test(apipaProse.summary.actions[0].fix), 'apipa fix names the relay');
assert(/VLAN/i.test(apipaProse.summary.actions[0].fix), 'apipa fix names the VLAN');
assert(apipaText.includes(apipaProse.summary.actions[0].evidence[0]), 'apipa evidence');

const routeNotDns = runSwarm('I can ping the gateway 192.168.1.1 but I cannot ping 8.8.8.8');
assert(routeNotDns.summary.actions[0].id === 'hyp-default-route', `numeric failure is a route (${ids(routeNotDns)})`);
assert(routeNotDns.summary.actions[0].id !== 'dns-lookup-failed', 'a failed IP ping is not ranked as DNS');

const exstartProse = runSwarm('OSPF neighbor stuck in EXSTART');
assert(exstartProse.summary.actions[0].id === 'ospf-adjacency', `exstart prose (${ids(exstartProse)})`);
assert(/\bMTU\b/.test(exstartProse.summary.actions[0].fix), 'exstart fix names MTU');

const exhausted = runSwarm('The DHCP scope is exhausted and clients are getting 169.254.10.20');
assert(exhausted.summary.actions[0].id === 'dhcp-apipa', `exhausted scope (${ids(exhausted)})`);
assert(exhausted.summary.actions[0].title.includes('169.254.10.20'), 'apipa title keeps the address');

const errdis = runSwarm('Gi1/0/1 is err-disabled by bpduguard');
assert(errdis.summary.actions[0].id === 'l12-err-disabled', `err-disable prose (${ids(errdis)})`);

const secretPaste = [
  'enable secret cisco',
  'enable password 7 0822455D0A16',
  'username admin privilege 15 secret 9 $9$hashvalue',
  'username bob password 0 bobpass',
  ' password cisco',
  'snmp-server community public RO',
  'snmp-server community private RW',
  'crypto isakmp key cisco123 address 10.0.0.1',
  ' pre-shared-key 0 letmein',
  ' ip ospf authentication-key s3cret',
  ' key-string abcdef',
  'no service password-encryption',
  'interface GigabitEthernet0/0',
  ' ip address 10.0.0.1 255.255.255.0',
].join('\n');
const redacted = redactSecrets(secretPaste);
assert(redacted.includes('enable secret [redacted]'), 'enable secret redacted');
assert(redacted.includes('enable password 7 [redacted]'), 'enable password redacted');
assert(redacted.includes('username admin privilege 15 secret 9 [redacted]'), 'username secret redacted');
assert(redacted.includes('username bob password 0 [redacted]'), 'username password redacted');
assert(redacted.includes(' password [redacted]'), 'line password redacted');
assert(redacted.includes('snmp-server community [redacted] RO'), 'snmp read community redacted');
assert(redacted.includes('snmp-server community [redacted] RW'), 'snmp write community redacted');
assert(redacted.includes('crypto isakmp key [redacted] address 10.0.0.1'), 'isakmp key redacted');
assert(redacted.includes(' pre-shared-key 0 [redacted]'), 'pre-shared-key redacted');
assert(redacted.includes(' ip ospf authentication-key [redacted]'), 'ospf key redacted');
assert(redacted.includes(' key-string [redacted]'), 'key-string redacted');
assert(redacted.includes('no service password-encryption'), 'encryption command stays');
assert(redacted.includes(' ip address 10.0.0.1 255.255.255.0'), 'interface address stays');
for (const leak of ['cisco', '0822455D0A16', 'bobpass', 'public', 'private', 'cisco123', 'letmein', 's3cret', 'abcdef', '$9$hashvalue']) {
  assert(!redacted.includes(leak), `redacted value stayed in the paste: ${leak}`);
}
assert(redactSecrets(redacted) === redacted, 'redaction can run twice');

const manifest = JSON.parse(fs.readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
assert(manifest.display === 'standalone', 'manifest is standalone');
assert(manifest.icons.some((icon) => icon.sizes === '192x192'), 'manifest 192 icon');
assert(manifest.icons.some((icon) => icon.sizes === '512x512'), 'manifest 512 icon');
const shellFiles = ['index.html', 'sw.js', 'css/app.css', 'js/app.js', 'js/deep.js', 'js/analyzers.js', 'js/samples.js'];
for (const file of shellFiles) {
  const text = fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
  assert(!/gmail\.com/i.test(text), `${file} has no email address`);
  assert(!/sk-ant-|sk-proj-|AKIA[0-9A-Z]{16}/.test(text), `${file} has no secret`);
}
const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
assert(html.includes('manifest.json'), 'page links the manifest');
assert(!html.includes('api.anthropic.com'), 'page does not call Anthropic by itself');
const appJs = fs.readFileSync(new URL('../js/app.js', import.meta.url), 'utf8');
assert(appJs.includes('serviceWorker.register'), 'app registers a service worker');
const worker = fs.readFileSync(new URL('../sw.js', import.meta.url), 'utf8');
assert(worker.includes('caches.open'), 'service worker caches the app');
for (const icon of ['icons/icon-192.png', 'icons/icon-512.png', 'icons/icon-maskable-512.png', 'icons/apple-touch-icon.png']) {
  assert(fs.statSync(new URL(`../${icon}`, import.meta.url)).size > 200, `${icon} exists`);
}
assert(html.includes('TODO'), 'pro waitlist is marked TODO');
assert(html.includes('<!-- TODO:'), 'TODO stays in a developer comment');
assert(!/>\s*TODO:/.test(html), 'TODO is not visible text');
assert(html.includes("Pro isn't open yet. Nothing is collected."), 'pro note is user-facing');
assert(html.includes('offline rule engine'), 'free tier is described as a rule engine');
assert(html.includes('id="privacy-note"'), 'privacy note is in the app');
assert(html.includes('The ranked report stays on this device'), 'privacy note says the report stays local');
assert(html.includes('property="og:title"') && html.includes('property="og:image"'), 'open graph tags');
assert(html.includes('name="twitter:card"') && html.includes('summary_large_image'), 'twitter card');
assert(!html.includes('The swarm reads'), 'the free check is not described as a swarm');
assert(!html.includes('specialist bots'), 'the free check is not described as bots');
assert(/offline rule engine/i.test(manifest.description), 'manifest describes a rule engine');
assert(!/swarm of specialist bots/i.test(manifest.description), 'manifest does not claim a bot swarm');
assert(!html.includes('fonts.googleapis.com'), 'fonts are self-hosted');
assert(html.includes('rel="preload" href="fonts/outfit-latin.woff2"'), 'outfit is preloaded');
assert(html.includes('rel="preload" href="fonts/jetbrains-mono-latin.woff2"'), 'jetbrains mono is preloaded');
assert(html.includes('role="tab"'), 'study tabs expose role=tab');
assert(html.includes('aria-selected="true"'), 'a study tab starts selected');
assert(html.includes('aria-controls="study-ref"'), 'study tab points at its panel');
assert(html.includes('aria-orientation="horizontal"'), 'device group is a horizontal radiogroup');
const saveTag = html.slice(Math.max(0, html.indexOf('id="save-key"') - 80), html.indexOf('id="save-key"') + 16);
assert(saveTag.includes('type="submit"'), 'enter in settings submits save');
const closeTag = html.slice(Math.max(0, html.indexOf('id="close-settings"') - 80), html.indexOf('id="close-settings"') + 20);
assert(closeTag.includes('type="button"'), 'close is not the implicit submit');

assert(appJs.includes("deviceType = 'auto'"), 'clear can reset the device');
const clearAt = appJs.indexOf("querySelector('#clear-btn')");
const clearHandler = appJs.slice(clearAt, clearAt + 240);
assert(clearHandler.includes("deviceType = 'auto'"), 'clear resets device to auto');
assert(clearHandler.includes('paintDevices()'), 'clear repaints the device control');
const pasteAt = appJs.indexOf("addEventListener('paste'");
assert(appJs.slice(pasteAt, pasteAt + 240).includes('scroll: true'), 'paste still scrolls to the result');
const inputAt = appJs.indexOf("addEventListener('input'");
assert(!appJs.slice(inputAt, inputAt + 280).includes('scroll: true'), 'typing does not request a scroll');
assert(appJs.includes('await navigator.clipboard.writeText(text)'), 'copy waits for the clipboard');
assert(!/copyText\(chip\.cmd\);\s*showToast/.test(appJs), 'chip toast is not fired before copy resolves');
assert(appJs.includes("Pro isn't open yet. Nothing is collected."), 'waitlist toast is honest');
assert(!appJs.includes('Waitlist is not connected'), 'old waitlist toast is gone');
assert(appJs.includes('aria-expanded'), 'ref cards expose aria-expanded');
assert(appJs.includes('ArrowLeft') && appJs.includes("tabindex: selected ? '0' : '-1'"), 'device radios rove with arrow keys');
assert(appJs.includes('deep-text'), 'deep analysis uses the pre-wrap class');
assert(appJs.includes('redactSecrets'), 'the AI step redacts the paste');
assert(appJs.includes('Send redacted paste'), 'the AI step warns before sending');
assert(appJs.includes('The ranked report stays on this device'), 'the AI warning says the report stays local');
assert(!appJs.includes('Swarm is reading'), 'status does not call the free check a swarm');
const deepJs = fs.readFileSync(new URL('../js/deep.js', import.meta.url), 'utf8');
assert(deepJs.includes('buildPrompt(redactSecrets(text)'), 'the provider payload is redacted');
const settingsAt = appJs.indexOf('#settings-form');
assert(appJs.slice(settingsAt, settingsAt + 180).includes('preventDefault'), 'enter in settings does not close the dialog');

const css = fs.readFileSync(new URL('../css/app.css', import.meta.url), 'utf8');
assert(css.includes('font-display: swap'), 'self-hosted fonts swap');
assert(css.includes('fonts/outfit-latin.woff2'), 'outfit is local');
assert(css.includes('fonts/jetbrains-mono-latin.woff2'), 'jetbrains mono is local');
assert(/\.deep-text\s*\{[^}]*white-space:\s*pre-wrap/.test(css), 'deep analysis keeps newlines');
assert(css.includes('opacity: 0') && css.includes('visibility: hidden'), 'toast hides with opacity and visibility');
assert(css.includes('safe-area-inset-bottom'), 'toast respects the safe area');
assert(css.includes('summary::before'), 'evidence summary draws a chevron');
assert(css.includes('text-overflow: ellipsis'), 'status stays on one line');
for (const font of ['fonts/outfit-latin.woff2', 'fonts/jetbrains-mono-latin.woff2']) {
  const bytes = fs.readFileSync(new URL(`../${font}`, import.meta.url));
  assert(bytes.slice(0, 4).toString() === 'wOF2', `${font} is woff2`);
}

assert(manifest.name === 'StarSwarm Security Agentic Toolkit', 'manifest name');
assert(manifest.short_name === 'StarSwarm', 'manifest short name');
assert(manifest.short_name.length <= 12, 'short name fits a home screen label');
assert(manifest.id === './', 'manifest id stays so an existing install updates in place');
assert(manifest.categories.includes('utilities') && manifest.categories.includes('productivity'), 'manifest categories');
const narrowShot = manifest.screenshots.find((shot) => shot.form_factor === 'narrow');
const wideShot = manifest.screenshots.find((shot) => shot.form_factor === 'wide');
assert(narrowShot && wideShot, 'manifest has narrow and wide screenshots');
for (const shot of [narrowShot, wideShot]) {
  const bytes = fs.readFileSync(new URL(`../${shot.src}`, import.meta.url));
  assert(bytes.readUInt32BE(16) + 'x' + bytes.readUInt32BE(20) === shot.sizes, `${shot.src} matches ${shot.sizes}`);
}

assert(worker.includes("const CACHE = 'starswarm-toolkit-v3'"), 'service worker cache was bumped');
const og = fs.readFileSync(new URL('../screenshots/og.png', import.meta.url));
assert(og.readUInt32BE(16) === 1200 && og.readUInt32BE(20) === 630, 'share image is 1200x630');
assert(worker.includes('fonts/outfit-latin.woff2') && worker.includes('fonts/jetbrains-mono-latin.woff2'), 'service worker precaches the fonts');
assert(!worker.includes('netfield-pocket-swarm'), 'old cache name is gone');
assert(deepJs.includes("const STORAGE_KEY = 'netfield.byok.v1'"), 'saved keys keep the existing storage key');
const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
assert(readme.includes('StarSwarm Security Agentic Toolkit'), 'readme uses the new name');
assert(readme.includes('https://links.starswarm.workers.dev/'), 'readme links the brand page');
assert(readme.includes('offline rule engine'), 'readme keeps the free tier honest');
assert(!/autonomous agents run|swarm of specialist bots/i.test(html + readme + manifest.description), 'free tier is not described as autonomous agents');
const userFacing = ['index.html', 'manifest.json', 'README.md', 'sw.js', 'css/app.css', 'js/app.js', 'js/analyzers.js', 'js/deep.js', 'js/samples.js', 'js/study.js'];
for (const file of userFacing) {
  const text = fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8').replaceAll('Formerly NetField', '');
  assert(!text.includes('NetField'), `${file} has no NetField name`);
  assert(!text.includes('Pocket Swarm'), `${file} has no Pocket Swarm name`);
}
assert(html.includes('Formerly NetField'), 'the app keeps a formerly note');
assert(html.includes('<title>StarSwarm Security Agentic Toolkit</title>'), 'page title');
assert(html.includes('content="StarSwarm"'), 'home screen title is the short name');
assert(html.includes('property="og:title" content="StarSwarm Security Agentic Toolkit"'), 'open graph title');
assert(html.includes('name="twitter:title" content="StarSwarm Security Agentic Toolkit"'), 'twitter title');

if (failed) {
  console.error(`\n${passed} passed, ${failed} failed`);
  process.exit(1);
}
console.log(`${passed} passed`);
