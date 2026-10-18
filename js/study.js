// CCNA study cards carried over from the original pocket tool.
export const REF_DATA = [
  {
    icon:'🔀', title:'VLANs & Trunking', sub:'802.1Q, SVI, inter-VLAN',
    tags:[{t:'L2',c:'blue'},{t:'Switching',c:'blue'},{t:'802.1Q',c:'green'}],
    body:`<b>VLANs</b> create separate broadcast domains on a single switch. 802.1Q trunks carry multiple VLANs between switches using a 4-byte VLAN tag.<br><br>
<b>Inter-VLAN Routing:</b> Use SVIs on a Layer 3 switch (<code>ip routing</code>) or Router-on-a-Stick (subinterfaces) on a router.`,
    cmd:`! Access port
interface Fa0/1
  switchport mode access
  switchport access vlan 10
  spanning-tree portfast

! Trunk port
interface Gi0/1
  switchport mode trunk
  switchport trunk allowed vlan 10,20,30
  switchport trunk native vlan 999

! SVI for inter-VLAN routing
ip routing
interface vlan 10
  ip address 192.168.10.1 255.255.255.0
  no shutdown

! Verify
show vlan brief
show interfaces trunk
show ip route`
  },
  {
    icon:'🌳', title:'STP / RSTP', sub:'Loop prevention, port roles',
    tags:[{t:'L2',c:'blue'},{t:'Loop Prevention',c:'orange'}],
    body:`<b>Spanning Tree Protocol</b> blocks redundant paths to prevent L2 loops. RSTP (802.1w) converges in under 1 second.<br><br>
<b>Election:</b> Root Bridge = lowest Bridge ID (priority 0-61440 + MAC). Default priority = 32768.<br>
<b>Port Roles:</b> Root Port, Designated Port, Alternate (blocked), Edge (PortFast)<br>
<b>RSTP States:</b> Discarding → Learning → Forwarding`,
    cmd:`! Set root bridge
spanning-tree vlan 10 priority 4096

! PortFast + BPDU Guard (access ports ONLY)
interface range Fa0/1-24
  spanning-tree portfast
  spanning-tree bpduguard enable

! RSTP mode
spanning-tree mode rapid-pvst

! Verify
show spanning-tree vlan 10
show spanning-tree summary
show spanning-tree interface Gi0/1 detail`
  },
  {
    icon:'🗺️', title:'OSPF', sub:'Link-state, AD 110, areas',
    tags:[{t:'L3',c:'green'},{t:'IGP',c:'green'},{t:'AD 110',c:'orange'}],
    body:`<b>OSPF</b> is a link-state routing protocol using Dijkstra's SPF algorithm.<br><br>
<b>Process:</b> Form adjacency → exchange LSAs → build LSDB → run SPF → install routes<br>
<b>Adjacency requirements:</b> Same area, MTU, hello/dead timers, authentication, subnet<br>
<b>DR/BDR:</b> Elected on multi-access networks (highest priority → highest Router ID)`,
    cmd:`router ospf 1
  router-id 1.1.1.1
  network 10.0.0.0 0.0.0.255 area 0
  network 192.168.1.0 0.0.0.255 area 1
  passive-interface default
  no passive-interface GigabitEthernet0/0
  auto-cost reference-bandwidth 1000

! Verify
show ip ospf neighbor
show ip ospf database
show ip route ospf
show ip ospf interface brief`
  },
  {
    icon:'🔄', title:'NAT / PAT', sub:'Address translation, overload',
    tags:[{t:'L3',c:'green'},{t:'WAN',c:'blue'}],
    body:`<b>PAT (overload)</b> maps many private IPs to one public IP using port numbers — most common setup.<br><br>
<b>Terms:</b><br>
• Inside local = private IP before NAT<br>
• Inside global = public IP after NAT<br>
• Outside global = destination public IP`,
    cmd:`! PAT (most common)
access-list 1 permit 192.168.0.0 0.0.255.255
ip nat inside source list 1 interface GigabitEthernet0/0 overload

! Mark interfaces
interface GigabitEthernet0/0
  ip nat outside
interface GigabitEthernet0/1
  ip nat inside

! Static NAT (server in DMZ)
ip nat inside source static 192.168.1.10 203.0.113.50

! Verify
show ip nat translations
show ip nat statistics
debug ip nat`
  },
  {
    icon:'🔐', title:'ACLs', sub:'Standard, extended, named',
    tags:[{t:'Security',c:'purple'},{t:'L3/L4',c:'green'}],
    body:`<b>ACLs</b> filter packets top-down. First match wins. <b>Implicit deny any</b> at end!<br><br>
<b>Standard (1-99):</b> source IP only → place near destination<br>
<b>Extended (100-199):</b> src, dst, protocol, port → place near source`,
    cmd:`! Named extended ACL (best practice)
ip access-list extended BLOCK-TELNET
  deny tcp any any eq 23 log
  permit ip any any

! Apply to interface
interface GigabitEthernet0/0
  ip access-group BLOCK-TELNET in

! Standard ACL for VTY
access-list 10 permit 10.0.0.0 0.0.0.255
line vty 0 4
  access-class 10 in

! Verify
show ip access-lists
show interfaces GigabitEthernet0/0 | include access list`
  },
  {
    icon:'⚡', title:'EtherChannel', sub:'LACP, PAgP, port-channel',
    tags:[{t:'L2',c:'blue'},{t:'LAG',c:'orange'}],
    body:`<b>EtherChannel</b> bundles links into one logical interface. Up to 8 active ports.<br><br>
<b>LACP (802.3ad):</b> active/passive — use this (open standard)<br>
<b>PAgP:</b> desirable/auto — Cisco only<br><br>
All ports must match: speed, duplex, VLAN config, trunk mode`,
    cmd:`! LACP EtherChannel
interface range GigabitEthernet0/1-2
  channel-group 1 mode active
  no shutdown

! Configure the port-channel
interface port-channel 1
  switchport mode trunk
  switchport trunk allowed vlan 10,20

! Verify
show etherchannel summary
show etherchannel port-channel
show interfaces port-channel 1`
  },
  {
    icon:'📡', title:'DHCP', sub:'Server, relay, snooping',
    tags:[{t:'L3',c:'green'},{t:'UDP 67/68',c:'blue'}],
    body:`<b>DORA:</b> Discover → Offer → Request → Acknowledge<br><br>
<b>ip helper-address</b> forwards DHCP broadcasts across router boundaries to a central DHCP server.<br>
<b>DHCP Snooping</b> blocks rogue DHCP servers on untrusted ports.`,
    cmd:`! DHCP Server config
ip dhcp excluded-address 192.168.1.1 192.168.1.20
ip dhcp pool VLAN10
  network 192.168.1.0 /24
  default-router 192.168.1.1
  dns-server 8.8.8.8 8.8.4.4
  lease 7

! DHCP Relay (on router interface)
interface GigabitEthernet0/1
  ip helper-address 10.0.0.10

! DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10,20
interface GigabitEthernet0/24
  ip dhcp snooping trust

! Verify
show ip dhcp binding
show ip dhcp pool
show ip dhcp conflict`
  },
  {
    icon:'🔒', title:'SSH & Device Security', sub:'AAA, TACACS+, hardening',
    tags:[{t:'Security',c:'purple'},{t:'Mgmt',c:'blue'}],
    body:`Secure device access is critical. Disable Telnet, enable SSH v2, configure AAA with TACACS+ for device admin.<br><br>
<b>TACACS+:</b> TCP 49, full packet encryption, separates AuthN/AuthZ — best for device management<br>
<b>RADIUS:</b> UDP 1645/1646, encrypts password only — best for 802.1X`,
    cmd:`! SSH setup
hostname R1
ip domain-name corp.local
crypto key generate rsa modulus 2048
ip ssh version 2

! Local user fallback
username admin privilege 15 secret Str0ngP@ss!

! AAA with TACACS+
aaa new-model
tacacs server TACACS-SRV
  address ipv4 10.0.0.10
  key TacacsKey!
aaa authentication login VTY-AUTH group tacacs+ local
aaa authorization exec VTY-AUTHZ group tacacs+ local

! VTY hardening
line vty 0 4
  login authentication VTY-AUTH
  authorization exec VTY-AUTHZ
  transport input ssh
  exec-timeout 5 0
  access-class 10 in

! Console
line console 0
  login local
  exec-timeout 5 0
  logging synchronous`
  },
  {
    icon:'📶', title:'Wireless / WLC', sub:'CAPWAP, 802.11, WPA3',
    tags:[{t:'Wireless',c:'blue'},{t:'CAPWAP',c:'green'}],
    body:`<b>CAPWAP:</b> UDP 5246 (control) and UDP 5247 (data) tunnels between AP and WLC.<br><br>
<b>802.11 channels:</b> 2.4GHz non-overlapping = 1, 6, 11 only<br>
<b>Wi-Fi 6 (802.11ax):</b> OFDMA, BSS Coloring, TWT, 6GHz band<br>
<b>WPA3:</b> SAE replaces PSK, mandatory for Wi-Fi 6`,
    cmd:`! WLC CLI (SSH to WLC)
show wlan summary
show ap summary
show client summary
show client detail [MAC]

! Configure WLAN (WLC CLI)
config wlan create 1 Corp Corp-SSID
config wlan security wpa wpa2 enable 1
config wlan security wpa wpa2 ciphers aes enable 1
config wlan security 802.1x enable 1
config wlan enable 1

! AP commands
show ap config general [AP-name]
config ap channel 36 [AP-name]
show rogue ap summary`
  },
  {
    icon:'🐍', title:'Automation & APIs', sub:'Ansible, Python, NETCONF',
    tags:[{t:'Automation',c:'purple'},{t:'REST API',c:'blue'},{t:'NETCONF',c:'green'}],
    body:`<b>Key data formats:</b> JSON (REST APIs), XML (NETCONF), YAML (Ansible playbooks)<br><br>
<b>NETCONF:</b> SSH port 830, uses YANG models, datastores (running/candidate/startup)<br>
<b>RESTCONF:</b> HTTP/HTTPS, REST-like interface to YANG data<br>
<b>Ansible:</b> Agentless, push model, idempotent`,
    cmd:`# Enable on IOS-XE
netconf-yang
restconf
ip http secure-server

# Python - Netmiko
from netmiko import ConnectHandler
dev = {"device_type":"cisco_ios",
       "host":"10.0.0.1",
       "username":"admin","password":"cisco"}
with ConnectHandler(**dev) as c:
    print(c.send_command("show ip route"))

# Ansible playbook snippet
- name: Configure OSPF
  cisco.ios.ios_config:
    lines:
      - network 10.0.0.0 0.0.0.255 area 0
    parents: router ospf 1`
  },
];

export const SCENARIOS = [
  {
    icon:'🔌', name:'Interface Down', desc:'Port not coming up',
    title:'INTERFACE TROUBLESHOOTING',
    steps:[
      { n:1, title:'Check physical status', desc:'Verify cable, SFP, and link light. Check both ends.', cmd:'show interfaces GigabitEthernet0/1\nshow interfaces status' },
      { n:2, title:'Check admin state', desc:'Interface may be administratively shut down.', cmd:'show running-config interface Gi0/1\n! If shutdown:\nno shutdown' },
      { n:3, title:'Check duplex/speed', desc:'Mismatch causes CRC errors and collisions.', cmd:'show interfaces Gi0/1 | include duplex\ninterface Gi0/1\n  duplex full\n  speed 1000' },
      { n:4, title:'Check error counters', desc:'High CRC/input errors = bad cable or NIC. High output drops = congestion.', cmd:'show interfaces Gi0/1 | include error\nshow interfaces Gi0/1 counters errors\nclear counters GigabitEthernet0/1' },
      { n:5, title:'Check SFP/transceiver', desc:'Verify transceiver is seated and compatible.', cmd:'show interfaces transceiver\nshow inventory' },
    ]
  },
  {
    icon:'🌐', name:'No Internet', desc:'Users can\'t reach WAN',
    title:'NO INTERNET TROUBLESHOOTING',
    steps:[
      { n:1, title:'Verify default route', desc:'Check a default route exists pointing to ISP gateway.', cmd:'show ip route 0.0.0.0\nshow ip route | include 0.0.0.0' },
      { n:2, title:'Ping ISP gateway', desc:'Test L3 connectivity to the upstream router.', cmd:'ping [ISP-gateway-IP]\nping [ISP-gateway-IP] source [your-WAN-IP]' },
      { n:3, title:'Check NAT translations', desc:'Verify NAT is translating. If table is empty, traffic isn\'t matching ACL.', cmd:'show ip nat translations\nshow ip nat statistics\ndebug ip nat' },
      { n:4, title:'Check NAT interfaces', desc:'Confirm inside/outside are set on correct interfaces.', cmd:'show ip interface brief\nshow running-config | include nat' },
      { n:5, title:'Test DNS resolution', desc:'Ping 8.8.8.8 (no DNS) vs ping google.com (with DNS) to isolate issue.', cmd:'ping 8.8.8.8\nping google.com\nnslookup google.com\nshow hosts' },
    ]
  },
  {
    icon:'🔁', name:'Routing Issue', desc:'Specific routes missing',
    title:'ROUTING TROUBLESHOOTING',
    steps:[
      { n:1, title:'Check routing table', desc:'Identify which routes are present and which are missing.', cmd:'show ip route\nshow ip route [destination-network]\nshow ip route summary' },
      { n:2, title:'Check OSPF neighbors', desc:'FULL state = healthy. INIT/2WAY = problem forming adjacency.', cmd:'show ip ospf neighbor\nshow ip ospf interface brief\nshow ip ospf database' },
      { n:3, title:'Verify network statements', desc:'Check OSPF/EIGRP network commands match your interface IPs.', cmd:'show running-config | section router ospf\nshow ip protocols' },
      { n:4, title:'Check passive interfaces', desc:'Passive interfaces don\'t send/receive hellos — may block adjacency.', cmd:'show ip ospf interface brief | include Passive\nshow ip protocols | include Passive' },
      { n:5, title:'Traceroute to destination', desc:'Identify exactly where packets are being dropped.', cmd:'traceroute [destination-IP]\ntraceroute [dest] source [your-IP]\nping [dest] repeat 100' },
    ]
  },
  {
    icon:'📡', name:'VLAN Not Working', desc:'Traffic not crossing VLANs',
    title:'VLAN TROUBLESHOOTING',
    steps:[
      { n:1, title:'Check VLAN exists', desc:'VLAN must exist in the database and be active.', cmd:'show vlan brief\n! If missing:\nvlan 10\n  name SERVERS' },
      { n:2, title:'Check port assignments', desc:'Verify ports are in the correct VLAN and mode.', cmd:'show interfaces status\nshow interfaces Fa0/1 switchport' },
      { n:3, title:'Check trunk ports', desc:'Verify VLAN is allowed on trunk and not pruned.', cmd:'show interfaces trunk\nshow interfaces Gi0/1 trunk\nswitchport trunk allowed vlan add 10' },
      { n:4, title:'Check SVI / inter-VLAN routing', desc:'SVI must be up/up and ip routing must be enabled.', cmd:'show ip interface brief | include Vlan\nshow interface vlan 10\nshow ip route' },
      { n:5, title:'Ping test between VLANs', desc:'Ping from device in VLAN 10 to gateway, then to VLAN 20.', cmd:'! From router/switch:\nping vrf default 192.168.10.1\nping 192.168.20.1 source vlan 10' },
    ]
  },
  {
    icon:'🔐', name:'Can\'t SSH', desc:'SSH/VTY access failing',
    title:'SSH TROUBLESHOOTING',
    steps:[
      { n:1, title:'Check SSH is enabled', desc:'SSH requires crypto keys and ip ssh version 2.', cmd:'show ip ssh\nshow crypto key mypubkey rsa\n! Regenerate if needed:\ncrypto key generate rsa modulus 2048' },
      { n:2, title:'Check VTY config', desc:'VTY lines must allow SSH and have login configured.', cmd:'show running-config | section line vty\n! Must have:\n! transport input ssh\n! login local (or aaa)' },
      { n:3, title:'Check ACL on VTY', desc:'An access-class on VTY lines may be blocking your source IP.', cmd:'show running-config | include access-class\nshow ip access-lists [ACL-name]' },
      { n:4, title:'Check reachability', desc:'Can you ping the device management IP from your workstation?', cmd:'ping [device-mgmt-IP]\ntraceroute [device-mgmt-IP]' },
      { n:5, title:'Check domain name', desc:'SSH requires a hostname and domain name for key generation.', cmd:'show running-config | include hostname\nshow running-config | include domain\n! Must have both set before generating keys' },
    ]
  },
  {
    icon:'📶', name:'WiFi Issues', desc:'Wireless clients dropping',
    title:'WIRELESS TROUBLESHOOTING',
    steps:[
      { n:1, title:'Check AP status', desc:'Verify APs are registered and joined to WLC.', cmd:'show ap summary\nshow ap join stats summary\nshow ap config general [AP-name]' },
      { n:2, title:'Check client association', desc:'Find the client and check its association state and signal.', cmd:'show client summary\nshow client detail [client-MAC]\nshow wireless client summary' },
      { n:3, title:'Check CAPWAP tunnel', desc:'AP must have L3 connectivity to WLC. Check DHCP/routing to WLC.', cmd:'show capwap client rcb\nping [WLC-management-IP]\n! From AP console (local mode)' },
      { n:4, title:'Check WLAN config', desc:'Verify SSID is enabled, security config is correct, VLAN mapping is set.', cmd:'show wlan summary\nshow wlan [wlan-id]\nshow wlan security [wlan-id]' },
      { n:5, title:'Check RF / signal', desc:'Low SNR, co-channel interference, or wrong channel causes drops.', cmd:'show ap dot11 24ghz channel\nshow ap dot11 5ghz channel\nshow rogue ap summary' },
    ]
  },
];

export const CS_DATA = [
  {
    icon:'🔢', name:'Admin\nDistances', count:'12 protocols',
    items:[
      {k:'Connected',v:'0'},
      {k:'Static',v:'1'},
      {k:'EIGRP Summary',v:'5'},
      {k:'eBGP',v:'20'},
      {k:'EIGRP Internal',v:'90'},
      {k:'OSPF',v:'110'},
      {k:'IS-IS',v:'115'},
      {k:'RIP',v:'120'},
      {k:'EIGRP External',v:'170'},
      {k:'iBGP',v:'200'},
      {k:'Unreachable',v:'255'},
    ]
  },
  {
    icon:'🚪', name:'Common\nPorts', count:'14 services',
    items:[
      {k:'FTP',v:'TCP 20/21'},
      {k:'SSH',v:'TCP 22'},
      {k:'Telnet',v:'TCP 23'},
      {k:'SMTP',v:'TCP 25'},
      {k:'DNS',v:'UDP/TCP 53'},
      {k:'DHCP',v:'UDP 67/68'},
      {k:'HTTP',v:'TCP 80'},
      {k:'SNMP',v:'UDP 161/162'},
      {k:'HTTPS',v:'TCP 443'},
      {k:'BGP',v:'TCP 179'},
      {k:'Syslog',v:'UDP 514'},
      {k:'NETCONF',v:'TCP 830'},
      {k:'TACACS+',v:'TCP 49'},
      {k:'RADIUS',v:'UDP 1645/1646'},
    ]
  },
  {
    icon:'📊', name:'Syslog\nLevels', count:'8 severity levels',
    items:[
      {k:'0 Emergency',v:'System unusable'},
      {k:'1 Alert',v:'Immediate action'},
      {k:'2 Critical',v:'Critical failure'},
      {k:'3 Error',v:'Error conditions'},
      {k:'4 Warning',v:'Warning threshold'},
      {k:'5 Notice',v:'Significant normal'},
      {k:'6 Info',v:'Informational'},
      {k:'7 Debug',v:'Debug only — verbose!'},
    ]
  },
  {
    icon:'📐', name:'Subnet\nRef', count:'9 common masks',
    items:[
      {k:'/24',v:'254 hosts'},
      {k:'/25',v:'126 hosts'},
      {k:'/26',v:'62 hosts'},
      {k:'/27',v:'30 hosts'},
      {k:'/28',v:'14 hosts'},
      {k:'/29',v:'6 hosts'},
      {k:'/30',v:'2 hosts (P2P)'},
      {k:'/23',v:'510 hosts'},
      {k:'/22',v:'1022 hosts'},
    ]
  },
  {
    icon:'📡', name:'OSPF\nTimers', count:'Key values',
    items:[
      {k:'Hello (broadcast)',v:'10 seconds'},
      {k:'Dead (broadcast)',v:'40 seconds'},
      {k:'Hello (NBMA)',v:'30 seconds'},
      {k:'Dead (NBMA)',v:'120 seconds'},
      {k:'LSA max age',v:'3600 seconds'},
      {k:'SPF delay',v:'5 seconds'},
      {k:'SPF hold',v:'10 seconds'},
    ]
  },
  {
    icon:'🔑', name:'STP\nTimers', count:'Key values',
    items:[
      {k:'Hello',v:'2 seconds'},
      {k:'Forward delay',v:'15 seconds'},
      {k:'Max age',v:'20 seconds'},
      {k:'802.1D converge',v:'~50 seconds'},
      {k:'RSTP converge',v:'< 1 second'},
      {k:'PortFast skips',v:'Listen+Learn'},
      {k:'Default priority',v:'32768'},
    ]
  },
  {
    icon:'🌐', name:'IPv4\nRanges', count:'Private + special',
    items:[
      {k:'10.0.0.0/8',v:'Class A private'},
      {k:'172.16.0.0/12',v:'Class B private'},
      {k:'192.168.0.0/16',v:'Class C private'},
      {k:'127.0.0.0/8',v:'Loopback'},
      {k:'169.254.0.0/16',v:'APIPA (no DHCP)'},
      {k:'224.0.0.0/4',v:'Multicast'},
      {k:'255.255.255.255',v:'Broadcast'},
    ]
  },
  {
    icon:'⚡', name:'Quick\nVerify', count:'Show commands',
    items:[
      {k:'show ip route',v:'Routing table'},
      {k:'show ip int brief',v:'Interface summary'},
      {k:'show vlan brief',v:'VLAN database'},
      {k:'show interfaces trunk',v:'Trunk ports'},
      {k:'show ip ospf neighbor',v:'OSPF neighbors'},
      {k:'show ip nat translations',v:'NAT table'},
      {k:'show spanning-tree',v:'STP topology'},
      {k:'show etherchannel summary',v:'LAG status'},
    ]
  },
];
