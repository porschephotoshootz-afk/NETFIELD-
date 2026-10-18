/** Built-in sample pastes. Labeled sample data, not a customer network. */

export const SAMPLES = [
  {
    id: 'vlan20-internet',
    deviceType: 'switch',
    title: 'VLAN 20, no internet',
    blurb: 'Guests ping their gateway and nothing else',
    text: `Users on VLAN 20 can't reach the internet. They can ping their gateway 192.168.20.1.

Switch# show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  unassigned      YES unset  administratively down down
Vlan10                 192.168.10.1    YES manual up                    up
Vlan20                 192.168.20.1    YES manual up                    up
GigabitEthernet0/0     203.0.113.2     YES manual up                    up
GigabitEthernet0/1     unassigned      YES unset  up                    up

Switch# show vlan brief
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/2, Gi0/3
10   USERS                            active    Gi0/4, Gi0/5
20   GUEST                            active    Gi0/6, Gi0/7

Switch# show ip route
Gateway of last resort is not set

      192.168.10.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.168.10.0/24 is directly connected, Vlan10
L        192.168.10.1/32 is directly connected, Vlan10
      192.168.20.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.168.20.0/24 is directly connected, Vlan20
L        192.168.20.1/32 is directly connected, Vlan20
      203.0.113.0/24 is variably subnetted, 2 subnets, 2 masks
C        203.0.113.0/24 is directly connected, GigabitEthernet0/0
L        203.0.113.2/32 is directly connected, GigabitEthernet0/0

Switch# show running-config | section nat
access-list 1 permit 192.168.10.0 0.0.0.255
ip nat inside source list 1 interface GigabitEthernet0/0 overload
interface GigabitEthernet0/0
 ip nat outside
interface Vlan10
 ip nat inside
`,
  },
  {
    id: 'duplex-mismatch',
    deviceType: 'switch',
    title: 'Slow copies, CRC errors',
    blurb: 'Server port is half duplex with late collisions',
    text: `Users report slow file copies through the server switch port.

Switch# show interfaces GigabitEthernet0/1
GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is 0011.2233.4455 (bia 0011.2233.4455)
  Internet address is 10.1.1.1/24
  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec,
     reliability 214/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Half-duplex, 100Mb/s, media type is 10/100/1000BaseTX
     1280 input errors, 1104 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 340 collisions, 210 late collisions

%CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on GigabitEthernet0/1 (not half duplex), with Server Eth0 (half duplex).
`,
  },
  {
    id: 'ospf-exstart',
    deviceType: 'router',
    title: 'OSPF stuck in EXSTART',
    blurb: 'Branch never reaches FULL and HQ routes are missing',
    text: `Branch users cannot reach HQ. OSPF looks up but the LAN route is missing.

R1# show ip ospf neighbor
Neighbor ID     Pri   State           Dead Time   Address         Interface
2.2.2.2           1   EXSTART/DR      00:00:37    10.0.0.2        GigabitEthernet0/0

R1# show ip ospf interface GigabitEthernet0/0
GigabitEthernet0/0 is up, line protocol is up
  Internet Address 10.0.0.1/30, Area 0, Attached via Network Statement
  Process ID 1, Router ID 1.1.1.1, Network Type BROADCAST, Cost: 1
  MTU 1500 bytes, BW 1000000 Kbit/sec
  Timer intervals configured, Hello 10, Dead 40, Wait 40, Retransmit 5

R2# show ip ospf interface GigabitEthernet0/0
GigabitEthernet0/0 is up, line protocol is up
  Internet Address 10.0.0.2/30, Area 0, Attached via Network Statement
  Process ID 1, Router ID 2.2.2.2, Network Type BROADCAST, Cost: 1
  MTU 1400 bytes, BW 1000000 Kbit/sec
  Timer intervals configured, Hello 10, Dead 40, Wait 40, Retransmit 5

R1# show ip route
Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks
C        10.0.0.0/30 is directly connected, GigabitEthernet0/0
L        10.0.0.1/32 is directly connected, GigabitEthernet0/0
      192.168.50.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.168.50.0/24 is directly connected, GigabitEthernet0/1
L        192.168.50.1/32 is directly connected, GigabitEthernet0/1

R1# show running-config | section router ospf
router ospf 1
 router-id 1.1.1.1
 network 10.0.0.0 0.0.0.3 area 0
`,
  },
  {
    id: 'open-telnet',
    deviceType: 'router',
    title: 'Open Telnet, weak passwords',
    blurb: 'A router config that should not face a network',
    text: `R1# show running-config
hostname R1
enable password cisco
no service password-encryption
username admin password admin
ip http server
snmp-server community public RO
snmp-server community private RW
interface GigabitEthernet0/0
 ip address 203.0.113.10 255.255.255.0
 no shutdown
line con 0
 password cisco
 login
line vty 0 4
 password cisco
 login
 transport input telnet
 transport input all
`,
  },
  {
    id: 'wrong-gateway',
    deviceType: 'pc',
    title: 'Wrong gateway, overlapping LAN',
    blurb: 'The PC gateway is in a different subnet',
    text: `The workstation cannot reach anything, including its gateway.

PC> ipconfig

Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 192.168.1.50
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.2.1

C:\\> ping 192.168.2.1
Request timed out.
Request timed out.
Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),

C:\\> ping 8.8.8.8
Request timed out.
Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),

C:\\> ping google.com
Ping request could not find host google.com. Please check the name and try again.

R1# show running-config | section interface
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
interface GigabitEthernet0/1
 ip address 192.168.1.0 255.255.254.0
`,
  },
  {
    id: 'wireless-drop',
    deviceType: 'wireless',
    title: 'Wi-Fi keeps dropping',
    blurb: 'Weak lobby signal and overlapping 2.4 GHz channels',
    text: `Clients on the Corp SSID keep dropping. The AP is up but the lobby is painful.

WLC# show client detail 0011.2233.4455
Client MAC Address............................... 0011.2233.4455
AP Name.......................................... AP-LOBBY
Wireless LAN Network Name (SSID)................. Corp
Channel.......................................... 2
Signal Strength (RSSI)........................... -82 dBm
Signal to Noise Ratio............................ 12 dB
Status........................................... Associated

WLC# show ap dot11 24ghz summary
AP Name    Channel
AP-LOBBY   2
AP-HALL    1
AP-CAFE    3

Switch# show spanning-tree vlan 30
VLAN0030
  Spanning tree enabled protocol rstp
Interface           Role Sts Cost      Prio.Nbr Type
Gi1/0/24            Altn BLK 4         128.24   P2p
Gi1/0/1             Desg FWD 4         128.1    P2p Edge

%SPANTREE-7-RECV_1Q_NON_TRUNK: Received 802.1Q BPDU on non trunk GigabitEthernet1/0/1 VLAN30.
`,
  },
];
