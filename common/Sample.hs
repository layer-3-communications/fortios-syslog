{-# language TypeApplications #-}

module Sample
  ( traffic_local_A
  , traffic_local_B
  , traffic_forward_A
  , traffic_forward_B
  , traffic_forward_C
  , traffic_forward_D
  , traffic_forward_E
  , traffic_forward_F
  , traffic_forward_G
  , traffic_forward_H
  , traffic_forward_I
  , traffic_forward_J
  , utm_webfilter_A
  , utm_webfilter_B
  , utm_webfilter_C
  , event_system_A
  , event_wireless_A
  ) where

import Data.Bytes (Bytes)
import Data.Word (Word8)
import Data.Char (ord)
import qualified Data.Bytes as Bytes
import qualified GHC.Exts as Exts

-- Sample Logs. If you add a sample log to this file, please
-- replace all information in the log that could possibly be
-- meaningful. At a bare minimum, this means:
--
-- * Replace any IP addresses with non-routable addresses 
--   from the TEST-NET-1 block (192.0.2.0/24).
-- * Replace any domain names with the reserved domain
--   name example.com.
-- * Replace any hostnames with something like MY-HOST
--   or NY-APP or SAMPLE-HOST.
-- * Replace rule names and application categories.

pack :: String -> Bytes
pack = Bytes.fromByteArray . Exts.fromList . map (fromIntegral @Int @Word8 . ord)

-- Local Traffic Log 
traffic_local_A :: Bytes
traffic_local_A = pack $ concat
  [ "date=2019-11-08 time=09:50:39 devname=FGT-Device-Node0 "
  , "devid=FGT-Device logid=0001000014 type=traffic "
  , "subtype=local level=notice vd=root srcip=192.0.2.12 "
  , "srcport=48216 srcintf=\"port7\" dstip=192.0.2.23 dstport=14560 "
  , "dstintf=\"root\" sessionid=69597381 proto=6 action=deny policyid=0 "
  , "policytype=some-policy dstcountry=\"United States\" "
  , "srccountry=\"Canada\" trandisp=noop service=\"tcp/14560\" "
  , "app=\"tcp/14560\" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 "
  , "appcat=\"ex-cat\" crscore=30 craction=193181 crlevel=high"
  ]

traffic_local_B :: Bytes
traffic_local_B = pack $ concat
  [ "date=2019-11-28 time=19:13:00 devname=\"FG200ABC00001\" "
  , "devid=\"FG200ABC00001\" logid=\"0001000014\" type=\"traffic\" "
  , "subtype=\"local\" level=\"notice\" vd=\"root\" "
  , "eventtime=1574989980832601873 tz=\"-0700\" srcip=2001:db8::0001:0002 "
  , "srcport=5353 srcintf=\"port3\" srcintfrole=\"lan\" dstip=2001:db8::0003:0004 "
  , "dstport=5353 dstintf=\"unknown0\" dstintfrole=\"undefined\" sessionid=5208314 "
  , "proto=17 action=\"deny\" policyid=0 policytype=\"local-in-policy6\" "
  , "service=\"udp/5353\" trandisp=\"noop\" app=\"udp/5353\" duration=0 "
  , "sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 appcat=\"unscanned\" "
  , "srchwvendor=\"Dell\" osname=\"Windows\" srcswversion=\"10\" "
  , "mastersrcmac=\"de:ad:be:ef:00:01\" srcmac=\"be:ef:de:ad:02:03\" "
  , "srcserver=0"
  ]

traffic_forward_A :: Bytes
traffic_forward_A = pack $ concat
  [ "date=2019-11-08 time=09:50:39 devname=FGT5-NY-Node0 devid=FGT5-NY "
  , "logid=0000000013 type=traffic subtype=forward level=notice vd=root "
  , "srcip=192.0.2.55 srcport=54400 srcintf=\"vlan-13-trust\" "
  , "dstip=192.0.2.56 dstport=80 dstintf=\"port55\" "
  , "poluuid=176a120e-56c3-51a6-5fb1-485f3180eb81 sessionid=79091892 "
  , "proto=6 action=close policyid=6 policytype=policy "
  , "dstcountry=\"United States\" srccountry=\"Reserved\" trandisp=snat "
  , "transip=192.0.2.3 transport=54400 service=\"HTTP\" duration=6 "
  , "sentbyte=395 rcvdbyte=651 sentpkt=6 rcvdpkt=3 appcat=\"unscanned\" "
  , "wanin=372 wanout=131 lanin=145 lanout=381 utmaction=allow countweb=1"
  ]

traffic_forward_B :: Bytes
traffic_forward_B = pack $ concat
  [ "date=2019-11-15 time=08:24:34 devname=FGT-NY-Node0 devid=FGT-NY "
  , "logid=0000000013 type=traffic subtype=forward level=notice vd=root "
  , "srcip=192.0.2.103 srcport=55397 srcintf=\"port2\" dstip=192.0.2.97 "
  , "dstport=443 dstintf=\"vlan-1-trust\" poluuid=ecf7d054-16d2-50e7-e0c1-"
  , "fb0529e4ab90 sessionid=97182243 proto=6 action=close policyid=22 "
  , "policytype=policy dstcountry=\"United States\" srccountry=\"United States\" "
  , "trandisp=dnat tranip=192.0.2.200 tranport=443 service=\"HTTPS\" duration=97 "
  , "sentbyte=1204 rcvdbyte=935 sentpkt=9 rcvdpkt=6 appcat=\"unscanned\""
  ]

traffic_forward_C :: Bytes
traffic_forward_C = pack $ concat
  [ "date=2019-11-28 time=19:13:00 devname=\"FG200ZDJ12345678\" "
  , "devid=\"FG200ZDJ12345678\" logid=\"0000000020\" type=\"traffic\" "
  , "subtype=\"forward\" level=\"notice\" vd=\"root\" "
  , "eventtime=1574989980897483985 tz=\"-0600\" srcip=192.0.2.201 "
  , "srcname=\"WIN10-JK\" srcport=41484 srcintf=\"port1\" srcintfrole=\"lan\" "
  , "dstip=192.0.2.21 dstport=443 dstintf=\"wan1\" dstintfrole=\"wan\" "
  , "poluuid=\"4b8108d8-0315-61f0-042a-c1fdfa3e8910\" "
  , "dstinetsvc=\"Example-Web\" sessionid=96952295 proto=6 action=\"accept\" "
  , "policyid=69 policytype=\"policy\" dstcountry=\"United States\" "
  , "srccountry=\"Reserved\" trandisp=\"snat\" transip=192.0.2.23 "
  , "transport=41484 appid=34039 app=\"HTTP.BROWSER_Chrome\" "
  , "appcat=\"Web.Client\" apprisk=\"elevated\" "
  , "applist=\"fizz-default_ac_security\" duration=521971 sentbyte=7625130 "
  , "rcvdbyte=1212550 sentpkt=24469 rcvdpkt=10100 vwlid=0 sentdelta=4745 "
  , "rcvddelta=997 osname=\"Windows\" srcswversion=\"10 / 2016\" "
  , "mastersrcmac=\"de:ad:be:ef:00:00\" srcmac=\"be:ef:be:ef:ab:cd\" "
  , "srcserver=0"
  ]

traffic_forward_D :: Bytes
traffic_forward_D = pack $ concat
  [ "date=2019-12-17 time=00:14:07 devname=example-fgt devid=FGT-NY "
  , "logid=0000000013 type=traffic subtype=forward level=notice vd=root "
  , "srcip=192.0.2.211 srcport=63455 srcintf=\"Vlan7\" dstip=192.0.2.103 "
  , "dstport=443 dstintf=\"port7\" poluuid=8c1eb501-5e2d-61e1-280a-"
  , "58c0d8e15337 sessionid=3799706082 proto=6 action=close policyid=9 "
  , "policytype=policy dstcountry=\"United States\" srccountry=\"Reserved\" "
  , "trandisp=snat transip=192.0.2.115 transport=63455 service=\"HTTPS\" "
  , "duration=241 sentbyte=2910 rcvdbyte=2854 sentpkt=22 rcvdpkt=17 "
  , "appcat=\"unscanned\" wanin=2162 wanout=1758 lanin=1758 lanout=2162 "
  , "devtype=\"Router/NAT Device\" mastersrcmac=de:ad:be:ef:12:34 "
  , "srcmac=ab:cd:ef:01:23:45"
  ]

traffic_forward_E :: Bytes
traffic_forward_E = pack $ concat
  [ "date=2019-12-28 time=20:15:43 devname=foo-bar-1 devid=FGT-NY "
  , "logid=0000000013 type=traffic subtype=forward level=notice vd=root "
  , "srcip=192.0.2.16 srcport=44048 srcintf=\"port1\" dstip=192.0.2.15 "
  , "dstport=8800 dstintf=\"Vlan43\" "
  , "poluuid=665f3340-1fb0-5fe7-0a7e-b32af87b809a sessionid=3838291256 "
  , "proto=6 action=timeout policyid=37 policytype=policy "
  , "dstcountry=\"United States\" srccountry=\"United States\" "
  , "trandisp=snat+dnat tranip=192.0.2.201 tranport=80 transip=192.0.2.202 "
  , "transport=44048 service=\"TCP-8800\" duration=10 sentbyte=40 "
  , "rcvdbyte=68 sentpkt=1 rcvdpkt=1 appcat=\"unscanned\" crscore=5 "
  , "craction=252034 crlevel=low"
  ]

traffic_forward_F :: Bytes
traffic_forward_F = pack $ concat
  [ "<189>date=2021-02-11 time=13:15:00 devname=\"NYC-FW\" "
  , "devid=\"FG200FT817418227\" "
  , "eventtime=1613067301159688808 tz=\"-0500\" logid=\"0000000013\" "
  , "type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" "
  , "srcip=192.0.2.201 srcport=18570 "
  , "srcintf=\"Untrusted\" srcintfrole=\"thesrcintf\" dstip=192.0.2.205 "
  , "dstport=4791 "
  , "dstintf=\"thedstintf\" dstintfrole=\"lan\" srccountry=\"United States\" "
  , "dstcountry=\"United States\" sessionid=2143294 proto=6 action=\"close\" "
  , "policyid=10357 policytype=\"policy\" "
  , "poluuid=\"8d8548fd-400a-40f0-49bf-52906fe8aef4\" "
  , "policyname=\"My Policy\" service=\"the-service-name\" trandisp=\"dnat\" "
  , "tranip=172.16.4.15 tranport=5009 duration=2 sentbyte=1695 rcvdbyte=1269 "
  , "sentpkt=12 "
  , "rcvdpkt=12 appcat=\"unscanned\""
  ]

utm_webfilter_A :: Bytes
utm_webfilter_A = pack $ concat
  [ "date=2019-11-15 time=08:24:33 devname=FGT-NY-Node0 devid=FGT-NY "
  , "logid=0317013312 type=utm subtype=webfilter eventtype=ftgd_allow "
  , "level=notice vd=root policyid=6 sessionid=97184671 user=\"\" "
  , "srcip=192.0.2.31 srcport=53746 srcintf=\"vlan-7-trust\" "
  , "dstip=192.0.2.51 dstport=80 dstintf=\"port5\" proto=6 service=\"HTTP\" "
  , "hostname=\"192.0.2.201\" profile=\"my-profile\" action=passthrough "
  , "reqtype=direct url=\"/example/path.txt\" sentbyte=93 rcvdbyte=0 "
  , "direction=outgoing msg=\"URL belongs to an allowed category in policy\" "
  , "method=domain cat=52 catdesc=\"Information Technology\""
  ]

utm_webfilter_B :: Bytes
utm_webfilter_B = pack $ concat
  [ "date=2019-11-18 time=14:11:36 devname=FGT-NY-Node0 devid=FGT-NY "
  , "logid=0318012800 type=utm subtype=webfilter eventtype=ftgd_err "
  , "level=error vd=root policyid=5 sessionid=106167548 user=\"\" "
  , "srcip=192.0.2.67 srcport=58737 srcintf=\"vlan-115\" dstip=192.0.2.100 "
  , "dstport=53 dstintf=\"port59\" proto=17 service=\"DNS\" "
  , "hostname=\"example.com\" profile=\"default\" action=blocked "
  , "reqtype=direct sentbyte=0 rcvdbyte=0 direction=outgoing "
  , "msg=\"A rating error occurs\" error=\"DNS query timeout\""
  ]

utm_webfilter_C :: Bytes
utm_webfilter_C = pack $ concat
  [ "date=2019-11-18 time=14:11:35 devname=FGT-NY-Node0 devid=FGT-NY "
  , "logid=0317013312 type=utm subtype=webfilter eventtype=ftgd_allow "
  , "level=notice vd=root policyid=6 sessionid=107172027 user=\"\" "
  , "srcip=192.0.2.3 srcport=52992 srcintf=\"vlan-19-trust\" "
  , "dstip=192.0.2.54 dstport=80 dstintf=\"port91\" proto=6 "
  , "service=\"HTTP\" hostname=\"www.example.com\" "
  , "profile=\"prof\" action=passthrough reqtype=referral "
  , "url=\"/the/path.php?name=yes\" "
  , "referralurl=\"http://www.example.org/get/started\" "
  , "sentbyte=38053 rcvdbyte=126033 direction=outgoing "
  , "msg=\"URL belongs to an allowed category in policy\" "
  , "method=domain cat=42 catdesc=\"Shopping\""
  ]

event_system_A :: Bytes
event_system_A = pack $ concat
  [ "date=2019-11-18 time=14:44:07 devname=FGT-NY-Node0 devid=FGT-NY "
  , "logid=0100026001 type=event subtype=system level=information vd=root "
  , "logdesc=\"DHCP Ack log\" interface=\"vlan-11-trust\" dhcp_msg=\"Ack\" "
  , "mac=D1:1F:B1:41:FB:1F ip=192.0.2.97 lease=3600 hostname=\"SomeHost\" "
  , "msg=\"DHCP server sends a DHCPACK\""
  ]

traffic_forward_G :: Bytes
traffic_forward_G = pack $ concat
  [ "<189>logver=64 timestamp=1626459703 tz=\"UTC-5\" devname=\"fgt_ny_0\" "
  , "devid=\"FG5H1B5718009842\" vd=\"root\" date=2021-07-16 time=13:21:43 "
  , "eventtime=1626459704210037706 tz=\"-0500\" logid=\"0000000020\" "
  , "type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=192.0.2.11 "
  , "srcport=57925 srcintf=\"The Src Intf\" srcintfrole=\"lan\" "
  , "dstip=192.0.2.207 dstport=56773 dstintf=\"My VLAN\" "
  , "dstintfrole=\"lan\" srccountry=\"Reserved\" dstcountry=\"Reserved\" "
  , "sessionid=2216451506 proto=6 action=\"accept\" policyid=240 "
  , "policytype=\"policy\" poluuid=\"debfa4b4-0f92-54e4-39a7-060b8e7dc6bf\" "
  , "policyname=\"My SQL Policy\" service=\"The Service\" "
  , "trandisp=\"noop\" appid=16197 app=\"MSSQL\" appcat=\"Business\" "
  , "apprisk=\"low\" applist=\"Gaming - Restrictions\" duration=719 "
  , "sentbyte=4572 rcvdbyte=4559 sentpkt=56 rcvdpkt=47 sentdelta=940 "
  , "rcvddelta=1058 mastersrcmac=\"f3:9e:78:1a:af:fc\" "
  , "srcmac=\"f1:85:44:32:20:fc\" srcserver=0 dsthwvendor=\"VMware\" "
  , "dstosname=\"Windows\" dstswversion=\"8\" dstunauthuser=\"administrator\" "
  , "dstunauthusersource=\"kerberos\" masterdstmac=\"0f:51:03:84:39:4b\" "
  , "dstmac=\"09:31:40:af:ba:35\" dstserver=0"
  ]

traffic_forward_H :: Bytes
traffic_forward_H = pack $ concat
  [ "<189>logver=56 timestamp=1628858159 tz=\"UTC-5\" devname=\"big_device\" "
  , "devid=\"FG600C3913802107\" vd=\"root\" date=2021-08-13 time=07:35:59 "
  , "logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" "
  , "level=\"notice\" eventtime=1628858159 srcip=192.0.2.211 "
  , "srcname=\"MY-SRC\" srcport=62285 srcintf=\"Internal\" "
  , "srcintfrole=\"lan\" dstip=192.0.2.254 dstport=8888 dstintf=\"WAN\" "
  , "dstintfrole=\"wan\" poluuid=\"2e89feec-b855-0144-8c7d-957aba25cadc\" "
  , "sessionid=182927871 proto=17 action=\"accept\" policyid=61 "
  , "policytype=\"policy\" service=\"udp/8888\" dstcountry=\"United Kingdom\" "
  , "srccountry=\"Reserved\" trandisp=\"noop\" duration=180 sentbyte=92 "
  , "rcvdbyte=64 sentpkt=1 rcvdpkt=1 appcat=\"unscanned\" "
  , "devtype=\"Windows PC\" osname=\"Windows 10 / 2016\" "
  , "unauthuser=\"MYUSER$\" unauthusersource=\"kerberos\" "
  , "mastersrcmac=\"f4:ea:ab:01:23:65\" srcmac=\"af:fa:ab:ba:07:70\" "
  , "srcserver=1"
  ]

traffic_forward_I :: Bytes
traffic_forward_I = pack $ concat
  [ "<189>logver=604071911 timestamp=1635340667 devname=\"EXAMPLE-FW\" "
  , "devid=\"FG200FT920865370\" vd=\"root\" date=2021-10-27 time=09:17:47 "
  , "eventtime=1635340667879071090 tz=\"-0400\" logid=\"0000000013\" "
  , "type=\"traffic\" subtype=\"forward\" level=\"notice\" "
  , "srcip=192.0.2.5 srcport=44069"
  ]

event_wireless_A :: Bytes
event_wireless_A = pack $ concat
  [ "<172>date=2021-09-08 time=15:01:46 devname=\"alphabot\" "
  , "devid=\"FG500E3914707621\" logid=\"0104043673\" type=\"event\" "
  , "subtype=\"wireless\" level=\"warning\" vd=\"root\" "
  , "eventtime=1631106107482668813 tz=\"+0200\" logdesc=\"Wireless "
  , "station DNS process failed due to non-existing domain\" "
  , "sn=\"FP220FTF50814936\" action=\"DNS-no-domain\" "
  , "reason=\"Server 192.0.2.105 replied \\\"non-existing domain\\\"\" "
  , "msg=\"DNS lookup of example.com from client ab:cd:ef:00:11:ef "
  , "failed with \\\"non-existing domain\\\"\" remotewtptime=\"98.594337\""
  ]

traffic_forward_J :: Bytes
traffic_forward_J = pack $ concat
  [ "<189>logver=604071911 timestamp=1657911096 devname=\"dabot\" "
  , "devid=\"FG5H1E5818482910\" vd=\"root\" date=2022-07-15 "
  , "time=13:51:36 eventtime=1657911096381101465 tz=\"-0500\" logid=\"0000000020\" "
  , "type=\"traffic\" subtype=\"forward\" level=\"notice\" srcip=192.168.190.18 "
  , "srcname=\"SYN-TEST\" srcport=54519 srcintf=\"myintf\" srcintfrole=\"lan\" "
  , "dstip=192.0.2.200 dstport=8081 dstintf=\"VDOM Link1\" "
  , "dstintfrole=\"undefined\" srccountry=\"Reserved\" "
  , "dstcountry=\"United States\" sessionid=3459023332 proto=6 action=\"accept\" "
  , "policyid=212 policytype=\"policy\" poluuid=\"b71a33a6-0f55-51e4-337e-78c707d90be0\" "
  , "policyname=\"test-to-external\" service=\"EDR\" trandisp=\"snat\" "
  , "transip=192.0.2.254 transport=54519 duration=1719 "
  , "sentbyte=208014 rcvdbyte=112971 sentpkt=1013 rcvdpkt=1013 "
  , "appcat=\"unscanned\" sentdelta=14688 rcvddelta=7896 srchwvendor=\"VMware\" "
  , "devtype=\"Server\" srcfamily=\"Virtual Machine\" osname=\"Windows\" "
  , "srchwversion=\"Workstation pro\" srcswversion=\"8.1\" "
  , "unauthuser=\"administrator\" unauthusersource=\"kerberos\" "
  , "mastersrcmac=\"01:50:06:95:6e:ef\" srcmac=\"f0:43:56:94:0e:ef\" srcserver=0"
  ]
