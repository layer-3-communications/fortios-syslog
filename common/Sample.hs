{-# language TypeApplications #-}

module Sample
  ( traffic_local_A
  , traffic_local_B
  , traffic_forward_A
  , traffic_forward_B
  , traffic_forward_C
  , traffic_forward_D
  , traffic_forward_E
  , utm_webfilter_A
  , utm_webfilter_B
  , utm_webfilter_C
  , event_system_A
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
