{-# language PatternSynonyms #-}

--Notice: Generated by scripts/Generate.hs
--This module is generated. Do not modify its contents by hand.
module Fortios.Generated
  ( pattern H_action
  , pattern H_alert
  , pattern H_app
  , pattern H_appcat
  , pattern H_appid
  , pattern H_applist
  , pattern H_apprisk
  , pattern H_attack
  , pattern H_attackid
  , pattern H_cat
  , pattern H_catdesc
  , pattern H_centralnatid
  , pattern H_countapp
  , pattern H_countweb
  , pattern H_craction
  , pattern H_crlevel
  , pattern H_crscore
  , pattern H_desc
  , pattern H_devtype
  , pattern H_dhcp_msg
  , pattern H_direction
  , pattern H_dstcountry
  , pattern H_dstinetsvc
  , pattern H_dstintf
  , pattern H_dstintfrole
  , pattern H_dstip
  , pattern H_dstport
  , pattern H_dstuuid
  , pattern H_duration
  , pattern H_error
  , pattern H_eventtime
  , pattern H_eventtype
  , pattern H_group
  , pattern H_hostname
  , pattern H_incidentserialno
  , pattern H_interface
  , pattern H_ip
  , pattern H_lanin
  , pattern H_lanout
  , pattern H_lease
  , pattern H_level
  , pattern H_logdesc
  , pattern H_mac
  , pattern H_mastersrcmac
  , pattern H_method
  , pattern H_msg
  , pattern H_osname
  , pattern H_osversion
  , pattern H_policyid
  , pattern H_policytype
  , pattern H_poluuid
  , pattern H_profile
  , pattern H_profiletype
  , pattern H_proto
  , pattern H_rcvdbyte
  , pattern H_rcvddelta
  , pattern H_rcvdpkt
  , pattern H_ref
  , pattern H_referralurl
  , pattern H_reqtype
  , pattern H_sentbyte
  , pattern H_sentdelta
  , pattern H_sentpkt
  , pattern H_service
  , pattern H_session_id
  , pattern H_sessionid
  , pattern H_severity
  , pattern H_srccountry
  , pattern H_srchwvendor
  , pattern H_srcintf
  , pattern H_srcintfrole
  , pattern H_srcip
  , pattern H_srcmac
  , pattern H_srcname
  , pattern H_srcport
  , pattern H_srcserver
  , pattern H_srcswversion
  , pattern H_srcuuid
  , pattern H_trandisp
  , pattern H_tz
  , pattern H_url
  , pattern H_urlfilteridx
  , pattern H_urlfilterlist
  , pattern H_user
  , pattern H_utmaction
  , pattern H_vd
  , pattern H_vwlid
  , pattern H_wanin
  , pattern H_wanout

  , hashString2
  , hashString3
  , hashString4
  , hashString5
  , hashString6
  , hashString7
  , hashString8
  , hashString9
  , hashString10
  , hashString11
  , hashString12
  , hashString13
  , hashString16

  ) where

import Fortios.Hash (duohash,quadrohash)
import Data.Bytes.Types (Bytes(Bytes))

import Data.Primitive (ByteArray)

pattern H_action :: Word
pattern H_action = 6

pattern H_alert :: Word
pattern H_alert = 0

pattern H_app :: Word
pattern H_app = 3

pattern H_appcat :: Word
pattern H_appcat = 7

pattern H_appid :: Word
pattern H_appid = 3

pattern H_applist :: Word
pattern H_applist = 25

pattern H_apprisk :: Word
pattern H_apprisk = 11

pattern H_attack :: Word
pattern H_attack = 3

pattern H_attackid :: Word
pattern H_attackid = 0

pattern H_cat :: Word
pattern H_cat = 0

pattern H_catdesc :: Word
pattern H_catdesc = 20

pattern H_centralnatid :: Word
pattern H_centralnatid = 1

pattern H_countapp :: Word
pattern H_countapp = 3

pattern H_countweb :: Word
pattern H_countweb = 4

pattern H_craction :: Word
pattern H_craction = 5

pattern H_crlevel :: Word
pattern H_crlevel = 24

pattern H_crscore :: Word
pattern H_crscore = 0

pattern H_desc :: Word
pattern H_desc = 0

pattern H_devtype :: Word
pattern H_devtype = 17

pattern H_dhcp_msg :: Word
pattern H_dhcp_msg = 13

pattern H_direction :: Word
pattern H_direction = 2

pattern H_dstcountry :: Word
pattern H_dstcountry = 1

pattern H_dstinetsvc :: Word
pattern H_dstinetsvc = 0

pattern H_dstintf :: Word
pattern H_dstintf = 10

pattern H_dstintfrole :: Word
pattern H_dstintfrole = 5

pattern H_dstip :: Word
pattern H_dstip = 8

pattern H_dstport :: Word
pattern H_dstport = 15

pattern H_dstuuid :: Word
pattern H_dstuuid = 14

pattern H_duration :: Word
pattern H_duration = 7

pattern H_error :: Word
pattern H_error = 1

pattern H_eventtime :: Word
pattern H_eventtime = 3

pattern H_eventtype :: Word
pattern H_eventtype = 9

pattern H_group :: Word
pattern H_group = 12

pattern H_hostname :: Word
pattern H_hostname = 2

pattern H_incidentserialno :: Word
pattern H_incidentserialno = 0

pattern H_interface :: Word
pattern H_interface = 5

pattern H_ip :: Word
pattern H_ip = 3

pattern H_lanin :: Word
pattern H_lanin = 10

pattern H_lanout :: Word
pattern H_lanout = 1

pattern H_lease :: Word
pattern H_lease = 5

pattern H_level :: Word
pattern H_level = 2

pattern H_logdesc :: Word
pattern H_logdesc = 21

pattern H_mac :: Word
pattern H_mac = 6

pattern H_mastersrcmac :: Word
pattern H_mastersrcmac = 3

pattern H_method :: Word
pattern H_method = 0

pattern H_msg :: Word
pattern H_msg = 4

pattern H_osname :: Word
pattern H_osname = 4

pattern H_osversion :: Word
pattern H_osversion = 1

pattern H_policyid :: Word
pattern H_policyid = 9

pattern H_policytype :: Word
pattern H_policytype = 5

pattern H_poluuid :: Word
pattern H_poluuid = 22

pattern H_profile :: Word
pattern H_profile = 18

pattern H_profiletype :: Word
pattern H_profiletype = 2

pattern H_proto :: Word
pattern H_proto = 7

pattern H_rcvdbyte :: Word
pattern H_rcvdbyte = 12

pattern H_rcvddelta :: Word
pattern H_rcvddelta = 10

pattern H_rcvdpkt :: Word
pattern H_rcvdpkt = 5

pattern H_ref :: Word
pattern H_ref = 1

pattern H_referralurl :: Word
pattern H_referralurl = 4

pattern H_reqtype :: Word
pattern H_reqtype = 13

pattern H_sentbyte :: Word
pattern H_sentbyte = 6

pattern H_sentdelta :: Word
pattern H_sentdelta = 7

pattern H_sentpkt :: Word
pattern H_sentpkt = 12

pattern H_service :: Word
pattern H_service = 26

pattern H_session_id :: Word
pattern H_session_id = 2

pattern H_sessionid :: Word
pattern H_sessionid = 8

pattern H_severity :: Word
pattern H_severity = 8

pattern H_srccountry :: Word
pattern H_srccountry = 3

pattern H_srchwvendor :: Word
pattern H_srchwvendor = 0

pattern H_srcintf :: Word
pattern H_srcintf = 2

pattern H_srcintfrole :: Word
pattern H_srcintfrole = 1

pattern H_srcip :: Word
pattern H_srcip = 4

pattern H_srcmac :: Word
pattern H_srcmac = 5

pattern H_srcname :: Word
pattern H_srcname = 1

pattern H_srcport :: Word
pattern H_srcport = 7

pattern H_srcserver :: Word
pattern H_srcserver = 4

pattern H_srcswversion :: Word
pattern H_srcswversion = 0

pattern H_srcuuid :: Word
pattern H_srcuuid = 6

pattern H_trandisp :: Word
pattern H_trandisp = 11

pattern H_tz :: Word
pattern H_tz = 0

pattern H_url :: Word
pattern H_url = 5

pattern H_urlfilteridx :: Word
pattern H_urlfilteridx = 2

pattern H_urlfilterlist :: Word
pattern H_urlfilterlist = 0

pattern H_user :: Word
pattern H_user = 1

pattern H_utmaction :: Word
pattern H_utmaction = 0

pattern H_vd :: Word
pattern H_vd = 2

pattern H_vwlid :: Word
pattern H_vwlid = 6

pattern H_wanin :: Word
pattern H_wanin = 11

pattern H_wanout :: Word
pattern H_wanout = 2


hashString2 :: ByteArray -> Int -> Word
hashString2 arr off = rem (duohash 0 57023 18890 (Bytes arr off 2)) 4

hashString3 :: ByteArray -> Int -> Word
hashString3 arr off = rem (duohash 0 33971 31175 (Bytes arr off 2)) 8

hashString4 :: ByteArray -> Int -> Word
hashString4 arr off = rem (duohash 0 28960 49589 (Bytes arr off 4)) 2

hashString5 :: ByteArray -> Int -> Word
hashString5 arr off = rem (quadrohash 0 35107 25240 40393 41216 (Bytes arr off 4)) 16

hashString6 :: ByteArray -> Int -> Word
hashString6 arr off = rem (quadrohash 0 18259 47069 30730 8500 (Bytes arr off 4)) 8

hashString7 :: ByteArray -> Int -> Word
hashString7 arr off = rem (quadrohash 0 48261 849 60258 60499 (Bytes arr off 4)) 32

hashString8 :: ByteArray -> Int -> Word
hashString8 arr off = rem (quadrohash 0 23376 33897 57435 33138 (Bytes arr off 8)) 16

hashString9 :: ByteArray -> Int -> Word
hashString9 arr off = rem (quadrohash 0 34811 35513 39224 43938 (Bytes arr off 8)) 16

hashString10 :: ByteArray -> Int -> Word
hashString10 arr off = rem (duohash 0 21855 13904 (Bytes arr off 10)) 8

hashString11 :: ByteArray -> Int -> Word
hashString11 arr off = rem (duohash 0 25827 64894 (Bytes arr off 10)) 8

hashString12 :: ByteArray -> Int -> Word
hashString12 arr off = rem (duohash 0 1097 29135 (Bytes arr off 12)) 4

hashString13 :: ByteArray -> Int -> Word
hashString13 arr off = rem (duohash 0 20065 21433 (Bytes arr off 12)) 1

hashString16 :: ByteArray -> Int -> Word
hashString16 arr off = rem (duohash 0 13848 15794 (Bytes arr off 16)) 1


