{-# language PatternSynonyms #-}

--Notice: Generated by scripts/Generate.hs
--This module is generated. Do not modify its contents by hand.
module Fortios.Generated
  ( pattern H_action
  , pattern H_app
  , pattern H_appcat
  , pattern H_appid
  , pattern H_applist
  , pattern H_apprisk
  , pattern H_cat
  , pattern H_catdesc
  , pattern H_countweb
  , pattern H_craction
  , pattern H_crlevel
  , pattern H_crscore
  , pattern H_devtype
  , pattern H_dhcp_msg
  , pattern H_direction
  , pattern H_dstcountry
  , pattern H_dstinetsvc
  , pattern H_dstintf
  , pattern H_dstintfrole
  , pattern H_dstip
  , pattern H_dstport
  , pattern H_duration
  , pattern H_error
  , pattern H_eventtime
  , pattern H_eventtype
  , pattern H_group
  , pattern H_hostname
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
  , pattern H_policyid
  , pattern H_policytype
  , pattern H_poluuid
  , pattern H_profile
  , pattern H_profiletype
  , pattern H_proto
  , pattern H_rcvdbyte
  , pattern H_rcvddelta
  , pattern H_rcvdpkt
  , pattern H_referralurl
  , pattern H_reqtype
  , pattern H_sentbyte
  , pattern H_sentdelta
  , pattern H_sentpkt
  , pattern H_service
  , pattern H_sessionid
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
  , pattern H_trandisp
  , pattern H_tz
  , pattern H_url
  , pattern H_urlfilteridx
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

  ) where

import Fortios.Hash (duohash,quadrohash)
import Data.Bytes.Types (Bytes(Bytes))

import Data.Primitive (ByteArray)

pattern H_action :: Word
pattern H_action = 6

pattern H_app :: Word
pattern H_app = 5

pattern H_appcat :: Word
pattern H_appcat = 1

pattern H_appid :: Word
pattern H_appid = 4

pattern H_applist :: Word
pattern H_applist = 3

pattern H_apprisk :: Word
pattern H_apprisk = 11

pattern H_cat :: Word
pattern H_cat = 0

pattern H_catdesc :: Word
pattern H_catdesc = 0

pattern H_countweb :: Word
pattern H_countweb = 3

pattern H_craction :: Word
pattern H_craction = 0

pattern H_crlevel :: Word
pattern H_crlevel = 15

pattern H_crscore :: Word
pattern H_crscore = 8

pattern H_devtype :: Word
pattern H_devtype = 13

pattern H_dhcp_msg :: Word
pattern H_dhcp_msg = 4

pattern H_direction :: Word
pattern H_direction = 2

pattern H_dstcountry :: Word
pattern H_dstcountry = 1

pattern H_dstinetsvc :: Word
pattern H_dstinetsvc = 3

pattern H_dstintf :: Word
pattern H_dstintf = 21

pattern H_dstintfrole :: Word
pattern H_dstintfrole = 0

pattern H_dstip :: Word
pattern H_dstip = 9

pattern H_dstport :: Word
pattern H_dstport = 9

pattern H_duration :: Word
pattern H_duration = 6

pattern H_error :: Word
pattern H_error = 6

pattern H_eventtime :: Word
pattern H_eventtime = 1

pattern H_eventtype :: Word
pattern H_eventtype = 5

pattern H_group :: Word
pattern H_group = 10

pattern H_hostname :: Word
pattern H_hostname = 5

pattern H_interface :: Word
pattern H_interface = 0

pattern H_ip :: Word
pattern H_ip = 1

pattern H_lanin :: Word
pattern H_lanin = 5

pattern H_lanout :: Word
pattern H_lanout = 2

pattern H_lease :: Word
pattern H_lease = 11

pattern H_level :: Word
pattern H_level = 1

pattern H_logdesc :: Word
pattern H_logdesc = 10

pattern H_mac :: Word
pattern H_mac = 2

pattern H_mastersrcmac :: Word
pattern H_mastersrcmac = 3

pattern H_method :: Word
pattern H_method = 3

pattern H_msg :: Word
pattern H_msg = 4

pattern H_osname :: Word
pattern H_osname = 7

pattern H_policyid :: Word
pattern H_policyid = 9

pattern H_policytype :: Word
pattern H_policytype = 0

pattern H_poluuid :: Word
pattern H_poluuid = 5

pattern H_profile :: Word
pattern H_profile = 7

pattern H_profiletype :: Word
pattern H_profiletype = 4

pattern H_proto :: Word
pattern H_proto = 8

pattern H_rcvdbyte :: Word
pattern H_rcvdbyte = 1

pattern H_rcvddelta :: Word
pattern H_rcvddelta = 8

pattern H_rcvdpkt :: Word
pattern H_rcvdpkt = 1

pattern H_referralurl :: Word
pattern H_referralurl = 2

pattern H_reqtype :: Word
pattern H_reqtype = 20

pattern H_sentbyte :: Word
pattern H_sentbyte = 8

pattern H_sentdelta :: Word
pattern H_sentdelta = 11

pattern H_sentpkt :: Word
pattern H_sentpkt = 18

pattern H_service :: Word
pattern H_service = 6

pattern H_sessionid :: Word
pattern H_sessionid = 7

pattern H_srccountry :: Word
pattern H_srccountry = 2

pattern H_srchwvendor :: Word
pattern H_srchwvendor = 1

pattern H_srcintf :: Word
pattern H_srcintf = 16

pattern H_srcintfrole :: Word
pattern H_srcintfrole = 3

pattern H_srcip :: Word
pattern H_srcip = 2

pattern H_srcmac :: Word
pattern H_srcmac = 4

pattern H_srcname :: Word
pattern H_srcname = 12

pattern H_srcport :: Word
pattern H_srcport = 4

pattern H_srcserver :: Word
pattern H_srcserver = 3

pattern H_srcswversion :: Word
pattern H_srcswversion = 0

pattern H_trandisp :: Word
pattern H_trandisp = 2

pattern H_tz :: Word
pattern H_tz = 0

pattern H_url :: Word
pattern H_url = 3

pattern H_urlfilteridx :: Word
pattern H_urlfilteridx = 2

pattern H_user :: Word
pattern H_user = 0

pattern H_utmaction :: Word
pattern H_utmaction = 10

pattern H_vd :: Word
pattern H_vd = 2

pattern H_vwlid :: Word
pattern H_vwlid = 3

pattern H_wanin :: Word
pattern H_wanin = 0

pattern H_wanout :: Word
pattern H_wanout = 0


hashString2 :: ByteArray -> Int -> Word
hashString2 arr off = rem (duohash 0 29257 13044 (Bytes arr off 2)) 4

hashString3 :: ByteArray -> Int -> Word
hashString3 arr off = rem (duohash 0 50549 47481 (Bytes arr off 2)) 8

hashString4 :: ByteArray -> Int -> Word
hashString4 arr off = rem (duohash 0 7812 32790 (Bytes arr off 4)) 1

hashString5 :: ByteArray -> Int -> Word
hashString5 arr off = rem (quadrohash 0 689 27350 41936 715 (Bytes arr off 4)) 16

hashString6 :: ByteArray -> Int -> Word
hashString6 arr off = rem (duohash 0 706 39715 (Bytes arr off 6)) 8

hashString7 :: ByteArray -> Int -> Word
hashString7 arr off = rem (quadrohash 0 16595 57803 45639 47116 (Bytes arr off 4)) 32

hashString8 :: ByteArray -> Int -> Word
hashString8 arr off = rem (quadrohash 0 58375 19444 3257 47955 (Bytes arr off 8)) 16

hashString9 :: ByteArray -> Int -> Word
hashString9 arr off = rem (duohash 0 15219 62620 (Bytes arr off 8)) 16

hashString10 :: ByteArray -> Int -> Word
hashString10 arr off = rem (duohash 0 25263 22349 (Bytes arr off 10)) 4

hashString11 :: ByteArray -> Int -> Word
hashString11 arr off = rem (duohash 0 11166 5041 (Bytes arr off 10)) 8

hashString12 :: ByteArray -> Int -> Word
hashString12 arr off = rem (duohash 0 21102 29411 (Bytes arr off 12)) 4


