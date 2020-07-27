{-# language PatternSynonyms #-}

--Notice: Generated by scripts/Generate.hs
--This module is generated. Do not modify its contents by hand.
module Fortios.Generated
  ( pattern H_action
  , pattern H_alert
  , pattern H_app
  , pattern H_appact
  , pattern H_appcat
  , pattern H_appid
  , pattern H_applist
  , pattern H_apprisk
  , pattern H_attack
  , pattern H_attackid
  , pattern H_authserver
  , pattern H_cat
  , pattern H_catdesc
  , pattern H_centralnatid
  , pattern H_countapp
  , pattern H_countips
  , pattern H_countweb
  , pattern H_craction
  , pattern H_crlevel
  , pattern H_crscore
  , pattern H_desc
  , pattern H_devcategory
  , pattern H_devtype
  , pattern H_dhcp_msg
  , pattern H_direction
  , pattern H_dstcountry
  , pattern H_dstdevtype
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
  , pattern H_scertcname
  , pattern H_scertissuer
  , pattern H_sentbyte
  , pattern H_sentdelta
  , pattern H_sentpkt
  , pattern H_service
  , pattern H_session_id
  , pattern H_sessionid
  , pattern H_severity
  , pattern H_srccountry
  , pattern H_srcfamily
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
  , pattern H_unauthuser
  , pattern H_unauthusersource
  , pattern H_url
  , pattern H_urlfilteridx
  , pattern H_urlfilterlist
  , pattern H_user
  , pattern H_utmaction
  , pattern H_vd
  , pattern H_vwlid
  , pattern H_vwlquality
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
pattern H_action = 4

pattern H_alert :: Word
pattern H_alert = 1

pattern H_app :: Word
pattern H_app = 3

pattern H_appact :: Word
pattern H_appact = 7

pattern H_appcat :: Word
pattern H_appcat = 1

pattern H_appid :: Word
pattern H_appid = 6

pattern H_applist :: Word
pattern H_applist = 13

pattern H_apprisk :: Word
pattern H_apprisk = 3

pattern H_attack :: Word
pattern H_attack = 3

pattern H_attackid :: Word
pattern H_attackid = 11

pattern H_authserver :: Word
pattern H_authserver = 0

pattern H_cat :: Word
pattern H_cat = 0

pattern H_catdesc :: Word
pattern H_catdesc = 25

pattern H_centralnatid :: Word
pattern H_centralnatid = 1

pattern H_countapp :: Word
pattern H_countapp = 7

pattern H_countips :: Word
pattern H_countips = 12

pattern H_countweb :: Word
pattern H_countweb = 1

pattern H_craction :: Word
pattern H_craction = 0

pattern H_crlevel :: Word
pattern H_crlevel = 4

pattern H_crscore :: Word
pattern H_crscore = 2

pattern H_desc :: Word
pattern H_desc = 0

pattern H_devcategory :: Word
pattern H_devcategory = 1

pattern H_devtype :: Word
pattern H_devtype = 18

pattern H_dhcp_msg :: Word
pattern H_dhcp_msg = 6

pattern H_direction :: Word
pattern H_direction = 5

pattern H_dstcountry :: Word
pattern H_dstcountry = 14

pattern H_dstdevtype :: Word
pattern H_dstdevtype = 5

pattern H_dstinetsvc :: Word
pattern H_dstinetsvc = 7

pattern H_dstintf :: Word
pattern H_dstintf = 27

pattern H_dstintfrole :: Word
pattern H_dstintfrole = 0

pattern H_dstip :: Word
pattern H_dstip = 12

pattern H_dstport :: Word
pattern H_dstport = 10

pattern H_dstuuid :: Word
pattern H_dstuuid = 7

pattern H_duration :: Word
pattern H_duration = 13

pattern H_error :: Word
pattern H_error = 4

pattern H_eventtime :: Word
pattern H_eventtime = 6

pattern H_eventtype :: Word
pattern H_eventtype = 9

pattern H_group :: Word
pattern H_group = 7

pattern H_hostname :: Word
pattern H_hostname = 9

pattern H_incidentserialno :: Word
pattern H_incidentserialno = 0

pattern H_interface :: Word
pattern H_interface = 8

pattern H_ip :: Word
pattern H_ip = 1

pattern H_lanin :: Word
pattern H_lanin = 2

pattern H_lanout :: Word
pattern H_lanout = 2

pattern H_lease :: Word
pattern H_lease = 3

pattern H_level :: Word
pattern H_level = 10

pattern H_logdesc :: Word
pattern H_logdesc = 14

pattern H_mac :: Word
pattern H_mac = 6

pattern H_mastersrcmac :: Word
pattern H_mastersrcmac = 3

pattern H_method :: Word
pattern H_method = 5

pattern H_msg :: Word
pattern H_msg = 4

pattern H_osname :: Word
pattern H_osname = 0

pattern H_osversion :: Word
pattern H_osversion = 2

pattern H_policyid :: Word
pattern H_policyid = 4

pattern H_policytype :: Word
pattern H_policytype = 13

pattern H_poluuid :: Word
pattern H_poluuid = 11

pattern H_profile :: Word
pattern H_profile = 26

pattern H_profiletype :: Word
pattern H_profiletype = 4

pattern H_proto :: Word
pattern H_proto = 5

pattern H_rcvdbyte :: Word
pattern H_rcvdbyte = 3

pattern H_rcvddelta :: Word
pattern H_rcvddelta = 0

pattern H_rcvdpkt :: Word
pattern H_rcvdpkt = 12

pattern H_ref :: Word
pattern H_ref = 1

pattern H_referralurl :: Word
pattern H_referralurl = 6

pattern H_reqtype :: Word
pattern H_reqtype = 16

pattern H_scertcname :: Word
pattern H_scertcname = 4

pattern H_scertissuer :: Word
pattern H_scertissuer = 2

pattern H_sentbyte :: Word
pattern H_sentbyte = 2

pattern H_sentdelta :: Word
pattern H_sentdelta = 1

pattern H_sentpkt :: Word
pattern H_sentpkt = 1

pattern H_service :: Word
pattern H_service = 19

pattern H_session_id :: Word
pattern H_session_id = 6

pattern H_sessionid :: Word
pattern H_sessionid = 3

pattern H_severity :: Word
pattern H_severity = 5

pattern H_srccountry :: Word
pattern H_srccountry = 9

pattern H_srcfamily :: Word
pattern H_srcfamily = 7

pattern H_srchwvendor :: Word
pattern H_srchwvendor = 7

pattern H_srcintf :: Word
pattern H_srcintf = 8

pattern H_srcintfrole :: Word
pattern H_srcintfrole = 5

pattern H_srcip :: Word
pattern H_srcip = 11

pattern H_srcmac :: Word
pattern H_srcmac = 9

pattern H_srcname :: Word
pattern H_srcname = 5

pattern H_srcport :: Word
pattern H_srcport = 23

pattern H_srcserver :: Word
pattern H_srcserver = 11

pattern H_srcswversion :: Word
pattern H_srcswversion = 0

pattern H_srcuuid :: Word
pattern H_srcuuid = 20

pattern H_trandisp :: Word
pattern H_trandisp = 10

pattern H_tz :: Word
pattern H_tz = 0

pattern H_unauthuser :: Word
pattern H_unauthuser = 8

pattern H_unauthusersource :: Word
pattern H_unauthusersource = 1

pattern H_url :: Word
pattern H_url = 5

pattern H_urlfilteridx :: Word
pattern H_urlfilteridx = 2

pattern H_urlfilterlist :: Word
pattern H_urlfilterlist = 0

pattern H_user :: Word
pattern H_user = 1

pattern H_utmaction :: Word
pattern H_utmaction = 10

pattern H_vd :: Word
pattern H_vd = 2

pattern H_vwlid :: Word
pattern H_vwlid = 8

pattern H_vwlquality :: Word
pattern H_vwlquality = 1

pattern H_wanin :: Word
pattern H_wanin = 0

pattern H_wanout :: Word
pattern H_wanout = 8


hashString2 :: ByteArray -> Int -> Word
hashString2 arr off = rem (duohash 0 37701 8996 (Bytes arr off 2)) 4

hashString3 :: ByteArray -> Int -> Word
hashString3 arr off = rem (duohash 0 57923 30111 (Bytes arr off 2)) 8

hashString4 :: ByteArray -> Int -> Word
hashString4 arr off = rem (duohash 0 7042 51599 (Bytes arr off 4)) 2

hashString5 :: ByteArray -> Int -> Word
hashString5 arr off = rem (quadrohash 0 47834 10980 32387 48252 (Bytes arr off 4)) 16

hashString6 :: ByteArray -> Int -> Word
hashString6 arr off = rem (quadrohash 0 4162 5831 32508 12469 (Bytes arr off 4)) 16

hashString7 :: ByteArray -> Int -> Word
hashString7 arr off = rem (quadrohash 0 27681 13778 37680 59417 (Bytes arr off 4)) 32

hashString8 :: ByteArray -> Int -> Word
hashString8 arr off = rem (quadrohash 0 49215 45424 48316 65079 (Bytes arr off 8)) 16

hashString9 :: ByteArray -> Int -> Word
hashString9 arr off = rem (quadrohash 0 37427 11579 27415 62977 (Bytes arr off 8)) 16

hashString10 :: ByteArray -> Int -> Word
hashString10 arr off = rem (duohash 0 5754 64753 (Bytes arr off 10)) 16

hashString11 :: ByteArray -> Int -> Word
hashString11 arr off = rem (duohash 0 62706 54975 (Bytes arr off 10)) 8

hashString12 :: ByteArray -> Int -> Word
hashString12 arr off = rem (duohash 0 41377 1747 (Bytes arr off 12)) 4

hashString13 :: ByteArray -> Int -> Word
hashString13 arr off = rem (duohash 0 6310 20919 (Bytes arr off 12)) 1

hashString16 :: ByteArray -> Int -> Word
hashString16 arr off = rem (duohash 0 2899 4452 (Bytes arr off 16)) 2


