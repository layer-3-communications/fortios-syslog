{-# language PatternSynonyms #-}
module Fortios.Generated
  ( pattern H_action
  , pattern H_app
  , pattern H_appcat
  , pattern H_cat
  , pattern H_catdesc
  , pattern H_countweb
  , pattern H_craction
  , pattern H_crlevel
  , pattern H_crscore
  , pattern H_date
  , pattern H_devid
  , pattern H_devname
  , pattern H_direction
  , pattern H_dstcountry
  , pattern H_dstintf
  , pattern H_dstip
  , pattern H_dstport
  , pattern H_duration
  , pattern H_eventtype
  , pattern H_hostname
  , pattern H_lanin
  , pattern H_lanout
  , pattern H_level
  , pattern H_logid
  , pattern H_method
  , pattern H_msg
  , pattern H_policyid
  , pattern H_policytype
  , pattern H_poluuid
  , pattern H_profile
  , pattern H_proto
  , pattern H_rcvdbyte
  , pattern H_rcvdpkt
  , pattern H_reqtype
  , pattern H_sentbyte
  , pattern H_sentpkt
  , pattern H_service
  , pattern H_sessionid
  , pattern H_srccountry
  , pattern H_srcintf
  , pattern H_srcip
  , pattern H_srcport
  , pattern H_subtype
  , pattern H_time
  , pattern H_trandisp
  , pattern H_transip
  , pattern H_transport
  , pattern H_type
  , pattern H_url
  , pattern H_user
  , pattern H_utmaction
  , pattern H_vd
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

  ) where

import Fortios.Hash (duohash,quadrohash)
import Data.Bytes.Types (Bytes(Bytes))

import Data.Primitive (ByteArray)

pattern H_action :: Word
pattern H_action = 2

pattern H_app :: Word
pattern H_app = 4

pattern H_appcat :: Word
pattern H_appcat = 3

pattern H_cat :: Word
pattern H_cat = 3

pattern H_catdesc :: Word
pattern H_catdesc = 12

pattern H_countweb :: Word
pattern H_countweb = 9

pattern H_craction :: Word
pattern H_craction = 7

pattern H_crlevel :: Word
pattern H_crlevel = 29

pattern H_crscore :: Word
pattern H_crscore = 19

pattern H_date :: Word
pattern H_date = 0

pattern H_devid :: Word
pattern H_devid = 4

pattern H_devname :: Word
pattern H_devname = 27

pattern H_direction :: Word
pattern H_direction = 4

pattern H_dstcountry :: Word
pattern H_dstcountry = 3

pattern H_dstintf :: Word
pattern H_dstintf = 6

pattern H_dstip :: Word
pattern H_dstip = 12

pattern H_dstport :: Word
pattern H_dstport = 17

pattern H_duration :: Word
pattern H_duration = 5

pattern H_eventtype :: Word
pattern H_eventtype = 1

pattern H_hostname :: Word
pattern H_hostname = 2

pattern H_lanin :: Word
pattern H_lanin = 8

pattern H_lanout :: Word
pattern H_lanout = 0

pattern H_level :: Word
pattern H_level = 0

pattern H_logid :: Word
pattern H_logid = 11

pattern H_method :: Word
pattern H_method = 5

pattern H_msg :: Word
pattern H_msg = 1

pattern H_policyid :: Word
pattern H_policyid = 4

pattern H_policytype :: Word
pattern H_policytype = 0

pattern H_poluuid :: Word
pattern H_poluuid = 11

pattern H_profile :: Word
pattern H_profile = 16

pattern H_proto :: Word
pattern H_proto = 1

pattern H_rcvdbyte :: Word
pattern H_rcvdbyte = 10

pattern H_rcvdpkt :: Word
pattern H_rcvdpkt = 28

pattern H_reqtype :: Word
pattern H_reqtype = 14

pattern H_sentbyte :: Word
pattern H_sentbyte = 11

pattern H_sentpkt :: Word
pattern H_sentpkt = 25

pattern H_service :: Word
pattern H_service = 10

pattern H_sessionid :: Word
pattern H_sessionid = 3

pattern H_srccountry :: Word
pattern H_srccountry = 2

pattern H_srcintf :: Word
pattern H_srcintf = 2

pattern H_srcip :: Word
pattern H_srcip = 7

pattern H_srcport :: Word
pattern H_srcport = 13

pattern H_subtype :: Word
pattern H_subtype = 0

pattern H_time :: Word
pattern H_time = 1

pattern H_trandisp :: Word
pattern H_trandisp = 8

pattern H_transip :: Word
pattern H_transip = 26

pattern H_transport :: Word
pattern H_transport = 5

pattern H_type :: Word
pattern H_type = 4

pattern H_url :: Word
pattern H_url = 2

pattern H_user :: Word
pattern H_user = 2

pattern H_utmaction :: Word
pattern H_utmaction = 2

pattern H_vd :: Word
pattern H_vd = 0

pattern H_wanin :: Word
pattern H_wanin = 3

pattern H_wanout :: Word
pattern H_wanout = 4


hashString2 :: ByteArray -> Int -> Word
hashString2 arr off = rem (duohash 0 28212 36399 (Bytes arr off 2)) 2

hashString3 :: ByteArray -> Int -> Word
hashString3 arr off = rem (duohash 0 3084 9207 (Bytes arr off 2)) 8

hashString4 :: ByteArray -> Int -> Word
hashString4 arr off = rem (duohash 0 31321 25528 (Bytes arr off 4)) 8

hashString5 :: ByteArray -> Int -> Word
hashString5 arr off = rem (duohash 0 56497 51171 (Bytes arr off 4)) 16

hashString6 :: ByteArray -> Int -> Word
hashString6 arr off = rem (duohash 0 24380 44901 (Bytes arr off 6)) 8

hashString7 :: ByteArray -> Int -> Word
hashString7 arr off = rem (duohash 0 41825 22754 (Bytes arr off 6)) 32

hashString8 :: ByteArray -> Int -> Word
hashString8 arr off = rem (duohash 0 321 28204 (Bytes arr off 8)) 16

hashString9 :: ByteArray -> Int -> Word
hashString9 arr off = rem (duohash 0 53015 60718 (Bytes arr off 8)) 8

hashString10 :: ByteArray -> Int -> Word
hashString10 arr off = rem (duohash 0 64129 10191 (Bytes arr off 10)) 4


