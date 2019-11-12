{-# language TypeApplications #-}

module Sample
  ( traffic_local_A
  , traffic_forward_A
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
