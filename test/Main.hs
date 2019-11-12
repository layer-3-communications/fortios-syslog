{-# language LambdaCase #-}

import Control.Monad (when)
import Control.Monad.Trans.Class (lift)
import Data.Bytes (Bytes)
import Data.Char (ord)
import Data.Foldable (for_)

import qualified Data.Bytes as Bytes
import qualified Fortios.Syslog as FGT
import qualified Data.List as List
import qualified List.Transformer as ListT
import qualified Sample as S
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "traffic_local_A"
  testTrafficLocalA
  putStrLn "traffic_forward_A"
  testTrafficForwardA
  pure ()

testTrafficLocalA :: IO ()
testTrafficLocalA = case FGT.decode S.traffic_local_A of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.type_ x /= str "traffic")
      (fail "wrong type")
    when (FGT.deviceId x /= str "FGT-Device")
      (fail "wrong device id")
    for_ (FGT.fields x)
      (\case
        FGT.ClientReputationLevel v ->
          when (v /= str "high") (fail "wrong crlevel")
        FGT.SessionId v ->
          when (v /= 69597381) (fail "wrong sessionid")
        FGT.DestinationCountry v ->
          when (v /= str "United States") (fail "wrong dstcountry")
        FGT.SourceIp v ->
          when (v /= IP.ipv4 192 0 2 12) (fail "wrong srcip")
        _ -> pure ()
      ) 

testTrafficForwardA :: IO ()
testTrafficForwardA = case FGT.decode S.traffic_forward_A of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "forward")
      (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.CountWeb v ->
          when (v /= 1) (fail "wrong countweb")
        FGT.TranslatedSource ip port -> do
          when (ip /= IPv4.fromOctets 192 0 2 3) (fail "wrong transip")
          when (port /= 54400) (fail "wrong transport")
        _ -> pure ()
      ) 

str :: String -> Bytes
str = Bytes.fromAsciiString

hashFunc :: String -> Int
hashFunc = List.foldl' (\acc c -> acc * ord c) 1

-- Check that the hash functions does not hash any of the
-- keys we are interested in to the same value.
checkCollisions :: IO ()
checkCollisions = ListT.runListT $ do
  k1 <- ListT.select keywords
  k2 <- ListT.select keywords
  let h1 = hashFunc k1
  let h2 = hashFunc k2
  when (h1 == h2 && k1 /= k2)
    $ lift (fail (k1 ++ " and " ++ k2 ++ " both hash to " ++ show h1))

keywords :: [String]
keywords =
  [ "action"
  , "app"
  , "appcat"
  , "cat"
  , "catdesc"
  , "craction"
  , "crlevel"
  , "crscore"
  , "destcountry"
  , "destintf"
  , "destip"
  , "destport"
  , "direction"
  , "duration"
  , "hostname"
  , "level"
  , "method"
  , "msg"
  , "policyid"
  , "policytype"
  , "profile"
  , "proto"
  , "rcvdbyte"
  , "rcvdpkt"
  , "sentbyte"
  , "sentpkt"
  , "service"
  , "sessionid"
  , "srccountry"
  , "srcintf"
  , "srcip"
  , "srcport"
  , "trandisp"
  , "transport"
  , "transip"
  , "url"
  , "vd"
  ]
