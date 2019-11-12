{-# language LambdaCase #-}

import Control.Monad (when)
import Data.Bytes (Bytes)
import Data.Foldable (for_)

import qualified Data.Bytes as Bytes
import qualified Fortios.Syslog as FGT
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
