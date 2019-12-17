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
  putStrLn "traffic_local_B"
  testTrafficLocalB
  putStrLn "traffic_forward_A"
  testTrafficForwardA
  putStrLn "traffic_forward_B"
  testTrafficForwardB
  putStrLn "traffic_forward_C"
  testTrafficForwardC
  putStrLn "traffic_forward_D"
  testTrafficForwardD
  putStrLn "utm_webfilter_A"
  testUtmWebfilterA
  putStrLn "utm_webfilter_B"
  testUtmWebfilterB
  putStrLn "utm_webfilter_C"
  testUtmWebfilterC
  putStrLn "event_system_A"
  testEventSystemA
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

testTrafficLocalB :: IO ()
testTrafficLocalB = case FGT.decode S.traffic_local_B of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.type_ x /= str "traffic")
      (fail "wrong type")
    when (FGT.deviceId x /= str "FG200ABC00001")
      (fail "wrong device id")
    for_ (FGT.fields x)
      (\case
        FGT.SourceIp v ->
          when (v /= IP.ipv6 0x2001 0x0DB8 0x0 0x0 0x0 0x0 0x1 0x2) (fail "wrong srcip")
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

testTrafficForwardB :: IO ()
testTrafficForwardB = case FGT.decode S.traffic_forward_B of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "forward")
      (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.TranslatedDestination ip port -> do
          when (ip /= IPv4.fromOctets 192 0 2 200) (fail "wrong tranip")
          when (port /= 443) (fail "wrong tranport")
        _ -> pure ()
      )

testTrafficForwardC :: IO ()
testTrafficForwardC = case FGT.decode S.traffic_forward_C of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "forward")
      (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.OsName n -> when (n /= str "Windows") (fail "wrong osname")
        FGT.EventTime n -> when (n /= 1574989980897483985) (fail "wrong eventtime")
        FGT.TimeZone n -> when (n /= (-600)) (fail "wrong tz")
        _ -> pure ()
      )

testTrafficForwardD :: IO ()
testTrafficForwardD = case FGT.decode S.traffic_forward_C of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "forward")
      (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.DeviceType n -> when (n /= str "Router/Nat Device")
          (fail "wrong devtype")
        _ -> pure ()
      )

testUtmWebfilterA :: IO ()
testUtmWebfilterA = case FGT.decode S.utm_webfilter_A of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "webfilter") (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.Profile name -> when (name /= str "my-profile") (fail "profile")
        _ -> pure ()
      )

testUtmWebfilterB :: IO ()
testUtmWebfilterB = case FGT.decode S.utm_webfilter_B of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "webfilter") (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.Profile name -> when (name /= str "default") (fail "profile")
        FGT.Error name -> when (name /= str "DNS query timeout") (fail "error")
        _ -> pure ()
      )

testUtmWebfilterC :: IO ()
testUtmWebfilterC = case FGT.decode S.utm_webfilter_C of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "webfilter") (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.Profile name -> when (name /= str "prof") (fail "profile")
        FGT.ReferralUrl name -> when
          (name /= str "http://www.example.org/get/started")
          (fail "referralurl")
        _ -> pure ()
      )

testEventSystemA :: IO ()
testEventSystemA = case FGT.decode S.event_system_A of
  Left e -> fail (show e)
  Right x -> do
    when (FGT.subtype x /= str "system") (fail "wrong subtype")
    for_ (FGT.fields x)
      (\case
        FGT.Profile name -> when (name /= str "prof") (fail "profile")
        FGT.DhcpMessage name -> when (name /= str "Ack") (fail "dhcp_message")
        FGT.Interface name ->
          when (name /= str "vlan-11-trust") (fail "interface")
        FGT.LogDescription name ->
          when (name /= str "DHCP Ack log") (fail "logdesc")
        FGT.Lease n -> when (n /= 3600) (fail "lease")
        _ -> pure ()
      )

str :: String -> Bytes
str = Bytes.fromAsciiString
