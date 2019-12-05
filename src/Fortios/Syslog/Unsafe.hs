{-# language BangPatterns #-}
{-# language LambdaCase #-}
{-# language NamedFieldPuns #-}
{-# language PatternSynonyms #-}
{-# language ViewPatterns #-}
{-# language MagicHash #-}
{-# language TypeApplications #-}

module Fortios.Syslog.Unsafe
  ( Log(..)
  , Field(..)
  , DecodeException
  , afterEquals
  , fullParser
  , decode
  ) where

import Data.Char (ord)
import Data.Word (Word8,Word16,Word64)
import Data.WideWord (Word128)
import Data.Bytes.Types (Bytes(Bytes))
import Net.Types (IPv4,IP)
import Data.Chunks (Chunks)
import GHC.Exts (Int(I#),Char(C#),Char#,indexCharArray#,ord#,xorI#,orI#)
import GHC.Exts (Int#,(+#))
import Data.Primitive (ByteArray(..))
import Data.Bytes.Parser (Parser)
import Data.Builder.ST (Builder)

import qualified Data.Builder.ST as Builder
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4
import qualified Net.Types
import qualified Fortios.Generated as G

data Log = Log
  -- { date :: !Date
  -- , time :: !TimeOfDay
  { deviceName :: {-# UNPACK #-} !Bytes
  , deviceId :: {-# UNPACK #-} !Bytes
  , logId :: {-# UNPACK #-} !Bytes
  , type_ :: {-# UNPACK #-} !Bytes
  , subtype :: {-# UNPACK #-} !Bytes
  , fields :: !(Chunks Field)
  }

data DecodeException
  = ExpectedDate
  | ExpectedDeviceId
  | ExpectedDeviceName
  | ExpectedLogId
  | ExpectedSpace
  | ExpectedSubtype
  | ExpectedTime
  | ExpectedType
  | IncompleteKey
  | InvalidAction
  | InvalidApp
  | InvalidApplicationCategory
  | InvalidApplicationId
  | InvalidApplicationList
  | InvalidApplicationRisk
  | InvalidCategory
  | InvalidCategoryDescription
  | InvalidClientReputationAction
  | InvalidClientReputationLevel
  | InvalidClientReputationScore
  | InvalidCountWeb
  | InvalidDate
  | InvalidDestinationCountry
  | InvalidDestinationInterface
  | InvalidDestinationInterfaceRole
  | InvalidDestinationInternetService
  | InvalidDestinationIp
  | InvalidDestinationPort
  | InvalidDeviceId
  | InvalidDeviceName
  | InvalidDhcpMessage
  | InvalidDirection
  | InvalidDuration
  | InvalidError
  | InvalidEventTime
  | InvalidEventType
  | InvalidHostname
  | InvalidInterface
  | InvalidIp
  | InvalidLanIn
  | InvalidLanOut
  | InvalidLease
  | InvalidLevel
  | InvalidLogDescription
  | InvalidLogId
  | InvalidMac
  | InvalidMessage
  | InvalidMethod
  | InvalidOsName
  | InvalidPolicyId
  | InvalidPolicyType
  | InvalidPolicyUuid
  | InvalidProfile
  | InvalidProtocol
  | InvalidReceivedBytes
  | InvalidReceivedDelta
  | InvalidReceivedPackets
  | InvalidReferralUrl
  | InvalidRequestType
  | InvalidSentBytes
  | InvalidSentDelta
  | InvalidSentPackets
  | InvalidService
  | InvalidSessionId
  | InvalidSourceCountry
  | InvalidSourceHardwareVendor
  | InvalidSourceInterface
  | InvalidSourceInterfaceRole
  | InvalidSourceIp
  | InvalidSourceMac
  | InvalidSourceName
  | InvalidSourcePort
  | InvalidSourceServer
  | InvalidSourceSoftwareVersion
  | InvalidSubtype
  | InvalidSyslogPriority
  | InvalidTime
  | InvalidTimeZone
  | InvalidTranslationDisposition
  | InvalidTranslationIp
  | InvalidTranslationPort
  | InvalidType
  | InvalidUrl
  | InvalidUser
  | InvalidUtmAction
  | InvalidVirtualDomain
  | InvalidVirtualWanLinkId
  | InvalidWanIn
  | InvalidWanOut
  | UnknownField
  | UnknownField2
  | UnknownField3
  | UnknownField4
  | UnknownField5
  | UnknownField6
  | UnknownField7
  | UnknownField8
  | UnknownField9
  | UnknownField10
  | UnknownField11
  | UnknownField12
  deriving (Show)

data Field
  = Action {-# UNPACK #-} !Bytes
  | App {-# UNPACK #-} !Bytes
  | ApplicationCategory {-# UNPACK #-} !Bytes
  | ApplicationId {-# UNPACK #-} !Word64
  | ApplicationList {-# UNPACK #-} !Bytes
  | ApplicationRisk {-# UNPACK #-} !Bytes
  | Category {-# UNPACK #-} !Word64
  | CategoryDescription {-# UNPACK #-} !Bytes
  | ClientReputationScore {-# UNPACK #-} !Word64
  | ClientReputationLevel {-# UNPACK #-} !Bytes
  | ClientReputationAction {-# UNPACK #-} !Bytes
  | CountWeb {-# UNPACK #-} !Word64
  | DestinationCountry {-# UNPACK #-} !Bytes
  | DestinationInterface {-# UNPACK #-} !Bytes
  | DestinationInterfaceRole {-# UNPACK #-} !Bytes
  | DestinationInternetService {-# UNPACK #-} !Bytes
  | DestinationIp {-# UNPACK #-} !IP
  | DestinationPort {-# UNPACK #-} !Word16
  | DhcpMessage {-# UNPACK #-} !Bytes
  | Direction {-# UNPACK #-} !Bytes
  | Duration {-# UNPACK #-} !Word64
  | Error {-# UNPACK #-} !Bytes
  | EventTime {-# UNPACK #-} !Word64
  | EventType {-# UNPACK #-} !Bytes
  | Hostname {-# UNPACK #-} !Bytes
  | Interface {-# UNPACK #-} !Bytes
  | Ip {-# UNPACK #-} !IP
  | LanIn {-# UNPACK #-} !Word64
  | LanOut {-# UNPACK #-} !Word64
  | Lease {-# UNPACK #-} !Word64
  | Level {-# UNPACK #-} !Bytes
  | LogDescription {-# UNPACK #-} !Bytes
  | Mac {-# UNPACK #-} !Net.Types.Mac
  | Message {-# UNPACK #-} !Bytes
  | Method {-# UNPACK #-} !Bytes
  | OsName {-# UNPACK #-} !Bytes
  | PolicyId {-# UNPACK #-} !Word64
  | PolicyType {-# UNPACK #-} !Bytes
  | PolicyUuid {-# UNPACK #-} !Word128
  | Profile {-# UNPACK #-} !Bytes
  | Protocol {-# UNPACK #-} !Word8 -- ^ IANA Internet Protocol Number
  | ReceivedBytes {-# UNPACK #-} !Word64
  | ReceivedDelta {-# UNPACK #-} !Word64
  | ReceivedPackets {-# UNPACK #-} !Word64
  | ReferralUrl {-# UNPACK #-} !Bytes
  | RequestType {-# UNPACK #-} !Bytes
  | SentBytes {-# UNPACK #-} !Word64
  | SentDelta {-# UNPACK #-} !Word64
  | SentPackets {-# UNPACK #-} !Word64
  | Service {-# UNPACK #-} !Bytes
  | SessionId {-# UNPACK #-} !Word64
  | SourceCountry {-# UNPACK #-} !Bytes
  | SourceHardwareVendor {-# UNPACK #-} !Bytes
  | SourceInterface {-# UNPACK #-} !Bytes
  | SourceInterfaceRole {-# UNPACK #-} !Bytes
  | SourceIp {-# UNPACK #-} !IP
  | SourceMac {-# UNPACK #-} !Net.Types.Mac
  | SourceName {-# UNPACK #-} !Bytes
  | SourcePort {-# UNPACK #-} !Word16
  | SourceServer {-# UNPACK #-} !Word64
  | SourceSoftwareVersion {-# UNPACK #-} !Bytes
  | TimeZone {-# UNPACK #-} !Int -- ^ Offset from UTC in minutes
  | TranslatedNone -- ^ When @trandisp@ is @noop@
  | TranslatedSource {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | TranslatedDestination {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | UtmAction {-# UNPACK #-} !Bytes
  | Url {-# UNPACK #-} !Bytes
  | User {-# UNPACK #-} !Bytes
  | VirtualDomain {-# UNPACK #-} !Bytes
  | VirtualWanLinkId {-# UNPACK #-} !Word64
  | WanIn {-# UNPACK #-} !Word64
  | WanOut {-# UNPACK #-} !Word64

decode :: Bytes -> Either DecodeException Log
decode b = case P.parseBytes fullParser b of
  P.Failure e -> Left e
  P.Success (P.Slice _ _ x) -> Right x

fullParser :: Parser DecodeException s Log
fullParser = do
  -- If the caret-surrounded syslog priority is present, ignore it.
  Latin.trySatisfy (=='<') >>= \case
    True -> do
      Latin.skipDigits1 InvalidSyslogPriority
      Latin.char InvalidSyslogPriority '>'
    False -> pure ()
  -- Skip any leading space or any space after the syslog priority.
  Latin.skipChar ' '
  Latin.char5 ExpectedDate 'd' 'a' 't' 'e' '='
  Latin.skipTrailedBy InvalidDate ' '
  Latin.char5 ExpectedTime 't' 'i' 'm' 'e' '='
  Latin.skipTrailedBy InvalidTime ' '
  Latin.char8 ExpectedDeviceName 'd' 'e' 'v' 'n' 'a' 'm' 'e' '='
  deviceName <- asciiTextField InvalidDeviceName
  Latin.char7 ExpectedDeviceId ' ' 'd' 'e' 'v' 'i' 'd' '='
  deviceId <- asciiTextField InvalidDeviceId
  Latin.char7 ExpectedLogId ' ' 'l' 'o' 'g' 'i' 'd' '='
  logId <- asciiTextField InvalidLogId
  Latin.char6 ExpectedType ' ' 't' 'y' 'p' 'e' '='
  type_ <- asciiTextField InvalidType
  Latin.char9 ExpectedSubtype ' ' 's' 'u' 'b' 't' 'y' 'p' 'e' '='
  subtype <- asciiTextField InvalidSubtype
  fields <- fieldsParser =<< P.effect Builder.new
  -- let date = error "huantoehutnahoen"
  -- let time = error "huantoehutnahoen"
  pure Log
    { deviceName, deviceId, logId, type_, subtype
    , fields
    }

fieldsParser ::
     Builder s Field
  -> Parser DecodeException s (Chunks Field)
fieldsParser !b0 = P.isEndOfInput >>= \case
  True -> P.effect (Builder.freeze b0)
  False -> do
    Latin.char ExpectedSpace ' '
    name <- P.takeTrailedBy IncompleteKey (c2w '=')
    !fld <- afterEquals name
    b1 <- P.effect (Builder.push fld b0)
    fieldsParser b1

afterEquals :: Bytes -> Parser DecodeException s Field
afterEquals !b = case fromIntegral @Int @Word len of
  2 -> case G.hashString2 arr off of
    G.H_vd -> case zequal2 arr off 'v' 'd' of
      0# -> do
        val <- asciiTextField InvalidVirtualDomain
        pure (VirtualDomain val)
      _ -> P.fail UnknownField2
    G.H_ip -> case zequal2 arr off 'i' 'p' of
      0# -> do
        val <- IP.parserUtf8Bytes InvalidIp
        pure (Ip val)
      _ -> P.fail UnknownField2
    G.H_tz -> case zequal2 arr off 't' 'z' of
      0# -> do
        Latin.char InvalidTimeZone '"'
        val <- Latin.decSignedInt InvalidTimeZone
        Latin.char InvalidTimeZone '"'
        pure (TimeZone val)
      _ -> P.fail UnknownField2
    _ -> P.fail UnknownField2
  3 -> case G.hashString3 arr off of
    G.H_mac -> case zequal3 arr off 'm' 'a' 'c' of
      0# -> do
        _ <- asciiTextField InvalidMac
        -- TODO: Fix this
        pure (Mac (Net.Types.Mac 0))
      _ -> P.fail UnknownField3
    G.H_app -> case zequal3 arr off 'a' 'p' 'p' of
      0# -> do
        val <- asciiTextField InvalidApp
        pure (App val)
      _ -> P.fail UnknownField3
    G.H_url -> case zequal3 arr off 'u' 'r' 'l' of
      0# -> do
        val <- asciiTextField InvalidUrl
        pure (Url val)
      _ -> P.fail UnknownField3
    G.H_msg -> case zequal3 arr off 'm' 's' 'g' of
      0# -> do
        val <- asciiTextField InvalidMessage
        pure (Message val)
      _ -> P.fail UnknownField3
    G.H_cat -> case zequal3 arr off 'c' 'a' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidCategory
        pure (Category val)
      _ -> P.fail UnknownField3
    _ -> P.fail UnknownField3
  4 -> case zequal4 arr off 'u' 's' 'e' 'r' of
    0# -> do
      val <- asciiTextField InvalidUser
      pure (User val)
    _ -> P.fail UnknownField4
  5 -> case G.hashString5 arr off of
    G.H_vwlid -> case zequal5 arr off 'v' 'w' 'l' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidVirtualWanLinkId
        pure (VirtualWanLinkId val)
      _ -> P.fail UnknownField5
    G.H_appid -> case zequal5 arr off 'a' 'p' 'p' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidApplicationId
        pure (ApplicationId val)
      _ -> P.fail UnknownField5
    G.H_lease -> case zequal5 arr off 'l' 'e' 'a' 's' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidLease
        pure (Lease val)
      _ -> P.fail UnknownField5
    G.H_wanin -> case zequal5 arr off 'w' 'a' 'n' 'i' 'n' of
      0# -> do
        val <- Latin.decWord64 InvalidWanIn
        pure (WanIn val)
      _ -> P.fail UnknownField5
    G.H_lanin -> case zequal5 arr off 'l' 'a' 'n' 'i' 'n' of
      0# -> do
        val <- Latin.decWord64 InvalidLanIn
        pure (LanIn val)
      _ -> P.fail UnknownField5
    G.H_srcip -> case zequal5 arr off 's' 'r' 'c' 'i' 'p' of
      0# -> do
        val <- IP.parserUtf8Bytes InvalidSourceIp
        pure (SourceIp val)
      _ -> P.fail UnknownField5
    G.H_dstip -> case zequal5 arr off 'd' 's' 't' 'i' 'p' of
      0# -> do
        val <- IP.parserUtf8Bytes InvalidDestinationIp
        pure (DestinationIp val)
      _ -> P.fail UnknownField5
    G.H_level -> case zequal5 arr off 'l' 'e' 'v' 'e' 'l' of
      0# -> do
        val <- asciiTextField InvalidLevel
        pure (Level val)
      _ -> P.fail UnknownField5
    G.H_error -> case zequal5 arr off 'e' 'r' 'r' 'o' 'r' of
      0# -> do
        val <- asciiTextField InvalidError
        pure (Level val)
      _ -> P.fail UnknownField5
    G.H_proto -> case zequal5 arr off 'p' 'r' 'o' 't' 'o' of
      0# -> do
        val <- Latin.decWord8 InvalidProtocol
        pure (Protocol val)
      _ -> P.fail UnknownField5
    _ -> P.fail UnknownField5
  6 -> case G.hashString6 arr off of
    G.H_srcmac -> case zequal6 arr off 's' 'r' 'c' 'm' 'a' 'c' of
      0# -> do
        _ <- asciiTextField InvalidSourceMac
        -- TODO: Fix this
        pure (SourceMac (Net.Types.Mac 0))
      _ -> P.fail UnknownField6
    G.H_appcat -> case zequal6 arr off 'a' 'p' 'p' 'c' 'a' 't' of
      0# -> do
        val <- asciiTextField InvalidApplicationCategory
        pure (ApplicationCategory val)
      _ -> P.fail UnknownField6
    G.H_action -> case zequal6 arr off 'a' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidAction
        pure (Action val)
      _ -> P.fail UnknownField6
    G.H_method -> case zequal6 arr off 'm' 'e' 't' 'h' 'o' 'd' of
      0# -> do
        val <- asciiTextField InvalidMethod
        pure (Method val)
      _ -> P.fail UnknownField6
    G.H_wanout -> case zequal6 arr off 'w' 'a' 'n' 'o' 'u' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidWanOut
        pure (WanOut val)
      _ -> P.fail UnknownField6
    G.H_lanout -> case zequal6 arr off 'l' 'a' 'n' 'o' 'u' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidLanOut
        pure (LanOut val)
      _ -> P.fail UnknownField6
    G.H_osname -> case zequal6 arr off 'o' 's' 'n' 'a' 'm' 'e' of
      0# -> do
        val <- asciiTextField InvalidOsName
        pure (OsName val)
      _ -> P.fail UnknownField6
    _ -> P.fail UnknownField6
  7 -> case G.hashString7 arr off of
    G.H_poluuid -> case zequal7 arr off 'p' 'o' 'l' 'u' 'u' 'i' 'd' of
      0# -> do
        -- TODO: this is totally wrong
        _ <- asciiTextField InvalidPolicyUuid
        pure (PolicyUuid 0)
      _ -> P.fail UnknownField7
    G.H_srcname -> case zequal7 arr off 's' 'r' 'c' 'n' 'a' 'm' 'e' of
      0# -> do
        val <- asciiTextField InvalidSourceName
        pure (SourceName val)
      _ -> P.fail UnknownField7
    G.H_applist -> case zequal7 arr off 'a' 'p' 'p' 'l' 'i' 's' 't' of
      0# -> do
        val <- asciiTextField InvalidApplicationList
        pure (ApplicationList val)
      _ -> P.fail UnknownField7
    G.H_apprisk -> case zequal7 arr off 'a' 'p' 'p' 'r' 'i' 's' 'k' of
      0# -> do
        val <- asciiTextField InvalidApplicationRisk
        pure (ApplicationRisk val)
      _ -> P.fail UnknownField7
    G.H_logdesc -> case zequal7 arr off 'l' 'o' 'g' 'd' 'e' 's' 'c' of
      0# -> do
        val <- asciiTextField InvalidLogDescription
        pure (LogDescription val)
      _ -> P.fail UnknownField7
    G.H_reqtype -> case zequal7 arr off 'r' 'e' 'q' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidRequestType
        pure (RequestType val)
      _ -> P.fail UnknownField7
    G.H_crscore -> case zequal7 arr off 'c' 'r' 's' 'c' 'o' 'r' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidClientReputationScore
        pure (ClientReputationScore val)
      _ -> P.fail UnknownField7
    G.H_crlevel -> case zequal7 arr off 'c' 'r' 'l' 'e' 'v' 'e' 'l' of
      0# -> do
        val <- asciiTextField InvalidClientReputationLevel
        pure (ClientReputationLevel val)
      _ -> P.fail UnknownField7
    G.H_catdesc -> case zequal7 arr off 'c' 'a' 't' 'd' 'e' 's' 'c' of
      0# -> do
        val <- asciiTextField InvalidCategoryDescription
        pure (CategoryDescription val)
      _ -> P.fail UnknownField7
    G.H_srcintf -> case zequal7 arr off 's' 'r' 'c' 'i' 'n' 't' 'f' of
      0# -> do
        val <- asciiTextField InvalidSourceInterface
        pure (SourceInterface val)
      _ -> P.fail UnknownField7
    G.H_dstintf -> case zequal7 arr off 'd' 's' 't' 'i' 'n' 't' 'f' of
      0# -> do
        val <- asciiTextField InvalidDestinationInterface
        pure (DestinationInterface val)
      _ -> P.fail UnknownField7
    G.H_srcport -> case zequal7 arr off 's' 'r' 'c' 'p' 'o' 'r' 't' of
      0# -> do
        val <- Latin.decWord16 InvalidSourcePort
        pure (SourcePort val)
      _ -> P.fail UnknownField7
    G.H_dstport -> case zequal7 arr off 'd' 's' 't' 'p' 'o' 'r' 't' of
      0# -> do
        val <- Latin.decWord16 InvalidDestinationPort
        pure (DestinationPort val)
      _ -> P.fail UnknownField7
    G.H_service -> case zequal7 arr off 's' 'e' 'r' 'v' 'i' 'c' 'e' of
      0# -> do
        val <- asciiTextField InvalidService
        pure (Service val)
      _ -> P.fail UnknownField7
    G.H_sentpkt -> case zequal7 arr off 's' 'e' 'n' 't' 'p' 'k' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidSentPackets
        pure (SentPackets val)
      _ -> P.fail UnknownField7
    G.H_rcvdpkt -> case zequal7 arr off 'r' 'c' 'v' 'd' 'p' 'k' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidReceivedPackets
        pure (ReceivedPackets val)
      _ -> P.fail UnknownField7
    G.H_profile -> case zequal7 arr off 'p' 'r' 'o' 'f' 'i' 'l' 'e' of
      0# -> do
        val <- asciiTextField InvalidProfile
        pure (Profile val)
      _ -> P.fail UnknownField7
    _ -> P.fail UnknownField7
  8 -> case G.hashString8 arr off of
    G.H_dhcp_msg -> case zequal8 arr off 'd' 'h' 'c' 'p' '_' 'm' 's' 'g' of
      0# -> do
        val <- asciiTextField InvalidDhcpMessage
        pure (DhcpMessage val)
      _ -> P.fail UnknownField8
    G.H_hostname -> case zequal8 arr off 'h' 'o' 's' 't' 'n' 'a' 'm' 'e' of
      0# -> do
        val <- asciiTextField InvalidHostname
        pure (Hostname val)
      _ -> P.fail UnknownField8
    G.H_craction -> case zequal8 arr off 'c' 'r' 'a' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidClientReputationAction
        pure (ClientReputationAction val)
      _ -> P.fail UnknownField8
    G.H_policyid -> case zequal8 arr off 'p' 'o' 'l' 'i' 'c' 'y' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidPolicyId
        pure (PolicyId val)
      _ -> P.fail UnknownField8
    G.H_duration -> case zequal8 arr off 'd' 'u' 'r' 'a' 't' 'i' 'o' 'n' of
      0# -> do
        val <- Latin.decWord64 InvalidDuration
        pure (Duration val)
      _ -> P.fail UnknownField8
    G.H_sentbyte -> case zequal8 arr off 's' 'e' 'n' 't' 'b' 'y' 't' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidSentBytes
        pure (SentBytes val)
      _ -> P.fail UnknownField8
    G.H_rcvdbyte -> case zequal8 arr off 'r' 'c' 'v' 'd' 'b' 'y' 't' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidReceivedBytes
        pure (ReceivedBytes val)
      _ -> P.fail UnknownField8
    G.H_countweb -> case zequal8 arr off 'c' 'o' 'u' 'n' 't' 'w' 'e' 'b' of
      0# -> do
        val <- Latin.decWord64 InvalidCountWeb
        pure (CountWeb val)
      _ -> P.fail UnknownField8
    G.H_trandisp -> case zequal8 arr off 't' 'r' 'a' 'n' 'd' 'i' 's' 'p' of
      0# -> Latin.any InvalidTranslationDisposition >>= \case
        '"' -> Latin.any InvalidTranslationDisposition >>= \case
          'n' -> do
            Latin.char4 InvalidTranslationDisposition 'o' 'o' 'p' '"'
            pure TranslatedNone
          'd' -> do
            Latin.char5 InvalidTranslationDisposition 'n' 'a' 't' '"' ' '
            dnatFinish
          's' -> do
            Latin.char5 InvalidTranslationDisposition 'n' 'a' 't' '"' ' '
            snatFinish
          _ -> P.fail InvalidTranslationDisposition
        'n' -> do
          Latin.char3 InvalidTranslationDisposition 'o' 'o' 'p'
          pure TranslatedNone
        'd' -> do
          Latin.char4 InvalidTranslationDisposition 'n' 'a' 't' ' '
          dnatFinish
        's' -> do
          Latin.char4 InvalidTranslationDisposition 'n' 'a' 't' ' '
          snatFinish
        _ -> P.fail InvalidTranslationDisposition
      _ -> P.fail UnknownField8
    _ -> P.fail UnknownField8
  9 -> case G.hashString9 arr off of
    G.H_srcserver -> case zequal9 arr off 's' 'r' 'c' 's' 'e' 'r' 'v' 'e' 'r' of
      0# -> do
        val <- Latin.decWord64 InvalidSourceServer
        pure (SourceServer val)
      _ -> P.fail UnknownField9
    G.H_interface -> case zequal9 arr off 'i' 'n' 't' 'e' 'r' 'f' 'a' 'c' 'e' of
      0# -> do
        val <- asciiTextField InvalidInterface
        pure (Interface val)
      _ -> P.fail UnknownField9
    G.H_sessionid -> case zequal9 arr off 's' 'e' 's' 's' 'i' 'o' 'n' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidSessionId
        pure (SessionId val)
      _ -> P.fail UnknownField9
    G.H_eventtype -> case zequal9 arr off 'e' 'v' 'e' 'n' 't' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidEventType
        pure (EventType val)
      _ -> P.fail UnknownField9
    G.H_eventtime -> case zequal9 arr off 'e' 'v' 'e' 'n' 't' 't' 'i' 'm' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidEventTime
        pure (EventTime val)
      _ -> P.fail UnknownField9
    G.H_utmaction -> case zequal9 arr off 'u' 't' 'm' 'a' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidUtmAction
        pure (UtmAction val)
      _ -> P.fail UnknownField9
    G.H_direction -> case zequal9 arr off 'd' 'i' 'r' 'e' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidDirection
        pure (Direction val)
      _ -> P.fail UnknownField9
    G.H_sentdelta -> case zequal9 arr off 's' 'e' 'n' 't' 'd' 'e' 'l' 't' 'a' of
      0# -> do
        val <- Latin.decWord64 InvalidSentDelta
        pure (SentDelta val)
      _ -> P.fail UnknownField9
    G.H_rcvddelta -> case zequal9 arr off 'r' 'c' 'v' 'd' 'd' 'e' 'l' 't' 'a' of
      0# -> do
        val <- Latin.decWord64 InvalidReceivedDelta
        pure (ReceivedDelta val)
      _ -> P.fail UnknownField9
    _ -> P.fail UnknownField9
  10 -> case G.hashString10 arr off of
    G.H_srccountry -> case zequal10 arr off 's' 'r' 'c' 'c' 'o' 'u' 'n' 't' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidSourceCountry
        pure (SourceCountry val)
      _ -> P.fail UnknownField10
    G.H_dstcountry -> case zequal10 arr off 'd' 's' 't' 'c' 'o' 'u' 'n' 't' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidDestinationCountry
        pure (DestinationCountry val)
      _ -> P.fail UnknownField10
    G.H_policytype -> case zequal10 arr off 'p' 'o' 'l' 'i' 'c' 'y' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidPolicyType
        pure (PolicyType val)
      _ -> P.fail UnknownField10
    G.H_dstinetsvc -> case zequal10 arr off 'd' 's' 't' 'i' 'n' 'e' 't' 's' 'v' 'c' of
      0# -> do
        val <- asciiTextField InvalidDestinationInternetService
        pure (DestinationInternetService val)
      _ -> P.fail UnknownField10
    _ -> P.fail UnknownField10
  11 -> case G.hashString11 arr off of
    G.H_referralurl -> case zequal11 arr off 'r' 'e' 'f' 'e' 'r' 'r' 'a' 'l' 'u' 'r' 'l' of
      0# -> do
        val <- asciiTextField InvalidReferralUrl
        pure (ReferralUrl val)
      _ -> P.fail UnknownField11
    G.H_dstintfrole -> case zequal11 arr off 'd' 's' 't' 'i' 'n' 't' 'f' 'r' 'o' 'l' 'e' of
      0# -> do
        val <- asciiTextField InvalidDestinationInterfaceRole
        pure (DestinationInterfaceRole val)
      _ -> P.fail UnknownField11
    G.H_srcintfrole -> case zequal11 arr off 's' 'r' 'c' 'i' 'n' 't' 'f' 'r' 'o' 'l' 'e' of
      0# -> do
        val <- asciiTextField InvalidSourceInterfaceRole
        pure (SourceInterfaceRole val)
      _ -> P.fail UnknownField11
    G.H_srchwvendor -> case zequal11 arr off 's' 'r' 'c' 'h' 'w' 'v' 'e' 'n' 'd' 'o' 'r' of
      0# -> do
        val <- asciiTextField InvalidSourceHardwareVendor
        pure (SourceHardwareVendor val)
      _ -> P.fail UnknownField11
    _ -> P.fail UnknownField11
  12 -> case G.hashString12 arr off of
    G.H_srcswversion -> case zequal12 arr off 's' 'r' 'c' 's' 'w' 'v' 'e' 'r' 's' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidSourceSoftwareVersion
        pure (SourceSoftwareVersion val)
      _ -> P.fail UnknownField12
    G.H_mastersrcmac -> case zequal12 arr off 'm' 'a' 's' 't' 'e' 'r' 's' 'r' 'c' 'm' 'a' 'c' of
      0# -> do
        -- TODO: Fix this
        _ <- asciiTextField InvalidMac
        pure (Mac (Net.Types.Mac 0))
      _ -> P.fail UnknownField12
    _ -> P.fail UnknownField12
  _ -> P.fail UnknownField
  where
  !(Bytes arr off len) = b

dnatFinish :: Parser DecodeException s Field
dnatFinish = do
  Latin.char7 InvalidTranslationDisposition 't' 'r' 'a' 'n' 'i' 'p' '='
  !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
  Latin.char10 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 'p' 'o' 'r' 't' '='
  !port <- Latin.decWord16 InvalidTranslationPort
  pure (TranslatedDestination ip port)

snatFinish :: Parser DecodeException s Field
snatFinish = do
  Latin.char8 InvalidTranslationDisposition 't' 'r' 'a' 'n' 's' 'i' 'p' '='
  !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
  Latin.char11 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 's' 'p' 'o' 'r' 't' '='
  !port <- Latin.decWord16 InvalidTranslationPort
  pure (TranslatedSource ip port)

-- Field is optionally surrounded by quotes. This does not
-- consume a trailing space.
asciiTextField :: e -> Parser e s Bytes
asciiTextField e = Latin.trySatisfy (== '"') >>= \case
  True -> P.takeTrailedBy e (c2w '"')
  False -> P.takeWhile (\w -> w /= c2w ' ')

zequal2 :: ByteArray -> Int -> Char -> Char -> Int#
zequal2 (ByteArray arr) (I# off) (C# a) (C# b) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b

zequal3 :: ByteArray -> Int -> Char -> Char -> Char -> Int#
zequal3 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c

zequal4 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Int#
zequal4 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d

zequal5 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Int#
zequal5 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e

zequal6 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal6 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f

zequal7 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal7 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 6#)) g

zequal8 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal8 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 6#)) g
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 7#)) h

zequal9 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal9 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 6#)) g
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 7#)) h
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 8#)) i

zequal10 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal10 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 6#)) g
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 7#)) h
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 8#)) i
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 9#)) j

zequal11 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal11 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) (C# k) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 6#)) g
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 7#)) h
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 8#)) i
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 9#)) j
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 10#)) k

zequal12 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal12 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) (C# k) (C# l) =
  zeqChar# (indexCharArray# arr off) a
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 1#)) b
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 2#)) c
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 3#)) d
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 4#)) e
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 5#)) f
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 6#)) g
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 7#)) h
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 8#)) i
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 9#)) j
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 10#)) k
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 11#)) l

c2w :: Char -> Word8
c2w = fromIntegral . ord

-- Returns zero when the characters are equal
zeqChar# :: Char# -> Char# -> Int#
zeqChar# c1 c2 = xorI# (ord# c1) (ord# c2)
