{-# language BangPatterns #-}
{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}
{-# language PatternSynonyms #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}
{-# language ViewPatterns #-}

module Fortios.Syslog.Unsafe
  ( Log(..)
  , Field(..)
  , DecodeException
  , afterEquals
  , fullParser
  , decode
  , decodeSemistructured
  ) where

import Chronos (Date,TimeOfDay,Datetime(..))
import Chronos (Month(Month),DayOfMonth(DayOfMonth),Year(Year))
import Control.Monad (when)
import Control.Monad.ST.Run (runIntByteArrayST)
import Data.Builder.ST (Builder)
import Data.Bytes.Parser (Parser)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Char (ord)
import Data.Chunks (Chunks)
import Data.Primitive (ByteArray(..))
import Data.WideWord (Word128,Word256)
import Data.Word (Word8,Word16,Word32,Word64)
import GHC.Exts (Int#,(+#),Ptr(Ptr),xorWord32#,xor64#,word8ToWord#,xor#,word32ToWord#,or#)
import GHC.Exts (word16ToWord#)
import GHC.Exts (word64ToWord#)
import GHC.Exts (indexWord8OffAddrAsWord16#)
import GHC.Exts (indexWord8ArrayAsWord16#)
import GHC.Exts (Int(I#),Char(C#),Char#,indexCharArray#,ord#,xorI#,orI#)
import Net.Types (IPv4,IP)
import Data.Primitive.ByteArray.LittleEndian (indexUnalignedByteArray)
import GHC.Exts (Word#, Addr#)
import GHC.Exts (indexWord8ArrayAsWord32#, indexWord8OffAddrAsWord32# )
import GHC.Exts (indexWord8ArrayAsWord64#, indexWord8OffAddrAsWord64# )
import GHC.Exts (indexWord8OffAddr#, indexWord8Array#)

import qualified Chronos
import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as P
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe
import qualified Data.Bytes.Types
import qualified Data.Primitive as PM
import qualified Fortios.Generated as G
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4
import qualified Net.Mac as Mac
import qualified Net.Types
import qualified UUID

data Log = Log
  { date :: {-# UNPACK #-} !Date
  , time :: {-# UNPACK #-} !TimeOfDay
  , deviceName :: {-# UNPACK #-} !Bytes
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
  | ExpectedId
  | ExpectedLogVer
  | ExpectedEventTime
  | ExpectedFctsn
  | ExpectedFieldsAfterDeviceId
  | ExpectedITime
  | ExpectedLeadingChar
  | ExpectedLogId
  | ExpectedQuoteAfterDate
  | ExpectedQuoteAfterTime
  | ExpectedSlotId
  | ExpectedSpace
  | ExpectedSpaceAfterDeviceId
  | ExpectedSubtype
  | ExpectedTime
  | ExpectedTimestamp
  | ExpectedType
  | ExpectedTz
  | ExpectedTzOrDeviceName
  | ExpectedVd
  | IncompleteKey
  | InvalidAction
  | InvalidAlert
  | InvalidAnalyticsChecksum
  | InvalidApp
  | InvalidApplicationAction
  | InvalidApplicationCategory
  | InvalidApplicationId
  | InvalidApplicationList
  | InvalidApplicationRisk
  | InvalidAttack
  | InvalidAttackId
  | InvalidAuthServer
  | InvalidCategory
  | InvalidCategoryDescription
  | InvalidCdrContent
  | InvalidCentralNatId
  | InvalidChecksum
  | InvalidClientReputationAction
  | InvalidClientReputationLevel
  | InvalidClientReputationScore
  | InvalidContentDisarmed
  | InvalidCountApplication
  | InvalidCountIps
  | InvalidCountWeb
  | InvalidDate
  | InvalidDescription
  | InvalidDestinationCountry
  | InvalidDestinationDeviceCategory
  | InvalidLogVersion
  | InvalidDestinationDeviceType
  | InvalidDestinationHost
  | InvalidDestinationInterface
  | InvalidDestinationInterfaceRole
  | InvalidDestinationInternetService
  | InvalidDestinationIp
  | InvalidDestinationMac
  | InvalidDestinationOsName
  | InvalidDestinationOsVerson
  | InvalidDestinationPort
  | InvalidDestinationRegion
  | InvalidDestinationServer
  | InvalidDestinationUuid
  | InvalidDeviceCategory
  | InvalidDeviceId
  | InvalidDeviceName
  | InvalidDeviceType
  | InvalidDhcpMessage
  | InvalidDirection
  | InvalidDuration
  | InvalidError
  | InvalidEventTime
  | InvalidEventType
  | InvalidFilename
  | InvalidGroup
  | InvalidHealthCheck
  | InvalidHostname
  | InvalidIncidentSerialNumber
  | InvalidInterface
  | InvalidIp
  | InvalidLanIn
  | InvalidLanOut
  | InvalidLease
  | InvalidLevel
  | InvalidLocalPort
  | InvalidLogDescription
  | InvalidLogId
  | InvalidMac
  | InvalidMasterDestinationMac
  | InvalidMasterSourceMac
  | InvalidMember
  | InvalidMessage
  | InvalidMethod
  | InvalidNewValue
  | InvalidNextStatistics
  | InvalidOldValue
  | InvalidOsName
  | InvalidOsVersion
  | InvalidPolicyId
  | InvalidPolicyName
  | InvalidPolicyType
  | InvalidPolicyUuid
  | InvalidPriority
  | InvalidProfile
  | InvalidProfileType
  | InvalidProtocol
  | InvalidQueryClass
  | InvalidQueryName
  | InvalidQueryType
  | InvalidQueryTypeValue
  | InvalidReason
  | InvalidReceivedBytes
  | InvalidReceivedDelta
  | InvalidReceivedPackets
  | InvalidReference
  | InvalidReferralUrl
  | InvalidRemoteIp
  | InvalidRemotePort
  | InvalidRequestType
  | InvalidSentBytes
  | InvalidSentDelta
  | InvalidSentPackets
  | InvalidService
  | InvalidSessionId
  | InvalidSeverity
  | InvalidSourceCountry
  | InvalidSourceFamily
  | InvalidSourceHardwareVendor
  | InvalidSourceInterface
  | InvalidSourceInterfaceRole
  | InvalidSourceIp
  | InvalidSourceMac
  | InvalidSourceName
  | InvalidSourcePort
  | InvalidSourceRegion
  | InvalidSourceServer
  | InvalidSourceSoftwareVersion
  | InvalidSourceUuid
  | InvalidSslAction
  | InvalidSslCertificateCommonName
  | InvalidSslCertificateIssuer
  | InvalidSubtype
  | InvalidSyslogPriority
  | InvalidTime
  | InvalidTimeZone
  | InvalidTransactionId
  | InvalidTranslationDisposition
  | InvalidTranslationIp
  | InvalidTranslationPort
  | InvalidTunnelId
  | InvalidTunnelIp
  | InvalidTunnelType
  | InvalidType
  | InvalidUnauthenticatedUser
  | InvalidUnauthenticatedUserSource
  | InvalidUnknownField
  | InvalidUrl
  | InvalidUrlFilterIndex
  | InvalidUrlFilterList
  | InvalidUrlSource
  | InvalidUser
  | InvalidUtmAction
  | InvalidVirtualDomain
  | InvalidVirtualWanLinkId
  | InvalidVirtualWanLinkName
  | InvalidVirtualWanLinkQuality
  | InvalidVpn
  | InvalidVpnType
  | InvalidWanIn
  | InvalidWanOut
  deriving (Show)

data Field
  = Action {-# UNPACK #-} !Bytes
  | Alert {-# UNPACK #-} !Word64
  | AnalyticsChecksum {-# UNPACK #-} !Word256
  | App {-# UNPACK #-} !Bytes
  | ApplicationAction {-# UNPACK #-} !Bytes
  | ApplicationCategory {-# UNPACK #-} !Bytes
  | ApplicationId {-# UNPACK #-} !Word64
    -- ^ ID of the application.
  | ApplicationList {-# UNPACK #-} !Bytes
  | ApplicationRisk {-# UNPACK #-} !Bytes
  | Attack {-# UNPACK #-} !Bytes
  | AttackId {-# UNPACK #-} !Word64
    -- ^ Risk level of the application.
  | AuthServer {-# UNPACK #-} !Bytes
  | Category {-# UNPACK #-} !Word64
  | CategoryDescription {-# UNPACK #-} !Bytes
  | CentralNatId {-# UNPACK #-} !Word64
  | CdrContent {-# UNPACK #-} !Bytes
  | Checksum {-# UNPACK #-} !Word32
  | ContentDisarmed {-# UNPACK #-} !Bytes
  | CountIps {-# UNPACK #-} !Word64
    -- ^ Number of the IPS logs associated with the session
  | ClientReputationScore {-# UNPACK #-} !Word64
  | ClientReputationLevel {-# UNPACK #-} !Bytes
  | ClientReputationAction {-# UNPACK #-} !Bytes
  | CountApplication {-# UNPACK #-} !Word64
    -- ^ Number of App Ctrl logs associated with the session.
  | CountWeb {-# UNPACK #-} !Word64
  | Date !Chronos.Date
  | Description {-# UNPACK #-} !Bytes
  | DestinationCountry {-# UNPACK #-} !Bytes
  | DestinationDeviceCategory {-# UNPACK #-} !Bytes
  | DestinationDeviceType {-# UNPACK #-} !Bytes
  | DestinationHost {-# UNPACK #-} !Bytes
  | DestinationInterface {-# UNPACK #-} !Bytes
  | DestinationInterfaceRole {-# UNPACK #-} !Bytes
  | DestinationInternetService {-# UNPACK #-} !Bytes
  | DestinationIp {-# UNPACK #-} !IP
  | DestinationMac {-# UNPACK #-} !Net.Types.Mac
  | DestinationOsName {-# UNPACK #-} !Bytes
  | DestinationOsVersion {-# UNPACK #-} !Bytes
  | DestinationPort {-# UNPACK #-} !Word16
  | DestinationRegion {-# UNPACK #-} !Bytes
  | DestinationServer {-# UNPACK #-} !Word64
  | DestinationUuid {-# UNPACK #-} !Word128
  | DeviceCategory {-# UNPACK #-} !Bytes
  | DeviceId {-# UNPACK #-} !Bytes
  | DeviceType {-# UNPACK #-} !Bytes
  | DhcpMessage {-# UNPACK #-} !Bytes
  | Direction {-# UNPACK #-} !Bytes
  | Duration {-# UNPACK #-} !Word64
  | Error {-# UNPACK #-} !Bytes
  | EventTime {-# UNPACK #-} !Word64
  | EventType {-# UNPACK #-} !Bytes
  | Group {-# UNPACK #-} !Bytes
  | Filename {-# UNPACK #-} !Bytes
  | HealthCheck {-# UNPACK #-} !Bytes
  | Hostname {-# UNPACK #-} !Bytes
  | IncidentSerialNumber {-# UNPACK #-} !Word64
  | Interface {-# UNPACK #-} !Bytes
  | Ip {-# UNPACK #-} !IP
  | LanIn {-# UNPACK #-} !Word64
  | LanOut {-# UNPACK #-} !Word64
  | Lease {-# UNPACK #-} !Word64
  | Level {-# UNPACK #-} !Bytes
  | LocalPort {-# UNPACK #-} !Word16
  | LogDescription {-# UNPACK #-} !Bytes
  | LogId {-# UNPACK #-} !Bytes
  | LogVersion {-# UNPACK #-} !Word64
  | Mac {-# UNPACK #-} !Net.Types.Mac
  | MasterDestinationMac {-# UNPACK #-} !Net.Types.Mac
  | MasterSourceMac {-# UNPACK #-} !Net.Types.Mac
  | Member {-# UNPACK #-} !Bytes
  | Message {-# UNPACK #-} !Bytes
  | Method {-# UNPACK #-} !Bytes
  | NextStatistics {-# UNPACK #-} !Word64
  | NewValue {-# UNPACK #-} !Bytes
  | OldValue {-# UNPACK #-} !Bytes
  | OsName {-# UNPACK #-} !Bytes
  | OsVersion {-# UNPACK #-} !Bytes
  | PolicyId {-# UNPACK #-} !Word64
  | PolicyName {-# UNPACK #-} !Bytes
  | PolicyType {-# UNPACK #-} !Bytes
  | PolicyUuid {-# UNPACK #-} !Word128
  | Priority {-# UNPACK #-} !Bytes
  | Profile {-# UNPACK #-} !Bytes
  | ProfileType {-# UNPACK #-} !Bytes
  | Protocol {-# UNPACK #-} !Word8
  | QueryClass {-# UNPACK #-} !Bytes
  | QueryName {-# UNPACK #-} !Bytes
  | QueryType {-# UNPACK #-} !Bytes
  | QueryTypeValue {-# UNPACK #-} !Word64
    -- ^ IANA Internet Protocol Number.
  | Reason {-# UNPACK #-} !Bytes
  | ReceivedBytes {-# UNPACK #-} !Word64
    -- ^ Number of bytes received.
  | ReceivedDelta {-# UNPACK #-} !Word64
  | ReceivedPackets {-# UNPACK #-} !Word64
    -- ^ Number of packets received.
  | Reference {-# UNPACK #-} !Bytes
  | ReferralUrl {-# UNPACK #-} !Bytes
  | RemoteIp {-# UNPACK #-} !IP
  | RemotePort {-# UNPACK #-} !Word16
  | RequestType {-# UNPACK #-} !Bytes
  | SentBytes {-# UNPACK #-} !Word64
    -- ^ Number of bytes sent.
  | SentDelta {-# UNPACK #-} !Word64
  | SentPackets {-# UNPACK #-} !Word64
    -- ^ Number of packets sent.
  | Service {-# UNPACK #-} !Bytes
    -- ^ Name of the service.
  | SessionId {-# UNPACK #-} !Word64
  | Severity {-# UNPACK #-} !Bytes
  | SourceCountry {-# UNPACK #-} !Bytes
  | SourceFamily {-# UNPACK #-} !Bytes
  | SourceHardwareVendor {-# UNPACK #-} !Bytes
  | SourceInterface {-# UNPACK #-} !Bytes
  | SourceInterfaceRole {-# UNPACK #-} !Bytes
  | SourceIp {-# UNPACK #-} !IP
  | SourceMac {-# UNPACK #-} !Net.Types.Mac
  | SourceName {-# UNPACK #-} !Bytes
  | SourcePort {-# UNPACK #-} !Word16
  | SourceRegion {-# UNPACK #-} !Bytes
  | SourceServer {-# UNPACK #-} !Word64
  | SourceSoftwareVersion {-# UNPACK #-} !Bytes
  | SourceUuid {-# UNPACK #-} !Word128
  | SslAction {-# UNPACK #-} !Bytes
  | SslCertificateCommonName {-# UNPACK #-} !Bytes
  | SslCertificateIssuer {-# UNPACK #-} !Bytes
  | Subtype {-# UNPACK #-} !Bytes
  | Time !Chronos.TimeOfDay
  | TimeZone {-# UNPACK #-} !Int -- ^ Offset from UTC in minutes
  | TransactionId {-# UNPACK #-} !Word64 -- ^ Field is named @xid@.
  | TranslatedSource {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | TranslatedDestination {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | TunnelId {-# UNPACK #-} !Word64
  | TunnelIp {-# UNPACK #-} !IP
  | TunnelType {-# UNPACK #-} !Bytes
  | Type {-# UNPACK #-} !Bytes
  | UnauthenticatedUser {-# UNPACK #-} !Bytes
  | UnauthenticatedUserSource {-# UNPACK #-} !Bytes
  | UtmAction {-# UNPACK #-} !Bytes
  | Url {-# UNPACK #-} !Bytes
  | UrlSource {-# UNPACK #-} !Bytes
  | UrlFilterIndex {-# UNPACK #-} !Word64
  | UrlFilterList {-# UNPACK #-} !Bytes
  | User {-# UNPACK #-} !Bytes
  | VirtualDomain {-# UNPACK #-} !Bytes
  | VirtualWanLinkId {-# UNPACK #-} !Word64
  | VirtualWanLinkName {-# UNPACK #-} !Bytes
  | VirtualWanLinkQuality {-# UNPACK #-} !Bytes
  | Vpn {-# UNPACK #-} !Bytes
  | VpnType {-# UNPACK #-} !Bytes
  | WanIn {-# UNPACK #-} !Word64
  | WanOut {-# UNPACK #-} !Word64

decode :: Bytes -> Either DecodeException Log
decode b = case P.parseBytes fullParser b of
  P.Failure e -> Left e
  P.Success (P.Slice _ _ x) -> Right x

decodeSemistructured :: Bytes -> Either DecodeException (Chunks Field)
decodeSemistructured b = case P.parseBytes semistructuredParser b of
  P.Failure e -> Left e
  P.Success (P.Slice _ _ x) -> Right x

finishModeA :: Parser DecodeException s Log
finishModeA = do
  P.cstring ExpectedTimestamp (Ptr "timestamp="#)
  Latin.skipDigits1 ExpectedLogVer
  Latin.char ExpectedLogVer ' '
  Latin.any ExpectedLogVer >>= \case
    't' -> do
      Latin.char3 ExpectedTz 'z' '=' '"'
      _ <- P.takeTrailedBy ExpectedTz 0x22
      Latin.char2 ExpectedDeviceName ' ' 'd'
    'd' -> pure ()
    _ -> P.fail ExpectedTzOrDeviceName
  Latin.char7 ExpectedDeviceName 'e' 'v' 'n' 'a' 'm' 'e' '='
  deviceName <- asciiTextField InvalidDeviceName
  Latin.char5 ExpectedDeviceId ' ' 'd' 'e' 'v' 'i'
  deviceId <- Latin.any ExpectedDeviceId >>= \case
    'd' -> do
      Latin.char ExpectedDeviceId '='
      asciiTextField InvalidDeviceId
    'c' -> do
      Latin.char5 ExpectedDeviceId 'e' '_' 'i' 'd' '='
      asciiTextField InvalidDeviceId
    _ -> P.fail ExpectedDeviceId
  Latin.char5 ExpectedVd ' ' 'v' 'd' '=' '"'
  _ <- P.takeTrailedBy ExpectedVd 0x22
  Latin.char ExpectedVd ' '
  Latin.trySatisfy (=='i') >>= \case
    True -> do
      P.cstring ExpectedITime (Ptr "time="#)
      Latin.skipDigits1 ExpectedITime
      Latin.char ExpectedITime ' '
      P.cstring ExpectedFctsn (Ptr "fctsn=\""#)
      _ <- P.takeTrailedBy ExpectedFctsn 0x22
      Latin.char ExpectedITime ' '
    False -> pure ()
  Datetime date time <- takeDateAndTime
  Latin.char ExpectedTime ' '
  Latin.trySatisfy (=='s') >>= \case
    True -> do
      P.cstring ExpectedEventTime (Ptr "lot="#)
      Latin.skipDigits1 ExpectedSlotId
      Latin.char ExpectedSlotId ' '
    False -> pure ()
  Latin.trySatisfy (=='e') >>= \case
    True -> do
      P.cstring ExpectedEventTime (Ptr "venttime="#)
      Latin.skipDigits1 ExpectedEventTime
      P.cstring ExpectedTz (Ptr " tz="#)
      _ <- P.takeTrailedBy ExpectedTz (c2w ' ')
      pure ()
    False -> pure ()
  Latin.char3 ExpectedLogId 'l' 'o' 'g'
  logId <- Latin.any ExpectedLogId >>= \case
    '_' -> do
      Latin.char3 ExpectedLogId 'i' 'd' '='
      asciiTextField InvalidLogId
    'i' -> do
      Latin.char2 ExpectedLogId 'd' '='
      asciiTextField InvalidLogId
    'v' -> do
      Latin.char3 ExpectedLogVer 'e' 'r' '='
      _ <- asciiTextField ExpectedLogVer
      Latin.char4 ExpectedId ' ' 'i' 'd' '='
      Latin.skipDigits1 ExpectedId
      b <- Unsafe.expose
      pure (Bytes b 0 0)
    _ -> P.fail ExpectedLogId
  Latin.char6 ExpectedType ' ' 't' 'y' 'p' 'e' '='
  type_ <- asciiTextField InvalidType
  Latin.char9 ExpectedSubtype ' ' 's' 'u' 'b' 't' 'y' 'p' 'e' '='
  subtype <- asciiTextField InvalidSubtype
  fields <- fieldsParser =<< P.effect Builder.new
  pure Log
    { deviceName, deviceId, logId, type_, subtype
    , fields
    , date = date
    , time = time
    }

semistructuredParser :: Parser DecodeException s (Chunks Field)
semistructuredParser = do
  -- If the caret-surrounded syslog priority is present, ignore it.
  Latin.trySatisfy (=='<') >>= \case
    True -> do
      Latin.skipDigits1 InvalidSyslogPriority
      Latin.char InvalidSyslogPriority '>'
    False -> pure ()
  -- Skip any leading space or any space after the syslog priority.
  Latin.skipChar ' '
  fieldsParserStart =<< P.effect Builder.new

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
  Latin.peek' ExpectedLeadingChar >>= \case
    'l' -> do
      Latin.char7 ExpectedLogVer 'l' 'o' 'g' 'v' 'e' 'r' '='
      Latin.skipDigits1 ExpectedLogVer
      Latin.char ExpectedLogVer ' '
      finishModeA
    't' -> finishModeA
    _ -> do
      Datetime date time <- takeDateAndTime
      Latin.char ExpectedSpace ' '
      (deviceName, deviceId) <- Latin.peek' ExpectedDeviceName >>= \case
        'd' -> do
          Latin.char8 ExpectedDeviceName 'd' 'e' 'v' 'n' 'a' 'm' 'e' '='
          deviceName <- asciiTextField InvalidDeviceName
          Latin.char5 ExpectedDeviceId ' ' 'd' 'e' 'v' 'i'
          deviceId <- Latin.any ExpectedDeviceId >>= \case
            'd' -> do
              Latin.char ExpectedDeviceId '='
              asciiTextField InvalidDeviceId
            'c' -> do
              Latin.char5 ExpectedDeviceId 'e' '_' 'i' 'd' '='
              asciiTextField InvalidDeviceId
            _ -> P.fail ExpectedDeviceId
          Latin.char ExpectedSpaceAfterDeviceId ' '
          pure (deviceName, deviceId)
        _ -> pure (Bytes.empty, Bytes.empty)
      Latin.any ExpectedFieldsAfterDeviceId >>= \case
        -- This is a hack, and it causes us to lose the eventtime and tz, but
        -- these are somewhat low-value fields anyway. 
        'l' -> pure ()
        'e' -> do
          P.cstring ExpectedEventTime (Ptr "venttime="#)
          Latin.skipDigits1 ExpectedEventTime
          P.cstring ExpectedTz (Ptr " tz="#)
          _ <- P.takeTrailedBy ExpectedTz (c2w ' ')
          Latin.char ExpectedLogId 'l'
        _ -> P.fail ExpectedFieldsAfterDeviceId
      Latin.char2 ExpectedLogId 'o' 'g'
      logId <- Latin.any ExpectedLogId >>= \case
        '_' -> do
          Latin.char3 ExpectedLogId 'i' 'd' '='
          asciiTextField InvalidLogId
        'i' -> do
          Latin.char2 ExpectedLogId 'd' '='
          asciiTextField InvalidLogId
        _ -> P.fail ExpectedLogId
      Latin.char6 ExpectedType ' ' 't' 'y' 'p' 'e' '='
      type_ <- asciiTextField InvalidType
      Latin.char9 ExpectedSubtype ' ' 's' 'u' 'b' 't' 'y' 'p' 'e' '='
      subtype <- asciiTextField InvalidSubtype
      fields <- fieldsParser =<< P.effect Builder.new
      pure Log
        { deviceName, deviceId, logId, type_, subtype
        , fields
        , date = date
        , time = time
        }

-- Value may be optionally quoted.
parserDate :: Parser DecodeException s Date
parserDate = do
  dateHasLeadingDoubleQuote <- Latin.trySatisfy (=='"')
  year <- Latin.decWord InvalidDate
  Latin.char InvalidDate '-'
  month' <- Latin.decWord InvalidDate
  let !month = month' - 1
  Latin.char InvalidDate '-'
  day <- Latin.decWord InvalidDate
  when dateHasLeadingDoubleQuote (Latin.char ExpectedQuoteAfterDate '"')
  if month < 12
    then do
      let !date = Chronos.Date
            (Year (fromIntegral year))
            (Month (fromIntegral month))
            (DayOfMonth (fromIntegral day))
      pure date
    else P.fail InvalidDate

parserTimeOfDay :: Parser DecodeException s TimeOfDay
parserTimeOfDay = do
  timeHasLeadingDoubleQuote <- Latin.trySatisfy (=='"')
  hour <- Latin.decWord InvalidTime
  Latin.char InvalidTime ':'
  minute <- Latin.decWord InvalidTime
  Latin.char InvalidTime ':'
  sec <- Latin.decWord InvalidTime
  when timeHasLeadingDoubleQuote (Latin.char ExpectedQuoteAfterTime '"')
  let !time = Chronos.TimeOfDay
        (fromIntegral hour)
        (fromIntegral minute)
        (fromIntegral (sec * 1000000000))
  pure time

takeDateAndTime :: Parser DecodeException s Datetime
takeDateAndTime = do
  Latin.char5 ExpectedDate 'd' 'a' 't' 'e' '='
  date <- parserDate
  Latin.char6 ExpectedTime ' ' 't' 'i' 'm' 'e' '='
  time <- parserTimeOfDay
  pure Datetime{datetimeDate=date,datetimeTime=time}

fieldsParserStart :: Builder s Field -> Parser DecodeException s (Chunks Field)
fieldsParserStart !b0 = do
  name <- P.takeTrailedBy IncompleteKey (c2w '=')
  !b1 <- afterEquals name b0
  fieldsParser b1

fieldsParser ::
     Builder s Field
  -> Parser DecodeException s (Chunks Field)
fieldsParser !b0 = P.isEndOfInput >>= \case
  True -> P.effect (Builder.freeze b0)
  False -> do
    Latin.char ExpectedSpace ' '
    name <- P.takeTrailedBy IncompleteKey (c2w '=')
    !b1 <- afterEquals name b0
    fieldsParser b1

discardUnknownField :: Builder s Field -> Parser DecodeException s (Builder s Field)
discardUnknownField !b0 = do
  _ <- asciiTextField InvalidUnknownField
  pure b0

-- Precondition: There is an equals sign after the slice. That is, we can
-- index one past the end of the slice, and it will have a well defined
-- behavior.
afterEquals :: Bytes -> Builder s Field -> Parser DecodeException s (Builder s Field)
afterEquals !b !b0 = case fromIntegral @Int @Word len of
  2 -> case indexUnalignedByteArray arr off :: Word16 of
    G.W_vd -> do
      val <- asciiTextField InvalidVirtualDomain
      let !atom = VirtualDomain val
      P.effect (Builder.push atom b0)
    G.W_ip -> do
      val <- IP.parserUtf8Bytes InvalidIp
      let !atom = Ip val
      P.effect (Builder.push atom b0)
    G.W_tz -> do
      Latin.char InvalidTimeZone '"'
      val <- Latin.decSignedInt InvalidTimeZone
      Latin.char InvalidTimeZone '"'
      let !atom = TimeZone val
      P.effect (Builder.push atom b0)
    _ -> discardUnknownField b0
  3 -> case indexUnalignedByteArray arr off :: Word32 of
    G.W_mac -> do
      quoted <- Latin.trySatisfy (=='"')
      r <- Mac.parserUtf8Bytes InvalidMac
      when quoted (Latin.char InvalidMac '"')
      let !atom = Mac r
      P.effect (Builder.push atom b0)
    G.W_vpn -> do
      val <- asciiTextField InvalidVpn
      let !atom = Vpn val
      P.effect (Builder.push atom b0)
    G.W_pri -> do
      val <- asciiTextField InvalidPriority
      let !atom = Priority val
      P.effect (Builder.push atom b0)
    G.W_app -> do
      val <- asciiTextField InvalidApp
      let !atom = App val
      P.effect (Builder.push atom b0)
    G.W_url -> do
      val <- asciiTextField InvalidUrl
      let !atom = Url val
      P.effect (Builder.push atom b0)
    G.W_msg -> do
      val <- escapedAsciiTextField InvalidMessage
      let !atom = Message val
      P.effect (Builder.push atom b0)
    G.W_ref -> do
      val <- asciiTextField InvalidReference
      let !atom = Reference val
      P.effect (Builder.push atom b0)
    G.W_xid -> do
      val <- Latin.decWord64 InvalidTransactionId
      let !atom = TransactionId val
      P.effect (Builder.push atom b0)
    G.W_cat -> do
      val <- Latin.decWord64 InvalidCategory
      let !atom = Category val
      P.effect (Builder.push atom b0)
    _ -> discardUnknownField b0
  4 -> case indexUnalignedByteArray arr off :: Word32 of
    G.W_date -> do
      val <- parserDate
      let !atom = Date val
      P.effect (Builder.push atom b0)
    G.W_time -> do
      val <- parserTimeOfDay
      let !atom = Time val
      P.effect (Builder.push atom b0)
    G.W_type -> do
      val <- asciiTextField InvalidType
      let !atom = Type val
      P.effect (Builder.push atom b0)
    G.W_user -> do
      val <- asciiTextField InvalidUser
      let !atom = User val
      P.effect (Builder.push atom b0)
    G.W_desc -> do
      val <- asciiTextField InvalidDescription
      let !atom = Description val
      P.effect (Builder.push atom b0)
    _ -> discardUnknownField b0
  5 -> case G.hashString5 arr off of
    G.H_remip -> case equal5 arr off "remip"# of
      0## -> do
        val <- IP.parserUtf8Bytes InvalidRemoteIp
        let !atom = RemoteIp val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_qname -> case equal5 arr off "qname"# of
      0## -> do
        val <- asciiTextField InvalidQueryName
        let !atom = QueryName val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_devid -> case equal5 arr off "devid"# of
      0## -> do
        val <- asciiTextField InvalidDeviceId
        let !atom = DeviceId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_qtype -> case equal5 arr off "qtype"# of
      0## -> do
        val <- asciiTextField InvalidQueryType
        let !atom = QueryType val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_group -> case equal5 arr off "group"# of
      0## -> do
        val <- asciiTextField InvalidGroup
        let !atom = Group val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_alert -> case equal5 arr off "alert"# of
      0## -> do
        val <- optQuotedDecWord64 InvalidAlert
        let !atom = Alert val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_vwlid -> case equal5 arr off "vwlid"# of
      0## -> do
        val <- Latin.decWord64 InvalidVirtualWanLinkId
        let !atom = VirtualWanLinkId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_appid -> case equal5 arr off "appid"# of
      0## -> do
        val <- Latin.decWord64 InvalidApplicationId
        let !atom = ApplicationId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_lease -> case equal5 arr off "lease"# of
      0## -> do
        val <- Latin.decWord64 InvalidLease
        let !atom = Lease val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_wanin -> case equal5 arr off "wanin"# of
      0## -> do
        val <- Latin.decWord64 InvalidWanIn
        let !atom = WanIn val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_lanin -> case equal5 arr off "lanin"# of
      0## -> do
        val <- Latin.decWord64 InvalidLanIn
        let !atom = LanIn val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcip -> case equal5 arr off "srcip"# of
      0## -> do
        val <- optQuotedIp InvalidSourceIp
        let !atom = SourceIp val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstip -> case equal5 arr off "dstip"# of
      0## -> do
        val <- IP.parserUtf8Bytes InvalidDestinationIp
        let !atom = DestinationIp val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_level -> case equal5 arr off "level"# of
      0## -> do
        val <- asciiTextField InvalidLevel
        let !atom = Level val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_error -> case equal5 arr off "error"# of
      0## -> do
        val <- asciiTextField InvalidError
        let !atom = Level val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_proto -> case equal5 arr off "proto"# of
      0## -> do
        val <- Latin.decWord8 InvalidProtocol
        let !atom = Protocol val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_log_id -> case equal5 arr off "logid"# of
      0## -> do
        val <- escapedAsciiTextField InvalidLogId
        let !atom = LogId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  6 -> case G.hashString6 arr off of
    G.H_log_id -> case equal6 arr off "log_id"# of
      0## -> do
        val <- escapedAsciiTextField InvalidLogId
        let !atom = LogId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_reason -> case equal6 arr off "reason"# of
      0## -> do
        val <- escapedAsciiTextField InvalidReason
        let !atom = Reason val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_qclass -> case equal6 arr off "qclass"# of
      0## -> do
        val <- asciiTextField InvalidQueryClass
        let !atom = QueryClass val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstmac -> case equal6 arr off "dstmac"# of
      0## -> do
        quoted <- Latin.trySatisfy (=='"')
        r <- Mac.parserUtf8Bytes InvalidDestinationMac
        when quoted (Latin.char InvalidDestinationMac '"')
        let !atom = DestinationMac r
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcmac -> case equal6 arr off "srcmac"# of
      0## -> do
        quoted <- Latin.trySatisfy (=='"')
        r <- Mac.parserUtf8Bytes InvalidSourceMac
        when quoted (Latin.char InvalidSourceMac '"')
        let !atom = SourceMac r
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_appact -> case equal6 arr off "appact"# of
      0## -> do
        val <- asciiTextField InvalidApplicationAction
        let !atom = ApplicationAction val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_appcat -> case equal6 arr off "appcat"# of
      0## -> do
        val <- asciiTextField InvalidApplicationCategory
        let !atom = ApplicationCategory val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_attack -> case equal6 arr off "attack"# of
      0## -> do
        val <- asciiTextField InvalidAttack
        let !atom = Attack val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_action -> case equal6 arr off "action"# of
      0## -> do
        val <- asciiTextField InvalidAction
        let !atom = Action val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_member -> case equal6 arr off "member"# of
      0## -> do
        val <- asciiTextField InvalidMember
        let !atom = Member val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_method -> case equal6 arr off "method"# of
      0## -> do
        val <- asciiTextField InvalidMethod
        let !atom = Method val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_wanout -> case equal6 arr off "wanout"# of
      0## -> do
        val <- Latin.decWord64 InvalidWanOut
        let !atom = WanOut val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_lanout -> case equal6 arr off "lanout"# of
      0## -> do
        val <- Latin.decWord64 InvalidLanOut
        let !atom = LanOut val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_logver -> case equal6 arr off "logver"# of
      0## -> do
        val <- Latin.decWord64 InvalidLogVersion
        let !atom = LogVersion val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_osname -> case equal6 arr off "osname"# of
      0## -> do
        val <- asciiTextField InvalidOsName
        let !atom = OsName val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  7 -> case indexUnalignedByteArray arr off :: Word64 of
    G.W_subtype -> do
      w <- asciiTextField InvalidSubtype
      let !atom = Subtype w
      P.effect (Builder.push atom b0)
    G.W_vwlname -> do
      w <- asciiTextField InvalidVirtualWanLinkName
      let !atom = VirtualWanLinkName w
      P.effect (Builder.push atom b0)
    G.W_srcuuid -> do
      w <- uuidField InvalidSourceUuid
      let !atom = SourceUuid w
      P.effect (Builder.push atom b0)
    G.W_dstuuid -> do
      w <- uuidField InvalidDestinationUuid
      let !atom = DestinationUuid w
      P.effect (Builder.push atom b0)
    G.W_poluuid -> do
      w <- uuidField InvalidPolicyUuid
      let !atom = PolicyUuid w
      P.effect (Builder.push atom b0)
    G.W_vpntype -> do
      val <- asciiTextField InvalidVpnType
      let !atom = VpnType val
      P.effect (Builder.push atom b0)
    G.W_devtype -> do
      val <- asciiTextField InvalidDeviceType
      let !atom = DeviceType val
      P.effect (Builder.push atom b0)
    G.W_srcname -> do
      val <- asciiTextField InvalidSourceName
      let !atom = SourceName val
      P.effect (Builder.push atom b0)
    G.W_applist -> do
      val <- asciiTextField InvalidApplicationList
      let !atom = ApplicationList val
      P.effect (Builder.push atom b0)
    G.W_apprisk -> do
      val <- asciiTextField InvalidApplicationRisk
      let !atom = ApplicationRisk val
      P.effect (Builder.push atom b0)
    G.W_logdesc -> do
      val <- asciiTextField InvalidLogDescription
      let !atom = LogDescription val
      P.effect (Builder.push atom b0)
    G.W_reqtype -> do
      val <- asciiTextField InvalidRequestType
      let !atom = RequestType val
      P.effect (Builder.push atom b0)
    G.W_crscore -> do
      val <- Latin.decWord64 InvalidClientReputationScore
      let !atom = ClientReputationScore val
      P.effect (Builder.push atom b0)
    G.W_crlevel -> do
      val <- asciiTextField InvalidClientReputationLevel
      let !atom = ClientReputationLevel val
      P.effect (Builder.push atom b0)
    G.W_catdesc -> do
      val <- asciiTextField InvalidCategoryDescription
      let !atom = CategoryDescription val
      P.effect (Builder.push atom b0)
    G.W_srcintf -> do
      val <- asciiTextField InvalidSourceInterface
      let !atom = SourceInterface val
      P.effect (Builder.push atom b0)
    G.W_dstintf -> do
      val <- asciiTextField InvalidDestinationInterface
      let !atom = DestinationInterface val
      P.effect (Builder.push atom b0)
    G.W_locport -> do
      val <- Latin.decWord16 InvalidLocalPort
      let !atom = LocalPort val
      P.effect (Builder.push atom b0)
    G.W_remport -> do
      val <- Latin.decWord16 InvalidRemotePort
      let !atom = RemotePort val
      P.effect (Builder.push atom b0)
    G.W_srcport -> do
      val <- Latin.decWord16 InvalidSourcePort
      let !atom = SourcePort val
      P.effect (Builder.push atom b0)
    G.W_dstport -> do
      val <- Latin.decWord16 InvalidDestinationPort
      let !atom = DestinationPort val
      P.effect (Builder.push atom b0)
    G.W_service -> do
      val <- asciiTextField InvalidService
      let !atom = Service val
      P.effect (Builder.push atom b0)
    G.W_sentpkt -> do
      val <- Latin.decWord64 InvalidSentPackets
      let !atom = SentPackets val
      P.effect (Builder.push atom b0)
    G.W_rcvdpkt -> do
      val <- Latin.decWord64 InvalidReceivedPackets
      let !atom = ReceivedPackets val
      P.effect (Builder.push atom b0)
    G.W_profile -> do
      val <- asciiTextField InvalidProfile
      let !atom = Profile val
      P.effect (Builder.push atom b0)
    _ -> discardUnknownField b0
  8 -> case indexUnalignedByteArray arr off :: Word64 of
    G.W_oldvalue -> do
      val <- asciiTextField InvalidOldValue
      let !atom = OldValue val
      P.effect (Builder.push atom b0)
    G.W_newvalue -> do
      val <- asciiTextField InvalidNewValue
      let !atom = NewValue val
      P.effect (Builder.push atom b0)
    G.W_qtypeval -> do
      val <- Latin.decWord64 InvalidQueryTypeValue
      let !atom = QueryTypeValue val
      P.effect (Builder.push atom b0)
    G.W_checksum -> do
      quoted <- Latin.trySatisfy (=='"')
      val <- Latin.hexFixedWord32 InvalidChecksum
      when quoted (Latin.char InvalidMasterSourceMac '"')
      let !atom = Checksum val
      P.effect (Builder.push atom b0)
    G.W_tunnelip -> do
      -- Sometimes tunnelip is: N/A. In this case, we omit it.
      Latin.trySatisfy (== 'N') >>= \case
        True -> do
          Latin.char2 InvalidTunnelIp '/' 'A'
          pure b0
        False -> do
          val <- IP.parserUtf8Bytes InvalidTunnelIp
          let !atom = TunnelIp val
          P.effect (Builder.push atom b0)
    G.W_tunnelid -> do
      val <- Latin.decWord64 InvalidTunnelId
      let !atom = TunnelId val
      P.effect (Builder.push atom b0)
    G.W_dst_host -> do
      val <- asciiTextField InvalidDestinationHost
      let !atom = DestinationHost val
      P.effect (Builder.push atom b0)
    G.W_dhcp_msg -> do
      val <- asciiTextField InvalidDhcpMessage
      let !atom = DhcpMessage val
      P.effect (Builder.push atom b0)
    G.W_nextstat -> do
      val <- Latin.decWord64 InvalidNextStatistics
      let !atom = NextStatistics val
      P.effect (Builder.push atom b0)
    G.W_attackid -> do
      val <- Latin.decWord64 InvalidAttackId
      let !atom = AttackId val
      P.effect (Builder.push atom b0)
    G.W_countips -> do
      val <- Latin.decWord64 InvalidCountIps
      let !atom = CountIps val
      P.effect (Builder.push atom b0)
    G.W_hostname -> do
      val <- asciiTextField InvalidHostname
      let !atom = Hostname val
      P.effect (Builder.push atom b0)
    G.W_filename -> do
      val <- escapedAsciiTextField InvalidFilename
      let !atom = Filename val
      P.effect (Builder.push atom b0)
    G.W_craction -> do
      val <- asciiTextField InvalidClientReputationAction
      let !atom = ClientReputationAction val
      P.effect (Builder.push atom b0)
    G.W_severity -> do
      val <- asciiTextField InvalidSeverity
      let !atom = Severity val
      P.effect (Builder.push atom b0)
    G.W_policyid -> do
      val <- Latin.decWord64 InvalidPolicyId
      let !atom = PolicyId val
      P.effect (Builder.push atom b0)
    G.W_duration -> do
      val <- Latin.decWord64 InvalidDuration
      let !atom = Duration val
      P.effect (Builder.push atom b0)
    G.W_sentbyte -> do
      val <- Latin.decWord64 InvalidSentBytes
      let !atom = SentBytes val
      P.effect (Builder.push atom b0)
    G.W_rcvdbyte -> do
      val <- Latin.decWord64 InvalidReceivedBytes
      let !atom = ReceivedBytes val
      P.effect (Builder.push atom b0)
    G.W_countweb -> do
      val <- Latin.decWord64 InvalidCountWeb
      let !atom = CountWeb val
      P.effect (Builder.push atom b0)
    G.W_countapp -> do
      val <- Latin.decWord64 InvalidCountApplication
      let !atom = CountApplication val
      P.effect (Builder.push atom b0)
    G.W_trandisp -> Latin.any InvalidTranslationDisposition >>= \case
      '"' -> Latin.any InvalidTranslationDisposition >>= \case
        'n' -> do
          Latin.char4 InvalidTranslationDisposition 'o' 'o' 'p' '"'
          pure b0
        'd' -> do
          Latin.char5 InvalidTranslationDisposition 'n' 'a' 't' '"' ' '
          dnatFinish b0
        's' -> do
          Latin.char3 InvalidTranslationDisposition 'n' 'a' 't'
          Latin.trySatisfy (== '+') >>= \case
            False -> do
              Latin.char2 InvalidTranslationDisposition '"' ' '
              snatFinish b0
            True -> do
              Latin.char6 InvalidTranslationDisposition 'd' 'n' 'a' 't' '"' ' '
              snatAndDnatFinish b0
        _ -> P.fail InvalidTranslationDisposition
      'n' -> do
        Latin.char3 InvalidTranslationDisposition 'o' 'o' 'p'
        pure b0
      'd' -> do
        Latin.char4 InvalidTranslationDisposition 'n' 'a' 't' ' '
        dnatFinish b0
      's' -> do
        Latin.char3 InvalidTranslationDisposition 'n' 'a' 't'
        Latin.trySatisfy (== '+') >>= \case
          False -> do
            Latin.char InvalidTranslationDisposition ' '
            snatFinish b0
          True -> do
            Latin.char5 InvalidTranslationDisposition 'd' 'n' 'a' 't' ' '
            snatAndDnatFinish b0
      _ -> P.fail InvalidTranslationDisposition
    _ -> discardUnknownField b0
  9 -> case G.hashString9 arr off of
    G.H_dstregion -> case equal9 arr off "dstregion"# of
      0## -> do
        val <- asciiTextField InvalidDestinationRegion
        let !atom = DestinationRegion val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcregion -> case equal9 arr off "srcregion"# of
      0## -> do
        val <- asciiTextField InvalidSourceRegion
        let !atom = SourceRegion val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstserver -> case equal9 arr off "dstserver"# of
      0## -> do
        val <- Latin.decWord64 InvalidDestinationServer
        let !atom = DestinationServer val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_urlsource -> case equal9 arr off "urlsource"# of
      0## -> do
        val <- asciiTextField InvalidUrlSource
        let !atom = UrlSource val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstosname -> case equal9 arr off "dstosname"# of
      0## -> do
        val <- asciiTextField InvalidDestinationOsName
        let !atom = DestinationOsName val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_sslaction -> case equal9 arr off "sslaction"# of
      0## -> do
        val <- asciiTextField InvalidSslAction
        let !atom = SslAction val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_osversion -> case equal9 arr off "osversion"# of
      0## -> do
        val <- asciiTextField InvalidOsVersion
        let !atom = OsVersion val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcserver -> case equal9 arr off "srcserver"# of
      0## -> do
        val <- Latin.decWord64 InvalidSourceServer
        let !atom = SourceServer val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_interface -> case equal9 arr off "interface"# of
      0## -> do
        val <- asciiTextField InvalidInterface
        let !atom = Interface val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_sessionid -> case equal9 arr off "sessionid"# of
      0## -> do
        val <- Latin.decWord64 InvalidSessionId
        let !atom = SessionId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_eventtype -> case equal9 arr off "eventtype"# of
      0## -> do
        val <- asciiTextField InvalidEventType
        let !atom = EventType val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_eventtime -> case equal9 arr off "eventtime"# of
      0## -> do
        val <- Latin.decWord64 InvalidEventTime
        let !atom = EventTime val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_utmaction -> case equal9 arr off "utmaction"# of
      0## -> do
        val <- asciiTextField InvalidUtmAction
        let !atom = UtmAction val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_direction -> case equal9 arr off "direction"# of
      0## -> do
        val <- asciiTextField InvalidDirection
        let !atom = Direction val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcfamily -> case equal9 arr off "srcfamily"# of
      0## -> do
        val <- asciiTextField InvalidSourceFamily
        let !atom = SourceFamily val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_sentdelta -> case equal9 arr off "sentdelta"# of
      0## -> do
        val <- Latin.decWord64 InvalidSentDelta
        let !atom = SentDelta val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_rcvddelta -> case equal9 arr off "rcvddelta"# of
      0## -> do
        val <- Latin.decWord64 InvalidReceivedDelta
        let !atom = ReceivedDelta val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  10 -> case G.hashString10 arr off of
    G.H_policyname -> case zequal10 arr off 'p' 'o' 'l' 'i' 'c' 'y' 'n' 'a' 'm' 'e' of
      -- FortiOS uses both policyname and policy_name to mean the same thing.
      0# -> do
        val <- asciiTextField InvalidPolicyName
        let !atom = PolicyName val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_session_id -> case zequal10 arr off 's' 'e' 's' 's' 'i' 'o' 'n' '_' 'i' 'd' of
      0# -> do
        -- For some crazy reason, FortiOS logs can have the session identifier
        -- written as <sessionid=DECNUM> or <session_id=HEXNUM>. The underscore
        -- determines the encoding of the number
        -- TODO: Fix this.
        _ <- asciiTextField InvalidSessionId
        let !atom = SessionId 0
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_vwlquality -> case zequal10 arr off 'v' 'w' 'l' 'q' 'u' 'a' 'l' 'i' 't' 'y' of
      0# -> do
        val <- asciiTextField InvalidVirtualWanLinkQuality
        let !atom = VirtualWanLinkQuality val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_tunneltype -> case zequal10 arr off 't' 'u' 'n' 'n' 'e' 'l' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidTunnelType
        let !atom = TunnelType val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_cdrcontent -> case zequal10 arr off 'c' 'd' 'r' 'c' 'o' 'n' 't' 'e' 'n' 't' of
      0# -> do
        val <- asciiTextField InvalidCdrContent
        let !atom = CdrContent val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_authserver -> case zequal10 arr off 'a' 'u' 't' 'h' 's' 'e' 'r' 'v' 'e' 'r' of
      0# -> do
        val <- asciiTextField InvalidAuthServer
        let !atom = AuthServer val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstdevtype -> case zequal10 arr off 'd' 's' 't' 'd' 'e' 'v' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidDestinationDeviceType
        let !atom = DestinationDeviceType val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_unauthuser -> case zequal10 arr off 'u' 'n' 'a' 'u' 't' 'h' 'u' 's' 'e' 'r' of
      0# -> do
        val <- asciiTextField InvalidUnauthenticatedUser
        let !atom = UnauthenticatedUser val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srccountry -> case zequal10 arr off 's' 'r' 'c' 'c' 'o' 'u' 'n' 't' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidSourceCountry
        let !atom = SourceCountry val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstcountry -> case zequal10 arr off 'd' 's' 't' 'c' 'o' 'u' 'n' 't' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidDestinationCountry
        let !atom = DestinationCountry val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_policytype -> case zequal10 arr off 'p' 'o' 'l' 'i' 'c' 'y' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidPolicyType
        let !atom = PolicyType val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstinetsvc -> case zequal10 arr off 'd' 's' 't' 'i' 'n' 'e' 't' 's' 'v' 'c' of
      0# -> do
        val <- asciiTextField InvalidDestinationInternetService
        let !atom = DestinationInternetService val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_scertcname -> case zequal10 arr off 's' 'c' 'e' 'r' 't' 'c' 'n' 'a' 'm' 'e' of
      0# -> do
        val <- asciiTextField InvalidSslCertificateCommonName
        let !atom = SslCertificateCommonName val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  11 -> case G.hashString11 arr off of
    G.H_policy_name -> case zequal11 arr off 'p' 'o' 'l' 'i' 'c' 'y' '_' 'n' 'a' 'm' 'e' of
      -- FortiOS uses both policyname and policy_name to mean the same thing.
      0# -> do
        val <- asciiTextField InvalidPolicyName
        let !atom = PolicyName val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_healthcheck -> case zequal11 arr off 'h' 'e' 'a' 'l' 't' 'h' 'c' 'h' 'e' 'c' 'k' of
      0# -> do
        val <- asciiTextField InvalidHealthCheck
        let !atom = HealthCheck val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_devcategory -> case zequal11 arr off 'd' 'e' 'v' 'c' 'a' 't' 'e' 'g' 'o' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidDeviceCategory
        let !atom = DeviceCategory val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_scertissuer -> case zequal11 arr off 's' 'c' 'e' 'r' 't' 'i' 's' 's' 'u' 'e' 'r' of
      0# -> do
        val <- asciiTextField InvalidSslCertificateIssuer
        let !atom = SslCertificateIssuer val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_referralurl -> case zequal11 arr off 'r' 'e' 'f' 'e' 'r' 'r' 'a' 'l' 'u' 'r' 'l' of
      0# -> do
        val <- asciiTextField InvalidReferralUrl
        let !atom = ReferralUrl val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_profiletype -> case zequal11 arr off 'p' 'r' 'o' 'f' 'i' 'l' 'e' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidProfileType
        let !atom = ProfileType val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstintfrole -> case zequal11 arr off 'd' 's' 't' 'i' 'n' 't' 'f' 'r' 'o' 'l' 'e' of
      0# -> do
        val <- asciiTextField InvalidDestinationInterfaceRole
        let !atom = DestinationInterfaceRole val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcintfrole -> case zequal11 arr off 's' 'r' 'c' 'i' 'n' 't' 'f' 'r' 'o' 'l' 'e' of
      0# -> do
        val <- asciiTextField InvalidSourceInterfaceRole
        let !atom = SourceInterfaceRole val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srchwvendor -> case zequal11 arr off 's' 'r' 'c' 'h' 'w' 'v' 'e' 'n' 'd' 'o' 'r' of
      0# -> do
        val <- asciiTextField InvalidSourceHardwareVendor
        let !atom = SourceHardwareVendor val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  12 -> case G.hashString12 arr off of
    G.H_dstosversion -> case zequal12 arr off 'd' 's' 't' 'o' 's' 'v' 'e' 'r' 's' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidDestinationOsVerson
        let !atom = DestinationOsVersion val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_centralnatid -> case zequal12 arr off 'c' 'e' 'n' 't' 'r' 'a' 'l' 'n' 'a' 't' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidCentralNatId
        let !atom = CentralNatId val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_urlfilteridx -> case zequal12 arr off 'u' 'r' 'l' 'f' 'i' 'l' 't' 'e' 'r' 'i' 'd' 'x' of
      0# -> do
        val <- Latin.decWord64 InvalidUrlFilterIndex
        let !atom = UrlFilterIndex val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_srcswversion -> case zequal12 arr off 's' 'r' 'c' 's' 'w' 'v' 'e' 'r' 's' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidSourceSoftwareVersion
        let !atom = SourceSoftwareVersion val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_mastersrcmac -> case zequal12 arr off 'm' 'a' 's' 't' 'e' 'r' 's' 'r' 'c' 'm' 'a' 'c' of
      0# -> do
        quoted <- Latin.trySatisfy (=='"')
        r <- Mac.parserUtf8Bytes InvalidMasterSourceMac
        when quoted (Latin.char InvalidMasterSourceMac '"')
        let !atom = MasterSourceMac r
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_masterdstmac -> case zequal12 arr off 'm' 'a' 's' 't' 'e' 'r' 'd' 's' 't' 'm' 'a' 'c' of
      0# -> do
        quoted <- Latin.trySatisfy (=='"')
        r <- Mac.parserUtf8Bytes InvalidMasterDestinationMac
        when quoted (Latin.char InvalidMasterDestinationMac '"')
        let !atom = MasterDestinationMac r
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  13 -> case zequal13 arr off 'u' 'r' 'l' 'f' 'i' 'l' 't' 'e' 'r' 'l' 'i' 's' 't' of
    0# -> do
      val <- asciiTextField InvalidUrlFilterList
      let !atom = UrlFilterList val
      P.effect (Builder.push atom b0)
    _ -> discardUnknownField b0
  14 -> case G.hashString14 arr off of
    G.H_analyticscksum -> case zequal14 arr off 'a' 'n' 'a' 'l' 'y' 't' 'i' 'c' 's' 'c' 'k' 's' 'u' 'm' of
      0# -> do
        quoted <- Latin.trySatisfy (=='"')
        val <- Latin.hexFixedWord256 InvalidAnalyticsChecksum
        when quoted (Latin.char InvalidAnalyticsChecksum '"')
        let !atom = AnalyticsChecksum val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_dstdevcategory -> case zequal14 arr off 'd' 's' 't' 'd' 'e' 'v' 'c' 'a' 't' 'e' 'g' 'o' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidDestinationDeviceCategory
        let !atom = DestinationDeviceCategory val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  15 -> case zequal15 arr off 'c' 'o' 'n' 't' 'e' 'n' 't' 'd' 'i' 's' 'a' 'r' 'm' 'e' 'd' of
    0# -> do
      val <- asciiTextField InvalidContentDisarmed
      let !atom = ContentDisarmed val
      P.effect (Builder.push atom b0)
    _ -> discardUnknownField b0
  16 -> case G.hashString16 arr off of
    G.H_incidentserialno -> case zequal16 arr off 'i' 'n' 'c' 'i' 'd' 'e' 'n' 't' 's' 'e' 'r' 'i' 'a' 'l' 'n' 'o' of
      0# -> do
        val <- Latin.decWord64 InvalidIncidentSerialNumber
        let !atom = IncidentSerialNumber val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    G.H_unauthusersource -> case zequal16 arr off 'u' 'n' 'a' 'u' 't' 'h' 'u' 's' 'e' 'r' 's' 'o' 'u' 'r' 'c' 'e' of
      0# -> do
        val <- asciiTextField InvalidUnauthenticatedUserSource
        let !atom = UnauthenticatedUserSource val
        P.effect (Builder.push atom b0)
      _ -> discardUnknownField b0
    _ -> discardUnknownField b0
  _ -> discardUnknownField b0
  where
  !(Bytes arr off len) = b

dnatFinish :: Builder s Field -> Parser DecodeException s (Builder s Field)
dnatFinish !b0 = do
  Latin.char7 InvalidTranslationDisposition 't' 'r' 'a' 'n' 'i' 'p' '='
  !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
  Latin.char10 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 'p' 'o' 'r' 't' '='
  !port <- Latin.decWord16 InvalidTranslationPort
  let !atom = TranslatedDestination ip port
  P.effect (Builder.push atom b0)

snatFinish :: Builder s Field -> Parser DecodeException s (Builder s Field)
snatFinish !b0 = do
  Latin.char8 InvalidTranslationDisposition 't' 'r' 'a' 'n' 's' 'i' 'p' '='
  !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
  Latin.char11 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 's' 'p' 'o' 'r' 't' '='
  !port <- Latin.decWord16 InvalidTranslationPort
  let !atom = TranslatedSource ip port
  P.effect (Builder.push atom b0)

snatAndDnatFinish :: Builder s Field -> Parser DecodeException s (Builder s Field)
snatAndDnatFinish b0 = do
  Latin.char7 InvalidTranslationDisposition 't' 'r' 'a' 'n' 'i' 'p' '='
  !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
  Latin.char10 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 'p' 'o' 'r' 't' '='
  !port <- Latin.decWord16 InvalidTranslationPort
  Latin.char InvalidTranslationDisposition ' '
  b1 <- snatFinish b0
  let !atom = TranslatedDestination ip port
  P.effect (Builder.push atom b1)

optQuotedIp :: e -> Parser e s IP
optQuotedIp e = Latin.trySatisfy (== '"') >>= \case
  True -> IP.parserUtf8Bytes e <* Latin.char e '"'
  False -> IP.parserUtf8Bytes e

-- Field is optionally surrounded by quotes. This does not
-- consume a trailing space.
optQuotedDecWord64 :: e -> Parser e s Word64
optQuotedDecWord64 e = Latin.trySatisfy (== '"') >>= \case
  True -> Latin.decWord64 e <* Latin.char e '"'
  False -> Latin.decWord64 e

-- Field is optionally surrounded by quotes. This does not
-- consume a trailing space.
asciiTextField :: e -> Parser e s Bytes
asciiTextField e = Latin.trySatisfy (== '"') >>= \case
  True -> P.takeTrailedBy e (c2w '"')
  False -> P.takeWhile (\w -> w /= c2w ' ')

-- Field is optionally surrounded by quotes. This does not
-- consume a trailing space. Also, if the field is quoted,
-- the quoted field may contain quotes escaped by backslashes.
escapedAsciiTextField :: e -> Parser e s Bytes
{-# noinline escapedAsciiTextField #-}
escapedAsciiTextField e = Latin.trySatisfy (== '"') >>= \case
  True -> do
    start <- Unsafe.cursor
    P.skipTrailedBy2 e 0x22 0x5C >>= \case
      False -> do -- no backslashes, went all the way to a double quote
        end <- Unsafe.cursor
        let !len = (end - start) - 1
        arr <- Unsafe.expose
        pure Bytes{array=arr,offset=start,length=len}
      True -> do -- found a backslash, we will need to escape quotes
        c <- Latin.any e
        if c == '"' || c == ']'
          then pure ()
          else P.fail e
        consumeThroughUnescapedQuote e
        end <- Unsafe.cursor
        let !len = (end - start) - 1
        arr <- Unsafe.expose
        let bs = Bytes{array=arr,offset=start,length=len}
        pure $! removeEscapeSequences bs
  False -> P.takeWhile (\w -> w /= c2w ' ')

-- | Precondition: Every backslash is followed by a double quote or by
-- a close square bracket.
removeEscapeSequences :: Bytes -> Bytes
removeEscapeSequences Bytes{array,offset=off0,length=len0} =
  let (lengthX,arrayX) = runIntByteArrayST $ do
        dst <- PM.newByteArray len0
        let go !ixSrc !ixDst !len = case len of
              0 -> pure ixDst
              _ -> do
                let w :: Word8 = PM.indexByteArray array ixSrc
                case w of
                  0x5C -> go (ixSrc + 1) ixDst (len - 1)
                  _ -> do
                    PM.writeByteArray dst ixDst w
                    go (ixSrc + 1) (ixDst + 1) (len - 1)
        lenDst <- go off0 0 len0
        PM.shrinkMutableByteArray dst lenDst
        dst' <- PM.unsafeFreezeByteArray dst
        pure (lenDst,dst')
   in Bytes{array=arrayX,length=lengthX,offset=0}

consumeThroughUnescapedQuote :: e -> Parser e s ()
consumeThroughUnescapedQuote e = P.skipTrailedBy2 e 0x22 0x5C >>= \case
  False -> pure ()
  True -> do
    c <- Latin.any e
    -- Having a double-quote after a backslash is normal and expected.
    -- We just escape it. However, the backslash before the
    -- close-square-bracket is probably an accident by Fortinet.
    -- It happens in OSPF logs.
    if c == '"' || c == ']'
      then consumeThroughUnescapedQuote e
      else P.fail e

-- Some versions of FortiOS put quotes around uuids. Others do not.
-- We handle both cases.
uuidField :: e -> Parser e s Word128
uuidField e = do
  isQuoted <- Latin.trySatisfy (== '"')
  r <- UUID.parserHyphenated e
  when isQuoted (Latin.char e '"')
  pure r

equal5 :: ByteArray -> Int -> Addr# -> Word#
{-# inline equal5 #-}
equal5 (ByteArray arr) (I# off) x =
  word32ToWord# (indexWord8ArrayAsWord32# arr off `xorWord32#` indexWord8OffAddrAsWord32# x 0# ) 
  `or#` 
  (word8ToWord# (indexWord8Array# arr (off +# 4# )) `xor#` word8ToWord# (indexWord8OffAddr# x 4# ))

equal6 :: ByteArray -> Int -> Addr# -> Word#
{-# inline equal6 #-}
equal6 (ByteArray arr) (I# off) x =
  word32ToWord# (indexWord8ArrayAsWord32# arr off `xorWord32#` indexWord8OffAddrAsWord32# x 0# ) 
  `or#` 
  (word16ToWord# (indexWord8ArrayAsWord16# arr (off +# 4# )) `xor#` word16ToWord# (indexWord8OffAddrAsWord16# x 4# ))

equal9 :: ByteArray -> Int -> Addr# -> Word#
{-# inline equal9 #-}
equal9 (ByteArray arr) (I# off) x =
  word64ToWord# (indexWord8ArrayAsWord64# arr off `xor64#` indexWord8OffAddrAsWord64# x 0# ) 
  `or#` 
  (word8ToWord# (indexWord8Array# arr (off +# 8# )) `xor#` word8ToWord# (indexWord8OffAddr# x 8# ))

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

zequal13 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal13 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) (C# k) (C# l) (C# m) =
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
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 12#)) m

zequal14 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal14 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) (C# k) (C# l) (C# m) (C# n) =
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
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 12#)) m
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 13#)) n

zequal15 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal15 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) (C# k) (C# l) (C# m) (C# n) (C# o) =
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
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 12#)) m
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 13#)) n
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 14#)) o

zequal16 :: ByteArray -> Int -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Char -> Int#
zequal16 (ByteArray arr) (I# off) (C# a) (C# b) (C# c) (C# d) (C# e) (C# f) (C# g) (C# h) (C# i) (C# j) (C# k) (C# l) (C# m) (C# n) (C# o) (C# p) =
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
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 12#)) m
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 13#)) n
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 14#)) o
  `orI#`
  zeqChar# (indexCharArray# arr (off +# 15#)) p

c2w :: Char -> Word8
c2w = fromIntegral . ord

-- Returns zero when the characters are equal
zeqChar# :: Char# -> Char# -> Int#
zeqChar# c1 c2 = xorI# (ord# c1) (ord# c2)
