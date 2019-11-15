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
  | InvalidCategory
  | InvalidCategoryDescription
  | InvalidClientReputationAction
  | InvalidClientReputationLevel
  | InvalidClientReputationScore
  | InvalidCountWeb
  | InvalidDate
  | InvalidDestinationCountry
  | InvalidDestinationInterface
  | InvalidDestinationIp
  | InvalidDestinationPort
  | InvalidDeviceId
  | InvalidDeviceName
  | InvalidDirection
  | InvalidDuration
  | InvalidEventType
  | InvalidHostname
  | InvalidLanIn
  | InvalidLanOut
  | InvalidLevel
  | InvalidLogId
  | InvalidMessage
  | InvalidMethod
  | InvalidPolicyId
  | InvalidPolicyType
  | InvalidPolicyUuid
  | InvalidProfile
  | InvalidProtocol
  | InvalidReceivedBytes
  | InvalidReceivedPackets
  | InvalidRequestType
  | InvalidSentBytes
  | InvalidSentPackets
  | InvalidService
  | InvalidSessionId
  | InvalidSourceCountry
  | InvalidSourceInterface
  | InvalidSourceIp
  | InvalidSourcePort
  | InvalidSubtype
  | InvalidSyslogPriority
  | InvalidTime
  | InvalidTranslationDisposition
  | InvalidTranslationIp
  | InvalidTranslationPort
  | InvalidType
  | InvalidUser
  | InvalidUtmAction
  | InvalidUrl
  | InvalidVirtualDomain
  | InvalidWanIn
  | InvalidWanOut
  | UnknownField
  deriving (Show)

data Field
  = Action {-# UNPACK #-} !Bytes
  | App {-# UNPACK #-} !Bytes
  | ApplicationCategory {-# UNPACK #-} !Bytes
  | Category {-# UNPACK #-} !Word64
  | CategoryDescription {-# UNPACK #-} !Bytes
  | ClientReputationScore {-# UNPACK #-} !Word64
  | ClientReputationLevel {-# UNPACK #-} !Bytes
  | ClientReputationAction {-# UNPACK #-} !Bytes
  | CountWeb {-# UNPACK #-} !Word64
  | DestinationCountry {-# UNPACK #-} !Bytes
  | DestinationInterface {-# UNPACK #-} !Bytes
  | DestinationIp {-# UNPACK #-} !IP
  | DestinationPort {-# UNPACK #-} !Word16
  | Direction {-# UNPACK #-} !Bytes
  | Duration {-# UNPACK #-} !Word64
  | EventType {-# UNPACK #-} !Bytes
  | Hostname {-# UNPACK #-} !Bytes
  | LanIn {-# UNPACK #-} !Word64
  | LanOut {-# UNPACK #-} !Word64
  | Level {-# UNPACK #-} !Bytes
  | Message {-# UNPACK #-} !Bytes
  | Method {-# UNPACK #-} !Bytes
  | PolicyId {-# UNPACK #-} !Word64
  | PolicyType {-# UNPACK #-} !Bytes
  | PolicyUuid {-# UNPACK #-} !Word128
  | Profile {-# UNPACK #-} !Bytes
  | Protocol {-# UNPACK #-} !Word8 -- ^ IANA Internet Protocol Number
  | ReceivedBytes {-# UNPACK #-} !Word64
  | ReceivedPackets {-# UNPACK #-} !Word64
  | RequestType {-# UNPACK #-} !Bytes
  | SentBytes {-# UNPACK #-} !Word64
  | SentPackets {-# UNPACK #-} !Word64
  | Service {-# UNPACK #-} !Bytes
  | SessionId {-# UNPACK #-} !Word64
  | SourceCountry {-# UNPACK #-} !Bytes
  | SourceInterface {-# UNPACK #-} !Bytes
  | SourceIp {-# UNPACK #-} !IP
  | SourcePort {-# UNPACK #-} !Word16
  | TranslatedNone -- ^ When @trandisp@ is @noop@
  | TranslatedSource {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | TranslatedDestination {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | UtmAction {-# UNPACK #-} !Bytes
  | Url {-# UNPACK #-} !Bytes
  | User {-# UNPACK #-} !Bytes
  | VirtualDomain {-# UNPACK #-} !Bytes
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
  deviceName <- unquotedFieldAndSpace InvalidDeviceName
  Latin.char6 ExpectedDeviceId 'd' 'e' 'v' 'i' 'd' '='
  deviceId <- unquotedFieldAndSpace InvalidDeviceId
  Latin.char6 ExpectedLogId 'l' 'o' 'g' 'i' 'd' '='
  logId <- unquotedFieldAndSpace InvalidLogId
  Latin.char5 ExpectedType 't' 'y' 'p' 'e' '='
  type_ <- unquotedFieldAndSpace InvalidType
  Latin.char8 ExpectedSubtype 's' 'u' 'b' 't' 'y' 'p' 'e' '='
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
  2 -> case zequal2 arr off 'v' 'd' of
    0# -> do
      val <- asciiTextField InvalidVirtualDomain
      pure (VirtualDomain val)
    _ -> P.fail UnknownField
  3 -> case G.hashString3 arr off of
    G.H_app -> case zequal3 arr off 'a' 'p' 'p' of
      0# -> do
        val <- asciiTextField InvalidApp
        pure (App val)
      _ -> P.fail UnknownField
    G.H_url -> case zequal3 arr off 'u' 'r' 'l' of
      0# -> do
        val <- asciiTextField InvalidUrl
        pure (Url val)
      _ -> P.fail UnknownField
    G.H_msg -> case zequal3 arr off 'm' 's' 'g' of
      0# -> do
        val <- asciiTextField InvalidMessage
        pure (Message val)
      _ -> P.fail UnknownField
    G.H_cat -> case zequal3 arr off 'c' 'a' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidCategory
        pure (Category val)
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  4 -> case zequal4 arr off 'u' 's' 'e' 'r' of
    0# -> do
      val <- asciiTextField InvalidUser
      pure (User val)
    _ -> P.fail UnknownField
  5 -> case G.hashString5 arr off of
    G.H_wanin -> case zequal5 arr off 'w' 'a' 'n' 'i' 'n' of
      0# -> do
        val <- Latin.decWord64 InvalidWanIn
        pure (WanIn val)
      _ -> P.fail UnknownField
    G.H_lanin -> case zequal5 arr off 'l' 'a' 'n' 'i' 'n' of
      0# -> do
        val <- Latin.decWord64 InvalidLanIn
        pure (LanIn val)
      _ -> P.fail UnknownField
    G.H_srcip -> case zequal5 arr off 's' 'r' 'c' 'i' 'p' of
      0# -> do
        val <- IP.parserUtf8Bytes InvalidSourceIp
        pure (SourceIp val)
      _ -> P.fail UnknownField
    G.H_dstip -> case zequal5 arr off 'd' 's' 't' 'i' 'p' of
      0# -> do
        val <- IP.parserUtf8Bytes InvalidDestinationIp
        pure (DestinationIp val)
      _ -> P.fail UnknownField
    G.H_level -> case zequal5 arr off 'l' 'e' 'v' 'e' 'l' of
      0# -> do
        val <- asciiTextField InvalidLevel
        pure (Level val)
      _ -> P.fail UnknownField
    G.H_proto -> case zequal5 arr off 'p' 'r' 'o' 't' 'o' of
      0# -> do
        val <- Latin.decWord8 InvalidProtocol
        pure (Protocol val)
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  6 -> case G.hashString6 arr off of
    G.H_appcat -> case zequal6 arr off 'a' 'p' 'p' 'c' 'a' 't' of
      0# -> do
        val <- asciiTextField InvalidApplicationCategory
        pure (ApplicationCategory val)
      _ -> P.fail UnknownField
    G.H_action -> case zequal6 arr off 'a' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidAction
        pure (Action val)
      _ -> P.fail UnknownField
    G.H_method -> case zequal6 arr off 'm' 'e' 't' 'h' 'o' 'd' of
      0# -> do
        val <- asciiTextField InvalidMethod
        pure (Method val)
      _ -> P.fail UnknownField
    G.H_wanout -> case zequal6 arr off 'w' 'a' 'n' 'o' 'u' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidWanOut
        pure (WanOut val)
      _ -> P.fail UnknownField
    G.H_lanout -> case zequal6 arr off 'l' 'a' 'n' 'o' 'u' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidLanOut
        pure (LanOut val)
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  7 -> case G.hashString7 arr off of
    G.H_poluuid -> case zequal7 arr off 'p' 'o' 'l' 'u' 'u' 'i' 'd' of
      0# -> do
        -- TODO: this is totally wrong
        _ <- asciiTextField InvalidPolicyUuid
        pure (PolicyUuid 0)
      _ -> P.fail UnknownField
    G.H_reqtype -> case zequal7 arr off 'r' 'e' 'q' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidRequestType
        pure (RequestType val)
      _ -> P.fail UnknownField
    G.H_crscore -> case zequal7 arr off 'c' 'r' 's' 'c' 'o' 'r' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidClientReputationScore
        pure (ClientReputationScore val)
      _ -> P.fail UnknownField
    G.H_crlevel -> case zequal7 arr off 'c' 'r' 'l' 'e' 'v' 'e' 'l' of
      0# -> do
        val <- asciiTextField InvalidClientReputationLevel
        pure (ClientReputationLevel val)
      _ -> P.fail UnknownField
    G.H_catdesc -> case zequal7 arr off 'c' 'a' 't' 'd' 'e' 's' 'c' of
      0# -> do
        val <- asciiTextField InvalidCategoryDescription
        pure (CategoryDescription val)
      _ -> P.fail UnknownField
    G.H_srcintf -> case zequal7 arr off 's' 'r' 'c' 'i' 'n' 't' 'f' of
      0# -> do
        val <- asciiTextField InvalidSourceInterface
        pure (SourceInterface val)
      _ -> P.fail UnknownField
    G.H_dstintf -> case zequal7 arr off 'd' 's' 't' 'i' 'n' 't' 'f' of
      0# -> do
        val <- asciiTextField InvalidDestinationInterface
        pure (DestinationInterface val)
      _ -> P.fail UnknownField
    G.H_srcport -> case zequal7 arr off 's' 'r' 'c' 'p' 'o' 'r' 't' of
      0# -> do
        val <- Latin.decWord16 InvalidSourcePort
        pure (SourcePort val)
      _ -> P.fail UnknownField
    G.H_dstport -> case zequal7 arr off 'd' 's' 't' 'p' 'o' 'r' 't' of
      0# -> do
        val <- Latin.decWord16 InvalidDestinationPort
        pure (DestinationPort val)
      _ -> P.fail UnknownField
    G.H_service -> case zequal7 arr off 's' 'e' 'r' 'v' 'i' 'c' 'e' of
      0# -> do
        val <- asciiTextField InvalidService
        pure (Service val)
      _ -> P.fail UnknownField
    G.H_sentpkt -> case zequal7 arr off 's' 'e' 'n' 't' 'p' 'k' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidSentPackets
        pure (SentPackets val)
      _ -> P.fail UnknownField
    G.H_rcvdpkt -> case zequal7 arr off 'r' 'c' 'v' 'd' 'p' 'k' 't' of
      0# -> do
        val <- Latin.decWord64 InvalidReceivedPackets
        pure (ReceivedPackets val)
      _ -> P.fail UnknownField
    G.H_profile -> case zequal7 arr off 'p' 'r' 'o' 'f' 'i' 'l' 'e' of
      0# -> do
        val <- asciiTextField InvalidProfile
        pure (Profile val)
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  8 -> case G.hashString8 arr off of
    G.H_hostname -> case zequal8 arr off 'h' 'o' 's' 't' 'n' 'a' 'm' 'e' of
      0# -> do
        val <- asciiTextField InvalidHostname
        pure (Hostname val)
      _ -> P.fail UnknownField
    G.H_craction -> case zequal8 arr off 'c' 'r' 'a' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidClientReputationAction
        pure (ClientReputationAction val)
      _ -> P.fail UnknownField
    G.H_policyid -> case zequal8 arr off 'p' 'o' 'l' 'i' 'c' 'y' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidPolicyId
        pure (PolicyId val)
      _ -> P.fail UnknownField
    G.H_duration -> case zequal8 arr off 'd' 'u' 'r' 'a' 't' 'i' 'o' 'n' of
      0# -> do
        val <- Latin.decWord64 InvalidDuration
        pure (Duration val)
      _ -> P.fail UnknownField
    G.H_sentbyte -> case zequal8 arr off 's' 'e' 'n' 't' 'b' 'y' 't' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidSentBytes
        pure (SentBytes val)
      _ -> P.fail UnknownField
    G.H_rcvdbyte -> case zequal8 arr off 'r' 'c' 'v' 'd' 'b' 'y' 't' 'e' of
      0# -> do
        val <- Latin.decWord64 InvalidReceivedBytes
        pure (ReceivedBytes val)
      _ -> P.fail UnknownField
    G.H_countweb -> case zequal8 arr off 'c' 'o' 'u' 'n' 't' 'w' 'e' 'b' of
      0# -> do
        val <- Latin.decWord64 InvalidCountWeb
        pure (CountWeb val)
      _ -> P.fail UnknownField
    G.H_trandisp -> case zequal8 arr off 't' 'r' 'a' 'n' 'd' 'i' 's' 'p' of
      0# -> Latin.any InvalidTranslationDisposition >>= \case
        'n' -> do
          Latin.char3 InvalidTranslationDisposition 'o' 'o' 'p'
          pure TranslatedNone
        'd' -> do
          Latin.char4 InvalidTranslationDisposition 'n' 'a' 't' ' '
          Latin.char7 InvalidTranslationDisposition 't' 'r' 'a' 'n' 'i' 'p' '='
          !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
          Latin.char10 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 'p' 'o' 'r' 't' '='
          !port <- Latin.decWord16 InvalidTranslationPort
          pure (TranslatedDestination ip port)
        's' -> do
          Latin.char4 InvalidTranslationDisposition 'n' 'a' 't' ' '
          Latin.char8 InvalidTranslationDisposition 't' 'r' 'a' 'n' 's' 'i' 'p' '='
          !ip <- IPv4.parserUtf8Bytes InvalidTranslationIp
          Latin.char11 InvalidTranslationDisposition ' ' 't' 'r' 'a' 'n' 's' 'p' 'o' 'r' 't' '='
          !port <- Latin.decWord16 InvalidTranslationPort
          pure (TranslatedSource ip port)
        _ -> P.fail InvalidTranslationDisposition
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  9 -> case G.hashString9 arr off of
    G.H_sessionid -> case zequal9 arr off 's' 'e' 's' 's' 'i' 'o' 'n' 'i' 'd' of
      0# -> do
        val <- Latin.decWord64 InvalidSessionId
        pure (SessionId val)
      _ -> P.fail UnknownField
    G.H_eventtype -> case zequal9 arr off 'e' 'v' 'e' 'n' 't' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidEventType
        pure (EventType val)
      _ -> P.fail UnknownField
    G.H_utmaction -> case zequal9 arr off 'u' 't' 'm' 'a' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidUtmAction
        pure (UtmAction val)
      _ -> P.fail UnknownField
    G.H_direction -> case zequal9 arr off 'd' 'i' 'r' 'e' 'c' 't' 'i' 'o' 'n' of
      0# -> do
        val <- asciiTextField InvalidDirection
        pure (Direction val)
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  10 -> case G.hashString10 arr off of
    G.H_srccountry -> case zequal10 arr off 's' 'r' 'c' 'c' 'o' 'u' 'n' 't' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidSourceCountry
        pure (SourceCountry val)
      _ -> P.fail UnknownField
    G.H_dstcountry -> case zequal10 arr off 'd' 's' 't' 'c' 'o' 'u' 'n' 't' 'r' 'y' of
      0# -> do
        val <- asciiTextField InvalidDestinationCountry
        pure (DestinationCountry val)
      _ -> P.fail UnknownField
    G.H_policytype -> case zequal10 arr off 'p' 'o' 'l' 'i' 'c' 'y' 't' 'y' 'p' 'e' of
      0# -> do
        val <- asciiTextField InvalidPolicyType
        pure (PolicyType val)
      _ -> P.fail UnknownField
    _ -> P.fail UnknownField
  _ -> P.fail UnknownField
  where
  !(Bytes arr off len) = b

unquotedFieldAndSpace :: e -> Parser e s Bytes
unquotedFieldAndSpace e = P.takeTrailedBy e (c2w ' ')


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

c2w :: Char -> Word8
c2w = fromIntegral . ord

-- Returns zero when the characters are equal
zeqChar# :: Char# -> Char# -> Int#
zeqChar# c1 c2 = xorI# (ord# c1) (ord# c2)

