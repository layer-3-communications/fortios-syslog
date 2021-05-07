# fortios-syslog

### Overview
This repository is a parser for Fortinet Syslogs. 

Data Log
```sh
 { date :: {-# UNPACK #-} !Date
  , time :: {-# UNPACK #-} !TimeOfDay
  , deviceName :: {-# UNPACK #-} !Bytes
  , deviceId :: {-# UNPACK #-} !Bytes
  , logId :: {-# UNPACK #-} !Bytes
  , type_ :: {-# UNPACK #-} !Bytes
  , subtype :: {-# UNPACK #-} !Bytes
  , fields :: !(Chunks Field)
```


Data Attributes
```sh
= Action {-# UNPACK #-} !Bytes
  | Alert {-# UNPACK #-} !Word64
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
  | CountIps {-# UNPACK #-} !Word64
    -- ^ Number of the IPS logs associated with the session
  | ClientReputationScore {-# UNPACK #-} !Word64
  | ClientReputationLevel {-# UNPACK #-} !Bytes
  | ClientReputationAction {-# UNPACK #-} !Bytes
  | CountApplication {-# UNPACK #-} !Word64
    -- ^ Number of App Ctrl logs associated with the session.
  | CountWeb {-# UNPACK #-} !Word64
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
  | DestinationServer {-# UNPACK #-} !Word64
  | DestinationUuid {-# UNPACK #-} !Word128
  | DeviceCategory {-# UNPACK #-} !Bytes
  | DeviceType {-# UNPACK #-} !Bytes
  | DhcpMessage {-# UNPACK #-} !Bytes
  | Direction {-# UNPACK #-} !Bytes
  | Duration {-# UNPACK #-} !Word64
  | Error {-# UNPACK #-} !Bytes
  | EventTime {-# UNPACK #-} !Word64
  | EventType {-# UNPACK #-} !Bytes
  | Group {-# UNPACK #-} !Bytes
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
  | Mac {-# UNPACK #-} !Net.Types.Mac
  | MasterDestinationMac {-# UNPACK #-} !Net.Types.Mac
  | MasterSourceMac {-# UNPACK #-} !Net.Types.Mac
  | Message {-# UNPACK #-} !Bytes
  | Method {-# UNPACK #-} !Bytes
  | NextStatistics {-# UNPACK #-} !Word64
  | OsName {-# UNPACK #-} !Bytes
  | OsVersion {-# UNPACK #-} !Bytes
  | PolicyId {-# UNPACK #-} !Word64
  | PolicyType {-# UNPACK #-} !Bytes
  | PolicyUuid {-# UNPACK #-} !Word128
  | Profile {-# UNPACK #-} !Bytes
  | ProfileType {-# UNPACK #-} !Bytes
  | Protocol {-# UNPACK #-} !Word8
  | QueryClass {-# UNPACK #-} !Bytes
  | QueryName {-# UNPACK #-} !Bytes
  | QueryType {-# UNPACK #-} !Bytes
  | QueryTypeValue {-# UNPACK #-} !Word64
    -- ^ IANA Internet Protocol Number.
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
  | SourceServer {-# UNPACK #-} !Word64
  | SourceSoftwareVersion {-# UNPACK #-} !Bytes
  | SourceUuid {-# UNPACK #-} !Word128
  | SslAction {-# UNPACK #-} !Bytes
  | SslCertificateCommonName {-# UNPACK #-} !Bytes
  | SslCertificateIssuer {-# UNPACK #-} !Bytes
  | TimeZone {-# UNPACK #-} !Int -- ^ Offset from UTC in minutes
  | TransactionId {-# UNPACK #-} !Word64 -- ^ Field is named @xid@.
  | TranslatedSource {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | TranslatedDestination {-# UNPACK #-} !IPv4 {-# UNPACK #-} !Word16 -- ^ When @trandisp@ is @snat@
  | TunnelId {-# UNPACK #-} !Word64
  | TunnelIp {-# UNPACK #-} !IP
  | TunnelType {-# UNPACK #-} !Bytes
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
  | VirtualWanLinkQuality {-# UNPACK #-} !Bytes
  | Vpn {-# UNPACK #-} !Bytes
  | VpnType {-# UNPACK #-} !Bytes
  | WanIn {-# UNPACK #-} !Word64
  | WanOut {-# UNPACK #-} !Word64
```