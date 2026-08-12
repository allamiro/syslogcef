# ArcSight CEF Fields

The following tables list the CEF key names defined for event producers and
consumers. They are derived from the ArcSight Extension Dictionary.

## Notes from the specification

- **Producers vs. consumers**: the keys in the Event Consumers table are
  set by the receiving side (ArcSight connectors) and *must not be set by
  event producers*. Producers wanting to carry such data use the custom
  fields with a label (e.g. `cs1` + `cs1Label`), as syslog2cef's bundled
  mappings do for the raw event text.
- **Version differences**: in CEF 0.1, `in`/`out` (bytesIn/bytesOut) are
  Integer and all IP address fields are IPv4-only; from CEF 1.0 onward
  they accept Long values and IPv6 addresses respectively. Note the
  `CEF:0` wire prefix does not by itself select a dictionary version —
  integrations on the 1.x dictionary still emit `CEF:0` headers.
  syslog2cef *chooses* to validate against the conservative rules for
  broadest consumer compatibility: `--validate`/`--strict` enforce the
  0.x IP rule (IPv6 belongs in `c6a1`–`c6a4`) while accepting Long for
  `in`/`out`, matching what validation.py implements.
- **Wire format**: header fields are separated by `|` and ordered
  `CEF:version|vendor|product|deviceVersion|eventClassId|name|severity|`
  followed by space-separated `key=value` extensions. When sending
  events, only the short CEF key name is valid — using the full name
  fails.

Sample record (Symantec Threat Isolation, abridged):

```text
CEF:0|Symantec|Threat Isolation|1.0|Network Request|Network Request|6|rt=Jun 03 2018 12:40:48 src=10.0.80.80 dst=80.249.99.148 dpt=80 request=https://usermatch.krxd.net/um/v2?partner\=vdna requestMethod=GET app=http act=Isolate dvchost=fireglass1 cn2=200 cn2Label=Response Status Code cs4=Technology/Internet cs4Label=URL Categories
```

## Event Producers

| CEF Version | Key | Full Name | Data Type | Length | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0.1 | act | deviceAction | String | 63 | Action taken by the device. |
| 0.1 | app | applicationProtocol | String | 31 | Application layer protocol such as HTTP, HTTPS, SSHv2, Telnet, POP, IMAP, etc. |
| 0.1 | c6a1 | deviceCustomIPv6Address1 | IPv6 address |  | Custom IPv6 address field 1. |
| 0.1 | c6a1Label | deviceCustomIPv6Address1Label | String | 1023 | Label describing deviceCustomIPv6Address1. |
| 0.1 | c6a3 | deviceCustomIPv6Address3 | IPv6 address |  | Custom IPv6 address field 3. |
| 0.1 | c6a3Label | deviceCustomIPv6Address3Label | String | 1023 | Label describing deviceCustomIPv6Address3. |
| 0.1 | c6a4 | deviceCustomIPv6Address4 | IPv6 address |  | Custom IPv6 address field 4. |
| 0.1 | c6a4Label | deviceCustomIPv6Address4Label | String | 1023 | Label describing deviceCustomIPv6Address4. |
| 0.1 | cat | deviceEventCategory | String | 1023 | Category assigned by the originating device. |
| 0.1 | cfp1 | deviceCustomFloatingPoint1 | Floating point |  | Custom floating point field 1. |
| 0.1 | cfp1Label | deviceCustomFloatingPoint1Label | String | 1023 | Label describing deviceCustomFloatingPoint1. |
| 0.1 | cfp2 | deviceCustomFloatingPoint2 | Floating point |  | Custom floating point field 2. |
| 0.1 | cfp2Label | deviceCustomFloatingPoint2Label | String | 1023 | Label describing deviceCustomFloatingPoint2. |
| 0.1 | cfp3 | deviceCustomFloatingPoint3 | Floating point |  | Custom floating point field 3. |
| 0.1 | cfp3Label | deviceCustomFloatingPoint3Label | String | 1023 | Label describing deviceCustomFloatingPoint3. |
| 0.1 | cfp4 | deviceCustomFloatingPoint4 | Floating point |  | Custom floating point field 4. |
| 0.1 | cfp4Label | deviceCustomFloatingPoint4Label | String | 1023 | Label describing deviceCustomFloatingPoint4. |
| 0.1 | cn1 | deviceCustomNumber1 | Long |  | Custom number field 1. |
| 0.1 | cn1Label | deviceCustomNumber1Label | String | 1023 | Label describing deviceCustomNumber1. |
| 0.1 | cn2 | deviceCustomNumber2 | Long |  | Custom number field 2. |
| 0.1 | cn2Label | deviceCustomNumber2Label | String | 1023 | Label describing deviceCustomNumber2. |
| 0.1 | cn3 | deviceCustomNumber3 | Long |  | Custom number field 3. |
| 0.1 | cn3Label | deviceCustomNumber3Label | String | 1023 | Label describing deviceCustomNumber3. |
| 0.1 | cnt | baseEventCount | Integer |  | Event count (omit if 1). |
| 0.1 | cs1 | deviceCustomString1 | String | 4000 | Custom string field 1. |
| 0.1 | cs1Label | deviceCustomString1Label | String | 1023 | Label describing deviceCustomString1. |
| 0.1 | cs2 | deviceCustomString2 | String | 4000 | Custom string field 2. |
| 0.1 | cs2Label | deviceCustomString2Label | String | 1023 | Label describing deviceCustomString2. |
| 0.1 | cs3 | deviceCustomString3 | String | 4000 | Custom string field 3. |
| 0.1 | cs3Label | deviceCustomString3Label | String | 1023 | Label describing deviceCustomString3. |
| 0.1 | cs4 | deviceCustomString4 | String | 4000 | Custom string field 4. |
| 0.1 | cs4Label | deviceCustomString4Label | String | 1023 | Label describing deviceCustomString4. |
| 0.1 | cs5 | deviceCustomString5 | String | 4000 | Custom string field 5. |
| 0.1 | cs5Label | deviceCustomString5Label | String | 1023 | Label describing deviceCustomString5. |
| 0.1 | cs6 | deviceCustomString6 | String | 4000 | Custom string field 6. |
| 0.1 | cs6Label | deviceCustomString6Label | String | 1023 | Label describing deviceCustomString6. |
| 0.1 | destinationDnsDomain | destinationDnsDomain | String | 255 | Destination DNS domain. |
| 0.1 | destinationServiceName | destinationServiceName | String | 1023 | Destination service name. |
| 0.1 | destinationTranslatedAddress | destinationTranslatedAddress | IPv4 address |  | Translated destination IP address. |
| 0.1 | destinationTranslatedPort | destinationTranslatedPort | Integer |  | Translated destination port. |
| 0.1 | deviceCustomDate1 | deviceCustomDate1 | Timestamp |  | Custom timestamp field 1. |
| 0.1 | deviceCustomDate1Label | deviceCustomDate1Label | String | 1023 | Label describing deviceCustomDate1. |
| 0.1 | deviceCustomDate2 | deviceCustomDate2 | Timestamp |  | Custom timestamp field 2. |
| 0.1 | deviceCustomDate2Label | deviceCustomDate2Label | String | 1023 | Label describing deviceCustomDate2. |
| 0.1 | deviceDirection | deviceDirection | Integer |  | Communication direction (0 inbound, 1 outbound). |
| 0.1 | deviceDnsDomain | deviceDnsDomain | String | 255 | Device DNS domain. |
| 0.1 | deviceExternalId | deviceExternalId | String | 255 | Unique device identifier. |
| 0.1 | deviceFacility | deviceFacility | String | 1023 | Device facility (e.g., syslog facility). |
| 0.1 | deviceInboundInterface | deviceInboundInterface | String | 128 | Inbound interface. |
| 0.1 | deviceNtDomain | deviceNtDomain | String | 255 | Windows domain of the device. |
| 0.1 | deviceOutboundInterface | deviceOutboundInterface | String | 128 | Outbound interface. |
| 0.1 | devicePayloadId | devicePayloadId | String | 128 | Payload identifier. |
| 0.1 | deviceProcessName | deviceProcessName | String | 1023 | Device process name. |
| 0.1 | deviceTranslatedAddress | deviceTranslatedAddress | IPv4 address |  | Translated device IP address. |
| 0.1 | dhost | destinationHostName | String | 1023 | Destination host (FQDN if possible). |
| 0.1 | dmac | deviceMacAddress | MAC address |  | Device MAC address. |
| 0.1 | dntdom | destinationNtDomain | String | 255 | Destination Windows domain. |
| 0.1 | dpid | destinationProcessId | Integer |  | Destination process ID. |
| 0.1 | dpriv | destinationUserPrivileges | String | 1023 | Destination user privileges. |
| 0.1 | dproc | destinationProcessName | String | 1023 | Destination process name. |
| 0.1 | dpt | destinationPort | Integer |  | Destination port. |
| 0.1 | dst | destinationAddress | IPv4 address |  | Destination IP address. |
| 0.1 | dtz | deviceTimeZone | String | 255 | Device time zone. |
| 0.1 | duid | destinationUserId | String | 1023 | Destination user ID. |
| 0.1 | duser | destinationUserName | String | 1023 | Destination user name. |
| 0.1 | dvc | deviceAddress | IPv4 address |  | Device IP address. |
| 0.1 | dvchost | deviceHostName | String | 100 | Device host name. |
| 0.1 | dvcpid | deviceProcessId | Integer |  | Device process ID. |
| 0.1 | end | endTime | Timestamp |  | Time when the activity ended. |
| 0.1 | externalId | externalId | String | 40 | Originating device event ID. |
| 0.1 | fileCreateTime | fileCreateTime | Timestamp |  | File creation time. |
| 0.1 | fileHash | fileHash | String | 255 | File hash. |
| 0.1 | fileId | fileId | String | 1023 | File identifier (e.g., inode). |
| 0.1 | fileModificationTime | fileModificationTime | Timestamp |  | File modification time. |
| 0.1 | filePath | filePath | String | 1023 | Full file path. |
| 0.1 | filePermission | filePermission | String | 1023 | File permissions. |
| 0.1 | fileType | fileType | String | 1023 | File type (pipe, socket, etc.). |
| 0.1 | flexDate1 | flexDate1 | Timestamp |  | Flexible timestamp field 1. |
| 0.1 | flexDate1Label | flexDate1Label | String | 128 | Label describing flexDate1. |
| 0.1 | flexString1 | flexString1 | String | 1023 | Flexible string field 1. |
| 0.1 | flexString1Label | flexString1Label | String | 128 | Label describing flexString1. |
| 0.1 | flexString2 | flexString2 | String | 1023 | Flexible string field 2. |
| 0.1 | flexString2Label | flexString2Label | String | 128 | Label describing flexString2. |
| 0.1 | fname | filename | String | 1023 | File name (without path). |
| 0.1 | fsize | fileSize | Integer |  | File size. |
| 0.1 | in | bytesIn | Integer/Long |  | Bytes transferred inbound. |
| 0.1 | msg | message | String | 1023 | Additional message text. |
| 0.1 | oldFileCreateTime | oldFileCreateTime | Timestamp |  | Creation time of the old file. |
| 0.1 | oldFileHash | oldFileHash | String | 255 | Hash of the old file. |
| 0.1 | oldFileId | oldFileId | String | 1023 | Identifier of the old file. |
| 0.1 | oldFileModificationTime | oldFileModificationTime | Timestamp |  | Modification time of the old file. |
| 0.1 | oldFileName | oldFileName | String | 1023 | Old file name. |
| 0.1 | oldFilePath | oldFilePath | String | 1023 | Old file path. |
| 0.1 | oldFilePermission | oldFilePermission | String | 1023 | Permissions of the old file. |
| 0.1 | oldFileSize | oldFileSize | Integer |  | Size of the old file. |
| 0.1 | oldFileType | oldFileType | String | 1023 | Type of the old file. |
| 0.1 | out | bytesOut | Integer/Long |  | Bytes transferred outbound. |
| 0.1 | outcome | eventOutcome | String | 63 | Outcome such as success or failure. |
| 0.1 | proto | transportProtocol | String | 31 | Layer-4 protocol (TCP, UDP, etc.). |
| 0.1 | reason | Reason | String | 1023 | Reason the audit event was generated. |
| 0.1 | request | requestUrl | String | 1023 | Requested URL including protocol. |
| 0.1 | requestClientApplication | requestClientApplication | String | 1023 | User agent. |
| 0.1 | requestContext | requestContext | String | 2048 | Request context (e.g., HTTP referrer). |
| 0.1 | requestCookies | requestCookies | String | 1023 | Cookies associated with the request. |
| 0.1 | requestMethod | requestMethod | String | 1023 | HTTP method used (GET, POST, etc.). |
| 0.1 | rt | deviceReceiptTime | Timestamp |  | Time the device received the event. |
| 0.1 | shost | sourceHostName | String | 1023 | Source host (FQDN if possible). |
| 0.1 | smac | sourceMacAddress | MAC address |  | Source MAC address. |
| 0.1 | sntdom | sourceNtDomain | String | 255 | Source Windows domain. |
| 0.1 | sourceDnsDomain | sourceDnsDomain | String | 255 | Source DNS domain. |
| 0.1 | sourceServiceName | sourceServiceName | String | 1023 | Service responsible for generating the event. |
| 0.1 | sourceTranslatedAddress | sourceTranslatedAddress | IPv4 address |  | Translated source IP address. |
| 0.1 | sourceTranslatedPort | sourceTranslatedPort | Integer |  | Translated source port. |
| 0.1 | spid | sourceProcessId | Integer |  | Source process ID. |
| 0.1 | spriv | sourceUserPrivileges | String | 1023 | Source user privileges. |
| 0.1 | sproc | sourceProcessName | String | 1023 | Source process name. |
| 0.1 | spt | sourcePort | Integer |  | Source port. |
| 0.1 | src | sourceAddress | IPv4 address |  | Source IP address. |
| 0.1 | start | startTime | Timestamp |  | Activity start time. |
| 0.1 | suid | sourceUserId | String | 1023 | Source user ID. |
| 0.1 | suser | sourceUserName | String | 1023 | Source user name. |
| 0.1 | type | type | Integer |  | Event type (0 base, 1 aggregated, 2 correlation, 3 action). |
| 1.2 | agentTranslatedZoneKey | Agent Translated Zone Key | Integer (64-bit) |  | ID of an agentTranslatedZone reference. |
| 1.2 | agentZoneKey | Agent Zone Key | Integer (64-bit) |  | ID of an agentZone reference. |
| 1.2 | customerKey | Customer Key | Integer (64-bit) |  | ID of a customer reference. |
| 1.2 | dTranslatedZoneKey | Destination Translated Zone Key | Integer (64-bit) |  | ID of a destinationTranslatedZone reference. |
| 1.2 | dZoneKey | Destination Zone Key | Integer (64-bit) |  | ID of a destinationZone reference. |
| 1.2 | deviceTranslatedZoneKey | Device Translated Zone Key | Integer (64-bit) |  | ID of a deviceTranslatedZone reference. |
| 1.2 | deviceZoneKey | Device Zone Key | Integer (64-bit) |  | ID of a deviceZone reference. |
| 1.2 | sTranslatedZoneKey | Source Translated Zone Key | Integer (64-bit) |  | ID of a sourceTranslatedZone reference. |
| 1.2 | sZoneKey | Source Zone Key | Integer (64-bit) |  | ID of a sourceZone reference. |
| 1.2 | reportedDuration | Reported Duration | String (64-bit signed) |  | Duration in milliseconds. |
| 1.2 | reportedResourceGroupName | Reported Resource Group Name | String | 128 | Resource group name. |
| 1.2 | reportedResourceID | Reported Resource ID | String | 256 | Resource ID. |
| 1.2 | reportedResourceName | Reported Resource Name | String | 64 | Resource name. |
| 1.2 | reportedResourceType | Reported Resource Type | String | 64 | Resource type. |
| 1.2 | frameworkName | Framework Name | String | 256 | Name of the framework used for threatAttackID. |
| 1.2 | threatActor | Threat Actor | String | 40 | Associated threat actor. |
| 1.2 | threatAttackID | Threat Attack ID | String | 32 | Threat/attack identifier in the referenced framework. |

## Event Consumers

| CEF Version | Key | Full Name | Data Type | Length | Meaning |
| --- | --- | --- | --- | --- | --- |
| 0.1 | agentDnsDomain | agentDnsDomain | String | 255 | DNS domain of the ArcSight connector. |
| 0.1 | agentNtDomain | agentNtDomain | String | 255 | Windows domain of the ArcSight connector. |
| 0.1 | agentTranslatedAddress | agentTranslatedAddress | IP address |  | Translated address of the ArcSight connector. |
| 0.1 | agentTranslatedZoneExternalID | agentTranslatedZoneExternalID | String | 200 | External ID of the agent translated zone. |
| 0.1 | agentTranslatedZoneURI | agentTranslatedZoneURI | String | 2048 | URI of the agent translated zone. |
| 0.1 | agentZoneExternalID | agentZoneExternalID | String | 200 | External ID of the agent zone. |
| 0.1 | agentZoneURI | agentZoneURI | String | 2048 | URI of the agent zone. |
| 0.1 | agt | agentAddress | IP address |  | IP address of the ArcSight connector. |
| 0.1 | ahost | agentHostName | String | 1023 | Host name of the ArcSight connector. |
| 0.1 | aid | agentId | String | 40 | Identifier of the ArcSight connector. |
| 0.1 | amac | agentMacAddress | MAC address |  | MAC address of the ArcSight connector. |
| 0.1 | art | agentReceiptTime | Timestamp |  | Time ArcSight connector received the event. |
| 0.1 | at | agentType | String | 63 | Type of the ArcSight connector. |
| 0.1 | atz | agentTimeZone | String | 255 | Time zone of the ArcSight connector. |
| 0.1 | av | agentVersion | String | 31 | Version of the ArcSight connector. |
| 0.1 | customerExternalID | customerExternalID | String | 200 | Customer external ID. |
| 0.1 | customerURI | customerURI | String | 2048 | Customer URI. |
| 0.1 | destinationTranslatedZoneExternalID | destinationTranslatedZoneExternalID | String | 200 | External ID of the destination translated zone. |
| 0.1 | destinationTranslatedZoneURI | destinationTranslatedZoneURI | String | 2048 | URI of the destination translated zone. |
| 0.1 | destinationZoneExternalID | destinationZoneExternalID | String | 200 | Destination zone external ID. |
| 0.1 | destinationZoneURI | destinationZoneURI | String | 2048 | Destination zone URI. |
| 0.1 | deviceTranslatedZoneExternalID | deviceTranslatedZoneExternalID | String | 200 | Device translated zone external ID. |
| 0.1 | deviceTranslatedZoneURI | deviceTranslatedZoneURI | String | 2048 | Device translated zone URI. |
| 0.1 | deviceZoneExternalID | deviceZoneExternalID | String | 200 | Device zone external ID. |
| 0.1 | deviceZoneURI | deviceZoneURI | String | 2048 | Device zone URI. |
| 0.1 | dlat | destinationGeoLatitude | Double |  | Latitude of the destination IP. |
| 0.1 | dlong | destinationGeoLongitude | Double |  | Longitude of the destination IP. |
| 0.1 | eventId | eventId | Long |  | ArcSight-assigned unique event ID. |
| 0.1 | rawEvent | rawEvent | String | 4000 | Raw event payload. |
| 0.1 | slat | sourceGeoLatitude | Double |  | Latitude of the source IP. |
| 0.1 | slong | sourceGeoLongitude | Double |  | Longitude of the source IP. |
| 0.1 | sourceTranslatedZoneExternalID | sourceTranslatedZoneExternalID | String | 200 | External ID of the source translated zone. |
| 0.1 | sourceTranslatedZoneURI | sourceTranslatedZoneURI | String | 2048 | URI of the source translated zone. |
| 0.1 | sourceZoneExternalID | sourceZoneExternalID | String | 200 | Source zone external ID. |
| 0.1 | sourceZoneURI | sourceZoneURI | String | 2048 | Source zone URI. |
| 1.2 | agentTranslatedZoneKey | Agent Translated Zone Key | Integer (64-bit) |  | ID of an agentTranslatedZone reference. |
| 1.2 | agentZoneKey | Agent Zone Key | Integer (64-bit) |  | ID of an agentZone reference. |
| 1.2 | customerKey | Customer Key | Integer (64-bit) |  | ID of a customer reference. |
| 1.2 | dTranslatedZoneKey | Destination Translated Zone Key | Integer (64-bit) |  | ID of a destinationTranslatedZone reference. |
| 1.2 | dZoneKey | Destination Zone Key | Integer (64-bit) |  | ID of a destinationZone reference. |
| 1.2 | deviceTranslatedZoneKey | Device Translated Zone Key | Integer (64-bit) |  | ID of a deviceTranslatedZone reference. |
| 1.2 | deviceZoneKey | Device Zone Key | Integer (64-bit) |  | ID of a deviceZone reference. |
| 1.2 | sTranslatedZoneKey | Source Translated Zone Key | Integer (64-bit) |  | ID of a sourceTranslatedZone reference. |
| 1.2 | sZoneKey | Source Zone Key | Integer (64-bit) |  | ID of a sourceZone reference. |
| 1.2 | reportedDuration | Reported Duration | String (64-bit signed) |  | Duration in milliseconds. |
| 1.2 | reportedResourceGroupName | Reported Resource Group Name | String | 128 | Resource group name. |
| 1.2 | reportedResourceID | Reported Resource ID | String | 256 | Resource identifier. |
| 1.2 | reportedResourceName | Reported Resource Name | String | 64 | Resource name. |
| 1.2 | reportedResourceType | Reported Resource Type | String | 64 | Resource type. |
| 1.2 | frameworkName | Framework Name | String | 256 | Framework name for threatAttackID. |
| 1.2 | threatActor | Threat actor | String | 40 | Associated threat actor. |
| 1.2 | threatAttackID | Threat Attack ID | String | 32 | Threat/attack identifier. |
