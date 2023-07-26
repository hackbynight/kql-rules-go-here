# kql-rules-go-here

OfficeHome

```kql
// Sentinel KQL rule: Strange User Behavior; OfficeHome sign-ons upon corporate environment AAD
// Author: @hackbynight
// Date: May 16 2023
// Description: 
// This rule first collects OfficeHome sign-ins from the past 14 days. In the main query, 
// it selects only the alerts where the AppDisplayName is "OfficeHome". Then it performs 
// an anti join with the OfficeHomeSignIns table, which effectively filters out users who 
// have signed in with OfficeHome in the last 14 days. The result should be a table of alerts 
// for users who are signing into OfficeHome for the first time in the past 14 days.

let timeframe_start = ago(14d);
let finder = (workspace('###').SigninLogs
    | where UserPrincipalName contains "@"
    | summarize UserId = any(UserId) by UserPrincipalName
    | project UserId, UserPrincipalName);
let App1 = workspace('###').SigninLogs
    | summarize AppDisplayName = any(AppDisplayName) by Id
    | project Id, AppDisplayName;
let OfficeHomeSignIns = workspace('###').SigninLogs
    | where AppDisplayName == "OfficeHome"
    | where TimeGenerated >= timeframe_start
    | summarize by UserPrincipalName;
workspace('###').SigninLogs
| where TimeGenerated > timeframe_start
| join kind=leftouter finder on $left.UserId == $right.UserId
| join kind=leftouter App1 on $left.Id == $right.Id
| where AppDisplayName == "OfficeHome"
| join kind=anti OfficeHomeSignIns on $left.UserPrincipalName == $right.UserPrincipalName
| summarize
    TimeGenerated = any(TimeGenerated),
    UserPrincipalName = any(UserPrincipalName),
    AppDisplayName = any(AppDisplayName),
    UserAgent = any(UserAgent) 
    by Id
```



OneNote

```kql
// Sentinel KQL rule: Strange User Behavior; OneNote Files as Attachments
// Author: @hackbynight
// Date: February 12 2023
// Description: 
//   This rule is designed to track OneNote files (.one) that are found as attachments in email events. 
//   The rule filters out email events that are outbound and have at least one attachment. 
//   The result of the rule is a table that displays information such as; 
//   The recipient email address, sender email address, sender IP addresses, sender domain, delivery action, delivery location, and attachment count.
//
//
// 1. Filter the OfficeActivity data to only include records with the type "Exchange" and the file extension ".one"
// 2. Extract the OneNote file names from the Item column
// 3. Filter the data to only include records where the operation is "Create"
// 4. Convert the Item column to a dynamic type
// 5. Extract the mutual (parent folder ID) from the Item column
// 6. Project the Mutual and ResultStatus columns
// 7. Join the filtered OfficeActivity data with the EmailEvents data that has at least one attachment and is not an outbound email
// 8. Extract the mutual (InternetMessageId) from the EmailEvents data
// 9. Project relevant columns from the joined data

OfficeActivity
| where RecordType contains "Exchange"
| where Item contains ".one"
| extend OneNoteFiles = extract_all(@"(\w+)\.one", Item)
| where OneNoteFiles != ""
| where Operation contains "Create"
| extend todynamic(Item)
| extend Mutual = tostring(Item.ParentFolder.Id)
| project Mutual, ResultStatus
| join (
    EmailEvents
    | where AttachmentCount > 0
    | where EmailDirection !contains "Outbound"

    // Can filter out "Intra-org" as well if needed, thereby only looking at "Inbound" (from external users)
    //| where EmailDirection contains "Inbound"
    
    | extend Mutual = tostring(InternetMessageId)
    // Project relevant columns from the EmailEvents data
    | project TimeGenerated, Mutual, RecipientEmailAddress, SenderMailFromAddress, SenderIPv4, SenderIPv6, SenderMailFromDomain, DeliveryAction, DeliveryLocation, AttachmentCount
) on Mutual
| project TimeGenerated, RecipientEmailAddress, SenderMailFromAddress, SenderIPv4, SenderIPv6, SenderMailFromDomain, DeliveryAction, DeliveryLocation, AttachmentCount

//
//
```

``` KQL
// Title: Threat Intelligence Indicator Match with Azure Activities
// ID: 
// Description: This alert identifies a match in the AzureActivity table from any IP IOC retrieved from Threat Intelligence. The severity of the alert is High because a hit would imply a potential malicious activity.
// Severity: High
// Tactics: Initial Access
// Techniques: T1190 - Exploit Public-Facing Application
// Last modified date: 2023-07-12
// QueryFrequency: PT1H
// QueryPeriod: PT14D
// GroupingConfiguration-enabled: True
// Group-lookbackDuration: PT1H

let dt_lookBack = 1d;
let ioc_lookBack = 14d;
let min_ConfidenceScore = 75; // Adjust as needed
workspace('workspace_id').ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true and ConfidenceScore >= min_ConfidenceScore
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| extend IPIOC = iff(isnotempty(NetworkIP),NetworkIP,"")
| extend IPIOC = iff(isnotempty(NetworkSourceIP),NetworkSourceIP,IPIOC)
| extend IPIOC = iff(isnotempty(NetworkDestinationIP),NetworkDestinationIP,IPIOC)
| where isnotempty(IPIOC)
| join kind=innerunique (
workspace('workspace_id').AzureActivity
| where TimeGenerated >= ago(dt_lookBack) and isnotempty(CallerIpAddress)
| extend AzureActivity_TimeGenerated = TimeGenerated
) on $left.IPIOC == $right.CallerIpAddress
| where AzureActivity_TimeGenerated < ExpirationDateTime
| summarize AzureActivity_TimeGenerated = arg_max(AzureActivity_TimeGenerated, *) by IndicatorId, OperationName
| project AzureActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, OperationName, Caller, CallerIpAddress, Resource, SubscriptionId, ResourceProvider
| extend timestamp = AzureActivity_TimeGenerated

```
