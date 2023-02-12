# kql-rules-go-here

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
