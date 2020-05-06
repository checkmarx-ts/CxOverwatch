# CxHealthMonitor - Functionality
The CxHealthMonitor is written in PowerShell and is designed to be modular. Additional functionality can be written and added as needed.

> **Note : Supported Alerting Systems** The CxHealthMonitor supports the following systems:
> - SMTP (Email)
> - Syslog (Ex. Splunk, Kiwi, AlienVault, any SIEM system that accepts Syslog sources)
> - Slack
> - Event Logging 	(the monitor writes to the Console, a general log file and structured event data to an events file - to feed into 3rd
> party log aggregator products) Additional alerting systems (such as
> SNMP) can be written and plugged in if required.

 

## Queue Monitoring
The monitor evaluates the states of scans currently in the queue. There are two primary conditions it looks for:
-   Queue flooding - Excessive number of scans in the queue
-   Scans that remains in the 'Queued' state for prolonged periods

### Too many scans in queue
Alerts are generated when the number of scans in the queue exceed a configurable threshold.

Example alert/event:
>`9/9/2019 11:22:58 PM: TOO_MANY_SCANS_IN_QUEUE : Queued: [6]. Threshold: [5]`

### Scans stuck in queue for a long time
Alerts are generated when scans remain in the queue beyond a configurable number of minutes.

Example alert/event:
>`9/10/2019 1:55:10 PM: SCAN_TOO_LONG_IN_QUEUE : Scan [1000198, Spectrum (ReactJS), Full, SourcePullingAndDeployment]. Queued: [00:21:56.1022174]. Threshold: [00:20:00]`

## Scan Monitoring
The monitor evaluates the states of running scans. It publishes alerts for the following:
-   Slow running scans
-   Scan failures

### Slow running scans
The monitor generates alerts for Scans that exceed an estimated duration. 

The algorithm that calculates the duration estimate is swappable - and can be swapped out when more complex algorithms are developed.

The current algorithm  estimates the duration of a given scan by one of two methods:

 - LOC (lines of code) based
 - Previous run duration + configurable buffer time

Example alert/event:
>`8/5/2019 10:21:02 AM: SLOW_SCAN : Scan [1000193, Calypso, Full, Scanning] Elapsed: [06:18:21.9170000]. Threshold: duration [05:45:13.2770000]`

### Scan failures
The monitor publishes an alert when a scan fails. Scan failure alerts will generally include a reason for the scan failure.

Example alerts/events:
>`9/6/2019 1:04:41 PM: SCAN_FAILED : Scan [1000237, cxmon-develop, Full, Failed] (Reason: Git clone failed: repository 'https://76eac6906c989f5eabbc0f331ebcef9c9c4129a4@github.com/gemgit7/cxmon.git/' not found`

>`8/5/2019 6:03:34 PM: SCAN_FAILED : Scan [1000198, Spectrum (ReactJS), Full, Failed] (Reason: Scan failed due to insufficient memory. Engine server has a total 24414 MB out of which only 0 MB are free. To scan project of 96186 lines of code engine requires 384 MB of free memory. Please consider adding more RAM, reducing code size or closing running processes.)`

## Engine Monitoring
The monitor evaluates the health of all registered engines and generates alerts for the following:

- Slow response
- Offline engine

### Sluggish engine
There can be several reasons why an engine responds slowly. Generally an overworked and busy engine will respond slower to the monitor's health-check API call. When the monitor detects a sluggish response from a given engine, in relation to a configurable threshold, it publishes an alert.

Example alert/event:
>`9/9/2019 6:00:32 PM: SLOW_ENGINE : Engine [1, Localhost, Scanning] Response Time: [3.014502] seconds. Threshold: [0.50] seconds.`

### Offline engine
The monitor publishes an alert when it detects that an engine is offline.

Example alert/event:
>`9/10/2019 4:25:44 PM: ENGINE_OFFLINE : Engine [1, Localhost, Offline]`

## Portal Monitoring
The monitor evaluates the responsiveness of the portal by measuring how long it takes for the portal to respond to the monitor's page request. If the duration exceeds a configurable threshold, an alert is published.

The monitor uses an anonymous request to the login page as a proxy for portal responsiveness.

Example alert/event:
>`9/6/2019 10:26:18 PM: SLOW_PORTAL : Slow Portal response. Response Time: [1.0396037] seconds. Threshold: [0.50] seconds.`

## Audit Monitoring
The monitor generates alerts for audit conditions that are frequently requested by customers. The following audit alerts are supported:
- Results Severity, State, Assignment changes
- Project changes
- Query changes
- Preset changes

### Enable Audit Monitoring
To enable audit monitoring, add the argument -audit when running CxOverwatch
>`.\CxHealthMonitor.ps1 -audit`


### Scan Results : Severity / State changes
Alerts are generated when scan results are updated - when the Severity and/or the State are changed. 

Example alert/event:
>`9/6/2019 10:47:36 PM: AUDIT : [Results] : Action = [Changed status to Not Exploitable] , Query = [Reflected_XSS_All_Clients] , Project = [dvja-master] , File = [\src\main\webapp\WEB-INF\dvja\ProductList.jsp] , Line = [23] , Column = [446] , User = [admin@cx] , Timestamp = [09/06/2019 22:47:34] `

>`9/6/2019 10:51:07 PM: AUDIT : [Results] : Action = [Changed severity to High] , Query = [Insecure_Credential_Storage_Mechanism] , Project = [FreeNote] , File = [\server\rest_test.go] , Line = [46] , Column = [74] , User = [admin@cx] , Timestamp = [09/06/2019 22:50:58] 
`
 ### Project changes
Alerts are published when Projects are created/updated. 

Example alert/event:
>`9/6/2019 1:00:58 PM: [Project] : Action : [Update_project] , Name : [DVJA] , User : [admin@cx] , Timestamp : [09/06/2019 13:00:56] 
`

 ### Query changes
Alerts are published when someone creates or updates a query. 

Example alert/event:
>`9/6/2019 11:02:13 PM: AUDIT : [Query] : Action = [Create_Query] , Name = [Find_Interactive_Inputs] , User = [service@cx] , Timestamp = [09/06/2019 23:01:57] 
`

 ### Preset changes
Alerts are published when there are changes to a Preset. 

Example alert/event:
>`9/6/2019 11:07:46 PM: AUDIT : [Preset] : Action = [Update] , Name = [High and Medium] , User = [admin@cx] , Timestamp = [09/06/2019 23:07:43] `

