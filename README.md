# Checkmarx Health Monitor

The Checkmarx Health Monitor is a tool that monitors the following:
* Queue
    * Number of scans in queue
    * How long a scan remains in the 'Queued' state
* Scans
    * Slow running scan
    * Scan failure
* Engine
    * Responsiveness
    * Offline
* Portal
    * Responsiveness
* Audits
    * Project changes
    * Query changes
    * Preset changes
    * Results Severity, State, Assignment changes

## Getting Started

The tool consists of two files - a Powershell script (the monitor) and a JSON file (the configuration)
* CxHealthMonitor.ps1
* cx_health_mon_config.json


### Prerequisites

* Powershell V5 (Windows 10 has powershell 5.1 installed)
   * https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
* Access to the Checkmarx Server and Database
* Adding the following credentials to the Windows Credential Manager (One time process)
	1) **Checkmarx SAST Credentials** : 
		1. Open the Windows Credential Manager ( Control Panel -> Credential Manager)  
		2. Click on 'Windows Credentials' and scroll down till you see 'Generic Credentials' section.  
		3. Click on 'Add a generic credential' and enter the following values:  
			Internet or network address : **CxOverwatch.SAST**  (Kindly make sure you copy the same name as mentioned here)  
			User name : cxadmin  
			Password : xxxxx  
		
		4. Click 'Ok' to save your credentials.
		
	2) **Checkmarx SAST DB Credentials** :   
		Note : Storing SAST database credentials is Optional. If you want to use Windows Authentication for the SQL Server, DO NOT add the credentials for the database.  
		
		1. Open the Windows Credential Manager ( Control Panel -> Credential Manager)  
		2. Click on 'Windows Credentials' and scroll down till you see 'Generic Credentials' section.  
		3. Click on 'Add a generic credential' and enter the following values:  
			Internet or network address : **CxOverwatch.SAST.DB**  (Kindly make sure you copy the same name as mentioned here)  
			User name : dbuser  
			Password : xxxxx  
		
		4. Click 'Ok' to save your credentials.  

	3) **Email Alert Credentials** :   
		Note : Storing Email credentials is Optional. If you are not using Email as your alert system or if you want to use anonymous SMTP, you can ignore this section.   
		
		1. Open the Windows Credential Manager ( Control Panel -> Credential Manager)  
		2. Click on 'Windows Credentials' and scroll down till you see 'Generic Credentials' section.  
		3. Click on 'Add a generic credential' and enter the following values:  
			Internet or network address : **CxOverwatch.EmailAlert**  (Kindly make sure you copy the same name as mentioned here)  
			User name : username@mailserver.com  
			Password : xxxxx  
		
		4. Click 'Ok' to save your credentials.

Note : If the script is not able to find the Checkmarx SAST credentials in the Credential Manager, it will show a prompt to user asking for the SAST username and password.

## Usage

```
.\CxHealthMonitor.ps1 [-cxUser username] [-cxPass password] [-dbUser username] [-dbPass password] [-audit]
```

The optional arguments will override the corresponding values stored in the Credential Manager. 

Add the argument -audit to enable monitoring of audits.  This is not enabled by default and should only be used if the user has access to the db.

Note: If the optional db parameters are skipped and the corresponding entries in the Credential Manager are empty, the monitor will use SQLServer Windows authentication.

## Configuration

The configuration file (cx_health_mon_config.json) consists of the following sections:
* cx
* monitor
* alerts
* alertingSystems

The **"cx"** section drives connectivity to the Checkmarx server and database. The Checkmarx Server URL and database instance are configured here.
```json
"cx": {
        "host": "http://checkmarx.domain.com",
        "db": {
            "instance": "localhost\\SQLExpress"
        }
    }
```

The **"monitor"** section is used to configure thresholds and monitoring parameters. 
```json
"monitor": {
        "useUTCTimeOnClient": "true",
        "pollIntervalSeconds": 30,
        "thresholds": {
            "queuedScansThreshold": 5,
            "queuedTimeThresholdMinutes": 20,
            "scanDurationThresholdMarginPercent": 25.0,
            "scanRateAsLOCPerHour": 150000,
            "engineResponseThresholdSeconds": 60.0,
            "restResponseThresholdSeconds": 60.0
        },
        "apiResponseTimeoutSeconds": 120,
        "retries": 5
    }
```
*_useUTCTimeOnClient_: "true" or "false" - if true forces UTC for calculation of time on the client. Useful when script runs on a machine in a local time zone but server runs in UTC.
* _pollIntervalSeconds_: Polling cadence - how often the monitor will connect to the Checkmarx server for monitoring purposes.
* _queuedScansThreshold_: Threshold for the maximum number of scans in the CxSAST Queue, beyond which alerts will be sent.
* _queuedTimeThresholdMinutes_: Threshold for the number of minutes a scan can remain in the CxSAST Queue, beyond which alerts will be sent.
* _scanDurationThresholdMarginPercent_: Additional duration (added as a percentage) to a scan's estimated duration, beyond which the scan will be marked 'slow'.
* _scanRateAsLOCPerHour_: The scan rate, in Lines Of Code per hour - to be used in estimating a scan's expected duration.
* _engineResponseThresholdSeconds_: Threshold (in seconds) for an engine to respond to the monitor's API call.
* _restResponseThresholdSeconds_: Threshold (in seconds) for the CxManager to respond to the monitor's API call. This is a proxy for Portal responsiveness.
* _apiResponseTimeoutSeconds_: Specified in seconds, this is how long the monitor will wait for a response from the monitored system, before timing out and trying again (see 'retries').
* _retries_: Number of times the monitor will attempt to connect to the monitored system before giving up.


The **"alerts"** section is used to configure values specific to Alerts.
 
```json
"alerts": {
        "waitingPeriodBetweenAlertsMinutes": 15,
        "suppressionRegex": ""
    }
```
* _waitingPeriodBetweenAlertsMinutes_: Period in minutes, to wait before sending out subsequent alerts arising from the same monitored subject and the same conditions. This configuration controls/prevents alert flooding.
*_suppressionRegex_: Alert messages that match this regular expression will be suppressed. Supports multiple patterns like "(pattern1|pattern2)". 

The **"alertingSystems"** section is used to configure available Alerting Systems to be used by the monitor.
The monitor ships with multiple Alerting System implementations, such as Email(smtp), Syslog and Event Logs. When new implementations (such as SNMP etc.) are available, this is where they should be configured.

Leave smtp user and password blank for anonymous smtp.

Follow instructions on creating an incoming webhook at https://api.slack.com/messaging/webhooks for Slack notification.


```json
"alertingSystems": {
        "smtp": [
            {
                "systemType": "smtp",
                "name": "Email",
                "host": "007-myemailserver.com",
                "port": 587,
                "sender": "admin@myemailserver.com",
                "recipients": "list@of.com, email@addresses.com",
                "subject": "Checkmarx Health Monitor Alert",
                "useSsl": true
            }
        ],
        "syslog": [
            {
                "systemType": "syslog",
                "name": "Kiwi",
                "host": "localhost",
                "port": 514
            },
            {
                "systemType": "syslog",
                "name": "Splunk",
                "host": "localhost",
                "port": 515
            }
        ],
        "slack" : [
            {
                "systemType": "slack",
                "name": "Slack",
                "hook" : "https://hooks.slack.com/services/xxxxxxxxxxxxxxxxxxx"
            }
        ]
    }
```

The **"log"** section is used to configure the JSON output directory to be used by the monitor.
The _jsonDirectory_ element specifies where the JSON files output by the monitor should be written.

```json
    "log": {
        "jsonDirectory": "json"
    }
```    
    
## Authors

* Gem Immanuel, Checkmarx Professional Services - *Initial work*
* Benjamin Stokes, Checkmarx Professional Services - patches


## License

This project is licensed under **TBD**
