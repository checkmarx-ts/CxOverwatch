<#
    Checkmarx CxSAST Health Monitoring System
    Version 1.0
    Gem Immauel (gem.immanuel@checkmarx.com)
    Checkmarx Professional Services

    Usage: .\CxHealthMonitor.ps1 [-cxUser cxaccount] [-cxPass cxpassword] [-audit] [-dbUser dbaccount] [-dbPass dbpassword] 

    The command line parameters will override the values read from the 
    configuration file (cx_health_mon.config.json)
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $cxUser = "",
    
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $cxPass = "",

    [switch] 
    $audit,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $dbUser = "",
    
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $dbPass = ""    
)

# ----------------------- Module imports  ------------------------ #

if ($audit) {
    # This assumes that the SqlServer powershell module is already installed.
    # If not, run "Install-Module -Name Invoke-SqlCmd2" as an administrator prior to running this script.
    Import-Module "Invoke-SqlCmd2" -DisableNameChecking 
}


# CxSAST REST API auth values
[String] $CX_REST_GRANT_TYPE = "password"
[String] $CX_REST_SCOPE = "sast_rest_api"
[String] $CX_REST_CLIENT_ID = "resource_owner_client"
[String] $CX_REST_CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"

# -----------------------------------------------------------------
# Input/Output Utility
# -----------------------------------------------------------------
Class IO {
    
    # General logging
    static [String] $LOG_FILE = "cx_health_mon.log"
    # Event logging
    static [String] $EVENT_FILE = "cx_health_mon_events.log"
    hidden [DateTimeUtil] $dateUtil = [DateTimeUtil]::new()

    
    # Files for JSON output 
    static [String] $FILE_SUFFIX_TIMESTAMP_FORMAT = "yyyyMMdd_hhmmssfff"
    
    # Logs given message to configured log file
    Log ([String] $message) {
        # Write to log file
        $this.WriteToFile($message, [IO]::LOG_FILE) 
        # Also write to console
        $this.Console($message)
    }

    # Writes given message to configured events file
    LogEvent ([String] $message) {
        # Write to event file
        $this.WriteToFile($message, [IO]::EVENT_FILE)
        # Also write to log, console
        $this.Log($message)
    }

    # Write given string to host console
    Console ([String] $message) {
        Write-Host $this.AddTimestamp($message)
    }

    # Write to JSON file
    WriteJSON([AlertType] $jsonFile, [PSCustomObject] $object) {
        
        # Ensure folder exists
        [String] $jsonOutDir = $script:config.log.jsonDirectory
        If (!(Test-Path $jsonOutDir)) {
            New-Item -ItemType Directory -Force -Path $jsonOutDir
        }
        $jsonOutDir = (Get-Item -Path $jsonOutDir).FullName

        # Create timestamp 
        [DateTime] $timestamp = $this.dateUtil.NowUTC()
        [String] $fileSuffix = $timestamp.ToString([IO]::FILE_SUFFIX_TIMESTAMP_FORMAT)

        # Update JSON blob with timestamp
        $object.EventDate = $this.dateUtil.Format($timestamp)

        # Create file name
        [String] $fileName = $jsonFile.ToString().ToLower() + "_$fileSuffix.json"
        [String] $jsonFilePath = Join-Path -Path "$jsonOutDir" -ChildPath $fileName

        # Write to file
        Add-content $jsonFilePath -Value ($object | ConvertTo-Json)
    }

    # Write a pretty header output
    WriteHeader() {
        Write-Host "-----------------------------------------" -ForegroundColor Green
        Write-Host "Checkmarx Health Monitor" -ForegroundColor Green        
        Write-Host "Checkmarx CxSAST: $($script:config.cx.host)"
        if ($script:audit) {
            Write-Host "Checkmarx Database: $($script:config.cx.db.instance)"
        }
        Write-Host "Poll interval (seconds): $($script:config.monitor.pollIntervalSeconds)"
        Write-Host "Default scan rate (LOC / Hour): $($script:config.monitor.thresholds.scanRateAsLOCPerHour)"
        Write-Host "Threshold for number of scans in the queued state: $($script:config.monitor.thresholds.queuedScansThreshold)"
        Write-Host "Threshold for time spent in the queued state: $($script:config.monitor.thresholds.queuedTimeThresholdMinutes) minute(s)"
        Write-Host "Scan duration threshold margin: $($script:config.monitor.thresholds.scanDurationThresholdMarginPercent)%"
        Write-Host "Alerting Systems: [$($script:alertService.alertSystems.name)]"
        Write-Host "-----------------------------------------" -ForegroundColor Green
    }
    
    # Utility that writes to given file
    hidden WriteToFile([String] $message, [String] $file) {
        Add-content $file -Value $this.AddTimestamp($message)
    }

    hidden [String] AddTimestamp ([String] $message) {
        return $this.dateUtil.NowUTCFormatted() + ": " + $message
    }
}

# -----------------------------------------------------------------
# Abstract Alert System
# -----------------------------------------------------------------
Class AlertSystem {
    
    [String] $name = "Unknown Name. Alert System Name not explicitly set."
    [String] $systemType = "Unknown system type. Alert System Type not explicitly set."
    [IO] $io = [IO]::new()
    [DateTimeUtil] $dateUtil = [DateTimeUtil]::new()

    # Abstract constructor
    AlertSystem () {
        $type = $this.GetType()
        if ($type -eq [AlertSystem]) {
            throw("Class $type must be overridden by an alerting system implementation")
        }
    }

    # Sends an alert for given scan
    Send([String] $message) {
        # Force implementation by a concrete algo
        throw("Method is abstract. Needs to be overriden by an alerting system implementation.")
    }

    [String] GetSystemType() {
        return $this.systemType
    }

    # By default, alert systems do not batch(combine) alert messages.
    # Some systems, by design, can (ex. email systems)
    # If a system can batch messages, override this to return true
    [Bool] IsBatchMessages() {
        return $False
    }
}

# -----------------------------------------------------------------
# Standard Syslog Severities
# -----------------------------------------------------------------
Enum SyslogSeverity {
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7
}

# -----------------------------------------------------------------
# Support for alerting over the Syslog protocol
# -----------------------------------------------------------------
Class SyslogAlertSystem : AlertSystem {

    hidden [String] $syslogServer
    hidden [int] $syslogPort
    hidden [SyslogSeverity] $severity = [SyslogSeverity]::ALERT    

    # Constructs a syslog alerting system object
    SyslogAlertSystem([String] $systemType, [String] $name, [String] $syslogServer, [int] $syslogPort) {  
        $this.systemType = $systemType
        $this.name = $name
        $this.syslogServer = $syslogServer
        $this.syslogPort = $syslogPort
    }

    # Sends given message over UDP to configured syslog server/port
    Send([String] $message) {
       
        # If there is no message, not much to do
        if (!$message) { return }

        # Prepend 'Checkmarx' as marker
        $message = "Checkmarx: $message"

        # Syslog Facility 1 : User-level message 
        [int] $facility = 1
        [String] $hostname = $env:computername
        # Calculate the priority        
        [int] $priority = ([int] $facility * 8) + [int] $this.severity.value__
        # "MMM dd HH:mm:ss" or "yyyy:MM:dd:-HH:mm:ss zzz"
        [String] $timestamp = ($this.dateUtil.NowUTC()).ToString("MMM dd HH:mm:ss")

        # Syslog packet format
        [String] $syslogMessage = "<{0}>{1} {2} {3}" -f $priority, $timestamp, $hostname, $message

        # Create encoded syslog packet
        $encoder = [System.Text.Encoding]::ASCII
        $encodedPacket = $encoder.GetBytes($syslogMessage)

        # Connect to the syslog server and send packet over UDP
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Connect($this.syslogServer, $this.syslogPort)
        $udpClient.Send($encodedPacket, $encodedPacket.Length)

        $this.io.Log("Sent syslog message to [$($this.name) : $($this.syslogServer)]")
    }
}

# -----------------------------------------------------------------
# Email Alert System
# -----------------------------------------------------------------
Class EmailAlertSystem : AlertSystem {

    hidden [IO] $io
    hidden [String] $smtpHost
    hidden [int] $smtpPort
    hidden [pscredential] $smtpCredentials
    hidden [String] $subject
    hidden [String] $smtpSender
    hidden [String[]] $recipients
    hidden [Boolean] $useSsl

    # Constructs the email alert system object
    EmailAlertSystem ([String] $systemType, [String] $name, [String] $smtpHost, [int] $smtpPort, [String] $smtpUsername, [String] $smtpPassword, [String] $smtpSender, [String[]] $recipients, [String] $subject, [Boolean] $useSsl) {
        $this.io = [IO]::new()
        $this.systemType = $systemType
        $this.name = $name
        $this.smtpHost = $smtpHost
        $this.smtpPort = $smtpPort
        $this.smtpSender = $smtpSender
        $this.recipients = $recipients
        $this.subject = $subject
        $this.useSsl = $useSsl
        
        # Support anonymous authenticated smtp scenario
        if ($smtpUsername.Length -gt 0 -and $smtpPassword.Length -gt 0) {
            [CredentialsUtil] $credUtil = [CredentialsUtil]::new()
            $this.smtpCredentials = $credUtil.GetPSCredential($smtpUsername, $smtpPassword)
        }
    }

    # Override default behavior
    # Indicate that this system will batch messages.
    [Bool] IsBatchMessages() {
        return $True
    }

    # Sends an email with message
    Send([String] $message) {

        # No-frills implementation
        try {
            $this.io.Log("Sending email alert to [$($this.name) : $($this.recipients)]")
            
            $mailargs = @{
                From = $this.smtpSender
                Body = $message
                Subject = $this.subject
                To = $this.recipients
                Priority = "High"
                SmtpServer = $this.smtpHost
                Port = $this.smtpPort
            }
            
            # If credentials are not provided then we will use anonymous smtp
            if ($this.smtpCredentials) {
                $mailargs.Add("Credential", $this.smtpCredentials)
            }
            
            if ($this.useSsl) {
                $mailargs.Add("UseSsl", $True)
            }
                        
            Send-MailMessage @mailargs                        
        }
        catch {
            $this.io.Log("ERROR: [$($_.Exception.Message)] Could not send email alert. Verify email configuration.")
        }
    }
}

# -----------------------------------------------------------------
# Slack Alert System
# -----------------------------------------------------------------
Class SlackAlertSystem : AlertSystem {

    hidden [IO] $io
    hidden [String] $systemType
    hidden [String] $name
    hidden [String] $hook

    # Constructs the email alert system object
    SlackAlertSystem ([String] $systemType, [String] $name, [String] $hook) {
        $this.io = [IO]::new()
        $this.systemType = $systemType
        $this.name = $name
        $this.hook = $hook
    }

    # Sends a Slack with message
    Send([String] $message) {

        # No-frills implementation
        try {
			# This looks odd but it replaces the single backslash with double backslash.
			# Need to do this for the slack body
			$message = $message -replace '\\', '\\'

            $this.io.Log("Sending alert to [$($this.name)]")

            # message has to be in json format so Slack can parse it
            $body = '{"text":"' + $message + '"}'

            Invoke-RestMethod -Uri $this.hook -Method Post -Body $body -ContentType 'application/json'
        }
        catch {
            $this.io.Log("ERROR: [$($_.Exception.Message)] Could not send slack alert. Verify slack configuration.")
        }
    }
}

# Enumerates types of alerts that we send
# Helps keep track of which type of alert
# was sent when and for which scan/project.
Enum AlertType {
    SCAN_FAILED
    SCAN_SLOW
    QUEUE_SCAN_TIME_EXCEEDED
    QUEUE_SCAN_EXCESS
    ENGINE_OFFLINE
    ENGINE_RESPONSE_SLOW
    ENGINE_IDLE
    ENGINE_ERROR
    PORTAL_SLOW    
    AUDIT
}

# -----------------------------------------------------------------
# Alert Service
# -----------------------------------------------------------------
Class AlertService {

    hidden [IO] $io
    hidden [System.Collections.ArrayList] $alerts = @()
    hidden [System.Collections.ArrayList] $alertSystems = @()
    # Key = scanId_projectName_scanType_AlertType
    # Value = TimeSent
    hidden [Hashtable] $sent = @{ }

    # Number of minutes to wait before sending an
    # alert for the same scan and/or condition
    hidden [TimeSpan] $waitBetweenAlerts

    AlertService () {
        $this.io = [IO]::new()
        $this.waitBetweenAlerts = [TimeSpan]::FromMinutes($script:config.alerts.waitingPeriodBetweenAlertsMinutes)
        $this.RegisterAlertSystems()
    }

    # Register configured alert systems
    RegisterAlertSystems() {
        # Register alerting systems specified in configuration file

        foreach ($alertingSystem in $script:config.alertingSystems) {
    
            # For now, we register each type of alerting systems separately.
            # Enhancement would be to have configuration self-declare system type
            # and have a factory create the system for you :)    

            # Register SMTP systems, if configured
            if ($alertingSystem.smtp) {
                foreach ($smtpSystem in $alertingSystem.smtp) {
                    [AlertSystem] $emailAlertSystem = [EmailAlertSystem]::new($smtpSystem.systemType, $smtpSystem.name, $smtpSystem.host, $smtpSystem.port, $smtpSystem.user, $smtpSystem.password, $smtpSystem.sender, $smtpSystem.recipients, $smtpSystem.subject, $smtpSystem.useSsl)    
                    $this.AddAlertSystem($emailAlertSystem);
                }
            }

            # Register Syslog systems, if configured
            if ($alertingSystem.syslog) {
                foreach ($syslogSystem in $alertingSystem.syslog) {
                    [AlertSystem] $syslogAlertSystem = [SyslogAlertSystem]::new($syslogSystem.systemType, $syslogSystem.name, $syslogSystem.host, $syslogSystem.port)    
                    $this.AddAlertSystem($syslogAlertSystem);
                }
            }
            # Register slack, if configured
            if ($alertingSystem.slack) {
                foreach ($slackSystem in $alertingSystem.slack) {
                    [AlertSystem] $slackAlertSystem = [SlackAlertSystem]::new($slackSystem.systemType, $slackSystem.name, $slackSystem.hook)
                    $this.AddAlertSystem($slackAlertSystem);
                }
            }
        }
    }

    # Add an AlertSystem to the Alert Service
    # This enables multiple AlertSystem implementations
    # Ex. Email, Syslog, SMNP etc.
    AddAlertSystem ([AlertSystem] $alertSystem) {
        $this.alertSystems.Add($alertSystem)
        $this.io.Log("Config: Added Alert System [$($alertSystem.name)]")
    }

    # Track an alert : Type and current timestamp
    Track ([String] $scanKey, [AlertType] $alertType) {
        $timestamp = Get-Date
        [String] $alertKey = $scanKey + "_" + $alertType
        if ($this.sent.ContainsKey($alertKey)) {
            # Update with current timestamp
            $this.sent[$alertKey] = $timestamp
        }
        else {
            $this.sent.Add($alertKey, $timestamp)            
        }
    }

    # Should the alert be sent?
    # We determine if an alert should be sent again by:
    #   checking if an alert had been previously sent for (scanId + projectName + scanType + alertType)
    #       and we're past the waiting period between alerts
    [Bool] ShouldSend([String] $scanKey, [AlertType] $alertType) {
        [Bool] $goForIt = $True
        [String] $alertKey = $scanKey + "_" + $alertType
        if ($this.sent.containsKey($alertKey)) { 
            [datetime] $now = Get-Date
            [datetime] $lastSent = $this.sent[$alertKey] 

            # If we're still within (lastSent + waitingPeriod) don't send alert just yet
            if ($now -lt $lastSent.Add($this.waitBetweenAlerts)) { 
                # $this.io.Console("Alert [$alertKey] still within waiting period between alerts.")
                $goForIt = $False 
            }
        }
        return $goForIt        
    }
    
    # Add an alert message to a list that will be sent as a batch on Send()
    AddAlert ([AlertType] $alertType, [String] $message, [String] $scanKey) {
        $this.io.LogEvent("$alertType : $message")
        # Add only if given message should be sent
        if ($this.ShouldSend($scanKey, $alertType)) {
            $this.alerts.Add("$alertType : $message")
            $this.Track($scanKey, $alertType)
        }
    }

    # Sends out alert message 
    # via all registered alerting systems
    Send () {
        
        # If we don't have any alerts to send, return
        if ($this.alerts.Count -eq 0) { return }

        # Otherwise, send them out to every registered alerting system
        foreach ($alertSystem in $this.alertSystems) {

            # Batch(combine) messages is required:
            # Email systems, for instance.
            if ($alertSystem.IsBatchMessages()) {
                [String] $batchMessage = ""
                foreach ($message in $this.alerts) {
                    if ($message -notmatch $script:config.alerts.suppressionRegex -Or [String]::IsNullOrWhiteSpace($script:config.alerts.suppressionRegex)) {
                        $batchMessage += "$message`n"
                    } else {
                        Write-Host Alert [$message] suppressed due to matching suppressionRegex -ForegroundColor DarkRed
                    }                    
                }
                if (![string]::IsNullOrEmpty($batchMessage)) {
                    $alertSystem.Send($batchMessage)
                }                 
            }
            else {
                foreach ($message in $this.alerts) {
                    if ($message -notmatch $script:config.alerts.suppressionRegex -Or [String]::IsNullOrWhiteSpace($script:config.alerts.suppressionRegex)) {
                        $alertSystem.Send($message)
                    } else {
                        Write-Host Alert [$message] suppressed due to matching suppressionRegex -ForegroundColor DarkRed
                    }                    
                }
            }
        }
        $this.alerts.Clear()
    }
}

# -----------------------------------------------------------------
# Credentials Utility
# -----------------------------------------------------------------
Class CredentialsUtil {

    # Returns a PSCredential object from given plaintext username/password
    [PSCredential] GetPSCredential ([String] $username, [String] $plainTextPassword) {
        [SecureString] $secPassword = ConvertTo-SecureString $plainTextPassword -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential ($username, $secPassword)
    }
}

# -----------------------------------------------------------------
# DateTime Utility
# -----------------------------------------------------------------
Class DateTimeUtil {

    # Gets timestamp in UTC in configured format
    [String] NowUTCFormatted() {
        return $this.Format($this.NowUTC())
    }

    # Gets timestamp in UTC
    [DateTime] NowUTC() {
        return (Get-Date).ToUniversalTime()
    }

    # Converts to UTC and formats
    [String] ToUTCAndFormat([DateTime] $dateTime) {
        return $this.Format($dateTime.ToUniversalTime())
    }

    # Formats time based on configured format
    [String] Format([DateTime] $dateTime) {
        return $dateTime.ToString($script:config.monitor.timeFormat)
    }

}

# -----------------------------------------------------------------
# Simple fixed-size list
# -----------------------------------------------------------------
Class FixedSizeList {

    hidden $data 
    hidden [int] $size

    # Constructs a fixed size list
    # This is a simple implementation based on a LinkedList :)
    # Until CX requirements dictate a more complex impl, this'll do nicely.
    FixedSizeList ([int] $size) {
        $this.size = $size
        $this.data = New-Object Collections.Generic.LinkedList[Object]
    }

    # Add data item to the list
    Add([Object] $item) {
        # Maintain a max of {size} items
        if ($this.data.Count -eq $this.size) { 
            $this.data.RemoveLast() 
        }
        $this.data.AddFirst($item)  
    }

    # Get internal data
    # Tsk,tsk..
    [Array] GetData() {
        return $this.data
    }
}

# -----------------------------------------------------------------
# Abstract Scan Time Estimation algo
# -----------------------------------------------------------------
Class ScanTimeAlgo {    

    # Margin (%) to add to scan duration threshold
    [double] $thresholdMargin

    # Abstract constructor
    ScanTimeAlgo () {
        $type = $this.GetType()
        if ($type -eq [ScanTimeAlgo]) {
            throw("Class $type must be implemented")
        }
    }

    # Calculates expected scan duration
    [double] Estimate ([Object] $scan) {
        # Force implementation by a concrete algo
        throw("Method is abstract. Needs to be overriden by implementation.")
    }

    # Calculates elapsed time for a scan (in minutes)
    [double] GetScanDuration ([Object] $scan) {

        [double] $elapsedTime = 0.0
        [String] $scanStart = $scan.engineStartedOn
        if ($scanStart) {
            [String] $scanEnd = $scan.completedOn
        
            # Calculate scan duration
            $startTime = [Xml.XmlConvert]::ToDateTime($scanStart)
            if (!$scanEnd) {
                $scanEnd = Get-Date
                if ($script:config.monitor.useUTCTimeOnClient -eq "true") {
                    $scanEnd = (Get-Date).ToUniversalTime()
                }
            }
            $diff = New-TimeSpan -Start $startTime -End $scanEnd
            $elapsedTime = $diff.TotalMinutes            
        }
                        
        return $elapsedTime
    }    
}

# -----------------------------------------------------------------
# Default Scan Time Estimation algo
# -----------------------------------------------------------------
Class DefaultScanTimeAlgo : ScanTimeAlgo {
    
    hidden [IO] $io
    hidden [Hashtable] $scanHistory
    # Default scan rate: LOC / hour
    hidden [int] $scanRateLOCPerHour

    DefaultScanTimeAlgo () {
        $this.io = [IO]::new()
        $this.scanHistory = [Hashtable]::new()
        # Sets margin for threshold
        # Threshold is calculated as (scan time + margin %)        
        $this.thresholdMargin = $script:config.monitor.thresholds.scanDurationThresholdMarginPercent
        $this.scanRateLOCPerHour = $script:config.monitor.thresholds.scanRateAsLOCPerHour
    }

    # Default scan time estimation algo implementation
    #   Simply maintain last scan duration and use (that+%margin) as benchmark
    [double] Estimate ([Object] $scan) {

        [double] $scanDuration = 0.0

        # If we have prior scans from this project
        [String] $key = $this.GetKey($scan)

        if ($this.scanHistory.Count -gt 0 -and $this.scanHistory.containsKey($key)) {

            # Fetch previously completed scan
            [Object] $priorScan = $this.scanHistory[$key]

            $scanDuration = $this.GetScanDuration($priorScan)
        }
        else {
            # Simple formula : LOC / scan rate and converted to minutes
            $scanDuration = ($scan.loc / $this.scanRateLOCPerHour) * 60.0
            # $this.io.Console("Based on simple calculation: $($scan.loc) / $($this.scanRateLOCPerHour) * 60 = $scanDuration")  
        }

        # Margin is a percentage added on top of expected scan duration
        $margin = ($scanDuration * ($this.thresholdMargin / 100.0))
        return $scanDuration + $margin
    } 
    
    # Returns a machine readable Scan key
    [String] GetKey([Object] $scan) {
        [String] $scanType = if ($scan.isIncremental -eq $True) { "I" } else { "F" }
        return "$($scan.id)_$($scan.project.Name)_$scanType"
    }

    # Saves a finished scan's duration to scan history
    StoreScanDuration ($scan) {  
        # Guard for case when engineStartedOn is not available which 
        # happens when no source code changes were detected.  
        if ([string]::IsNullOrEmpty($scan.engineStartedOn)) {
            return
        } 

        [String] $key = $this.GetKey($scan)
        
        # Add scan if no prior scans exist for given key
        if (!$this.scanHistory.containsKey($key)) {
            # TODO: This table will need to be flushed either on a timely basis, or some other criteria
            # Store data only if the scan actually was underway
            if ($scan.engineStartedOn) {
                $this.scanHistory.Add($key, $scan)
            }
        }
        else {
            $priorScan = $this.scanHistory[$key]

            [DateTime] $priorScanStart = [Xml.XmlConvert]::ToDateTime($priorScan.engineStartedOn)
            [DateTime] $currentScanStart = [Xml.XmlConvert]::ToDateTime($scan.engineStartedOn)

            # Replace old scan with new scan if scan is newer
            if ($priorScan.id -ne $scan.id -and $currentScanStart -gt $priorScanStart) {
                # $this.io.Console("Replacing prior scan. Old scanId $($priorScan.id) Current ScanId $($scan.id)")
                $this.scanHistory[$key] = $scan
            }
        }
    }
}

# -----------------------------------------------------------------
# Reads Configuration from JSON file
# -----------------------------------------------------------------
Class Config {

    hidden [IO] $io
    hidden $config
    static [String] $CONFIG_FILE = ".\cx_health_mon_config.json"

    # Constructs and loads configuration from given path
    Config () {
        $this.io = [IO]::new()
        $this.LoadConfig()
    }

    # Loads configuration from configured path
    LoadConfig () {
        try {
            $cp = [Config]::CONFIG_FILE
            $configFilePath = (Get-Item -Path $cp).FullName
            $this.io.Log("Loading configuration from $configFilePath")
            $this.config = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
        }
        catch {
            $this.io.Log("Provided configuration file at [" + [Config]::CONFIG_FILE + "] is missing / corrupt.")        
        }
    }

    [PsCustomObject] GetConfig() {
        return $this.config
    }
}

# -----------------------------------------------------------------
# REST request methods
# -----------------------------------------------------------------
Enum RESTMethod {
    GET
    POST
}

# -----------------------------------------------------------------
# REST request body
# -----------------------------------------------------------------
Class RESTBody {

    [String] $grantType
    [String] $scope
    [String] $clientId
    [String] $clientSecret

    RESTBody(
        [String] $grantType, 
        [String] $scope,
        [String] $clientId,
        [String] $clientSecret
    ) {
        $this.grantType = $grantType 
        $this.scope = $scope
        $this.clientId = $clientId
        $this.clientSecret = $clientSecret
    }
}

# -----------------------------------------------------------------
# REST Client
# -----------------------------------------------------------------
Class RESTClient {

    [String] $baseUrl
    [RESTBody] $restBody

    hidden [String] $token
    hidden [IO] $io = [IO]::new()

    # Constructs a RESTClient based on given base URL and body
    RESTClient ([String] $cxHost, [RESTBody] $restBody) {
        $this.baseUrl = $cxHost + "/cxrestapi"
        $this.restBody = $restBody 
    }

    <#
    # Logins to the CxSAST REST API
    # and returns an API token
    #>
    [bool] login ([String] $username, [String] $password) {
        [bool] $isLoginSuccessful = $False
        $body = @{
            username      = $username
            password      = $password
            grant_type    = $this.restBody.grantType
            scope         = $this.restBody.scope
            client_id     = $this.restBody.clientId
            client_secret = $this.restBody.clientSecret
        }
    
        [psobject] $response = $null
        try {
            $loginUrl = $this.baseUrl + "/auth/identity/connect/token"
            $response = Invoke-RestMethod -uri $loginUrl -method POST -body $body -contenttype 'application/x-www-form-urlencoded' -TimeoutSec $script:config.monitor.apiResponseTimeoutSeconds
        }
        catch {            
            $this.io.Log("Could not authenticate against Checkmarx REST API. Reason: HTTP [$($_.Exception.Response.StatusCode.value__)] - $($_.Exception.Response.StatusDescription).")
        }
    
        if ($response -and $response.access_token) {
            $isLoginSuccessful = $True
            # Track token internally
            $this.token = $response.token_type + " " + $response.access_token
        }

        
        return $isLoginSuccessful
    }  

    <#
    # Invokes a given REST API
    #>
    [Object] invokeAPI ([String] $requestUri, [RESTMethod] $method, [Object] $body, [int] $apiResponseTimeoutSeconds) { 

        # Sanity : If not logged in, do not proceed
        if ( ! $this.token) {
            throw "Must execute login() first, prior to other API calls."
        }

        $headers = @{
            "Authorization" = $this.token
            "Accept"        = "application/json"
        }

        $response = $null
        
        try {
            $uri = $this.baseUrl + $requestUri
            if ($method -ieq "GET") {
                $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -TimeoutSec $apiResponseTimeoutSeconds
            }
            else {
                $response = Invoke-RestMethod -Uri $uri -Method $method.ToString() -Headers $headers -Body $body -TimeoutSec $apiResponseTimeoutSeconds
            }
        
            Write-Debug "ID: $($response.id)"
            Write-Debug "Key: $($response.key)"
            Write-Debug "Self: $($response.self)" 
        }
        catch {
            $exception = $_.Exception
    
            $this.io.Log("REST API call failed : [$($exception.Message)]")
            $this.io.Log("Status Code: $($exception.Response.StatusCode)")

            if ($exception.Response.StatusCode -eq "BadRequest") {
                $respstream = $exception.Response.GetResponseStream()
                $sr = new-object System.IO.StreamReader $respstream
                $ErrorResult = $sr.ReadToEnd()
                $this.io.Log($ErrorResult)
            }
        } 

        return $response
    }     
}


# -----------------------------------------------------------------
# Database Client
# -----------------------------------------------------------------
Class DBClient {

    hidden [IO] $io = [IO]::new()
    hidden [PSCredential] $sqlAuthCreds
    hidden [String] $serverInstance

    # Constructs a DBClient based on given server and creds
    DBClient ([String] $serverInstance, [String]$dbUser, [String] $dbPass) {
        $this.serverInstance = $serverInstance
        if ($dbUser -and $dbPass) {
            $this.sqlAuthCreds = [CredentialsUtil]::new().GetPSCredential($dbUser, $dbPass)
        }
    }

    # Executes given SQL using either SQLServer authentication or Windows, depending on given PSCredential object
    [PSObject] ExecSQL ([String] $sql, [Hashtable] $parameters) {
        # $this.io.Console("Executing $sql")
        try {
            if ($this.sqlAuthCreds.UserName) {
                $cred = $this.sqlAuthCreds
                return Invoke-Sqlcmd2 -ServerInstance $this.serverInstance -Credential @cred -Query $sql -SqlParameters $parameters
            }
            else {
                return Invoke-Sqlcmd2 -ServerInstance $this.serverInstance -Query $sql -SqlParameters $parameters
            }    
        }
        catch {
            $this.io.Log("Database execution error. $($_.Exception.GetType().FullName), $($_.Exception.Message)")
            # Force exit during dev run - runtime savior
            Exit
        }
    }

}



# -----------------------------------------------------------------
# Engine(s) Monitor
# -----------------------------------------------------------------
Class EngineMonitor {

    hidden [IO] $io
    hidden [AlertService] $alertService
    hidden [RESTClient] $cxSastRestClient
    hidden [DateTimeUtil] $dateUtil
    
    # Constructs a EngineMonitor
    EngineMonitor ([AlertService] $alertService) {
        $this.io = [IO]::new()
        $this.dateUtil = [DateTimeUtil]::new()
        $this.alertService = $alertService
    }

    Monitor() {
        # Create a RESTBody specific to CxSAST REST API calls
        $cxSastRestBody = [RESTBody]::new($script:CX_REST_GRANT_TYPE, $script:CX_REST_SCOPE, $script:CX_REST_CLIENT_ID, $script:CX_REST_CLIENT_SECRET)
        # Create a REST Client for CxSAST REST API
        $this.cxSastRestClient = [RESTClient]::new($script:config.cx.host, $cxSastRestBody)
        # Login to the CxSAST server
        [bool] $isLoginOk = $this.cxSastRestClient.login($script:config.cx.username, $script:config.cx.password)

        if ($isLoginOk -eq $True) {
            # Fetch Queue Status
            $resp = $this.GetEngineStatus()
        
            # Process the response
            $this.ProcessResponse($resp)
        }
    }

    # Fetches the status of the engines
    [Object] GetEngineStatus () {        
        [String] $apiUrl = "/sast/engineServers"
        $resp = $this.cxSastRestClient.invokeAPI($apiUrl, [RESTMethod]::GET, $null, $script:config.monitor.apiResponseTimeoutSeconds)
        return $resp
    }

    # Try to reach the specific engine's WSDL
    [Object] GetEngineWSDL ([String] $name, [String]$apiUri) { 
        [Object] $resp = $null
        for ($i = 0; $i -lt $script:config.monitor.retries; $i++) {             
            try {     
                $resp = Invoke-WebRequest -UseBasicParsing -Uri $apiUri -TimeoutSec $script:config.monitor.apiResponseTimeoutSeconds
                break
            }
            catch {
                $resp = $_.Exception.Response
                $this.io.Log("ERROR: Checking engine $name : [$($_.Exception.Message)]")
                if ($i -lt $script:config.mnitor.retries) { $this.io.Log("Attempting again...") }
            }
        }
        return $resp
    }

    # Processes response from CxSAST REST API call
    ProcessResponse ([Object] $apiResp) {

        # If there are registered engines
        if ($apiResp.Count -gt 0) {

            foreach ($engine in $apiResp) {
                
                [String] $engineInfo = "Engine [$($engine.id), $($engine.name), $($engine.status.value)]"
                
                [PSCustomObject] $engineDetails = $this.GetEngineDetails($engine)

                # Try connecting if not offline
                if ($engine.status.value -eq "Offline") {
                    $this.alertService.AddAlert([AlertType]::ENGINE_OFFLINE, $engineInfo, $engineInfo)
                    $this.io.WriteJSON([AlertType]::ENGINE_OFFLINE, $engineDetails)
                }
                else {
                    # Attempt to access the Engine's WSDL and report response time
                    $stopwatch = [system.diagnostics.stopwatch]::StartNew()
                    $wsdlResp = $this.GetEngineWSDL($engine.name, $engine.uri)
                    $stopwatch.Stop()   
                    
                    $this.io.Log($engineInfo + " Responded in [$($stopwatch.elapsed.TotalSeconds)] seconds.")

                    # Log any response other than HTTP 200 OK
                    if ($wsdlResp.StatusCode -ne [system.net.httpstatuscode]::OK) {
                        $message = $engineInfo + " Responded [$($wsdlResp.StatusCode)] instead of [OK]"
                        $this.io.LogEvent($message)
                        $this.alertService.AddAlert([AlertType]::ENGINE_ERROR, $message, $engineInfo)
                    }

                    # Check if engine is idle
                    if ($engine.status.value -eq "Idle") {

                        # Write idle engines JSON
                        $this.io.WriteJSON([AlertType]::ENGINE_IDLE, $engineDetails)

                        # Check if this idle engine could have taken on existing queued scans
                        $this.CheckQueuedScansForMatch($engine)
                    }

                    # Check API call elapsed time
                    [TimeSpan] $threshold = [TimeSpan]::FromSeconds($script:config.monitor.thresholds.engineResponseThresholdSeconds)
                    if ($stopwatch.elapsed.TotalSeconds -gt $script:config.monitor.thresholds.engineResponseThresholdSeconds) {
                        $message = $engineInfo + " Response Time: [$($stopWatch.elapsed)]. Threshold: [$threshold]."
                        $this.io.LogEvent($message)
                        $this.alertService.AddAlert([AlertType]::ENGINE_RESPONSE_SLOW, $message, $engineInfo) 

                        # Create a JSON structure for the slow engine
                        $engineDetails.Add("ResponseTime", "$($stopwatch.elapsed.Milliseconds)")
                        $engineDetails.Add("Threshold", "$($script:config.monitor.thresholds.engineResponseThresholdSeconds * 1000)")
                        $this.io.WriteJSON([AlertType]::ENGINE_RESPONSE_SLOW, $engineDetails)
                    }                    
                }
            }
        
            # Send out alerts
            $this.alertService.Send()
        }

    }

    # Checks queued scans against given idle engine to see if it 'fits'
    CheckQueuedScansForMatch ([PSObject] $engine) {

        # Check if there are idle engines that could have executed one of the queued scans
        if ($script:queuedEntriesDto) {

            [System.Collections.ArrayList] $matchedScans = @()

            # attempt to find scans that could 'fit'
            foreach ($queuedScan in $script:queuedEntriesDto) {                            
                                
                # Applies only to 'Queued' scans - not to ones that are in SourcePulling etc.
                if ($queuedScan.stage.value -eq "Queued") {
                                
                    # IdleEngineMinLOC <= QueuedScanLOC <= IdleEngineMaxLOC
                    if ($engine.ScanMinLoc -le $queuedScan.loc -and $queuedScan.loc -le $engine.ScanMaxLoc) {
                        # This algo is very eager,
                        # in that the engine could have just published 'idle' and we pick it up :)
                        $matchedScans.Add($queuedScan)
                    }
                }
            }

            # Publish alert only if we found scans within an idle engine's parameters
            # NOTE: TODO: we're not looking at the concurrent capacity of the engine
            if ($matchedScans.Count -gt 0) {
                [String] $engineInfo = "Engine [$($engine.id), $($engine.name), $($engine.status.value)]"
                [String] $message = "Idle engine [" + $engine.name + "]. Potential scans: [" + $matchedScans.id + "]";
                $this.alertService.AddAlert([AlertType]::ENGINE_IDLE, $message, $engineInfo)
            }
        }
    }

    # Maps engine details into a Hashtable
    [PSCustomObject] GetEngineDetails ($engine) {
        return [ordered] @{
            EventDate          = ""
            EngineId           = "$($engine.id)"
            EngineServerName   = "$($engine.name)"
            ScanMinLoc         = "$($engine.minLoc)"
            ScanMaxLoc         = "$($engine.maxLoc)"
            MaxConcurrentScans = "$($engine.maxScans)"
            ProductVersion     = "$($engine.cxVersion)"
            StatusId           = "$($engine.status.id)"
            StatusName         = "$($engine.status.value)"
        }
    }
}


# -----------------------------------------------------------------
# Database table metadata 
#
# The AuditMonitor executes SQL based on metadata of 
# the database item that needs to be audited/monitored,
# to generate the alert message. 
#
# The DBQueryMetadata contains the SQL query to execute, and 
# a map of [reportable Labels to DB Columns].
# Example: ["User that changed the value" : "updating_user"] 
# -----------------------------------------------------------------
Class DBQueryMetadata {   
    [String] $name
    [String] $sql
    # Notice the hashtable is ordered.
    # This enables control over the order of the labels
    # when we auto-generate the alert message.
    # See AuditMonitor's PopulateAuditMetadata() method
    # for the order of the labels.
    $meta = [ordered] @{ }
}



# -----------------------------------------------------------------
# Audit(s) Monitor
# -----------------------------------------------------------------
Class AuditMonitor {

    hidden [IO] $io
    hidden [AlertService] $alertService
    hidden [DateTime] $lastRun
    hidden [DBClient] $dbClient
    hidden [System.Collections.ArrayList] $dbQueryMetadata = @() 
    hidden [DateTimeUtil] $dateUtil

    # Constructs an AuditMonitor
    AuditMonitor ([AlertService] $alertService) {
        $this.io = [IO]::new()
        $this.dateUtil = [DateTimeUtil]::new()
        $this.alertService = $alertService
        $this.lastRun = Get-Date
        $this.PopulateAuditMetadata()
    }

    # Inject suitable DB client
    SetDbClient ([DBClient] $dbClient) {
        $this.dbClient = $dbClient
    }

    # Add metadata for database queries
    AddDBQueryMetadata ([DBQueryMetadata] $metadata) {
        $this.dbQueryMetadata.Add($metadata)
    }

    # Monitor for changes in audit tables
    Monitor() {

        # Big picture:
        # For each database item that needs to be monitored,
        #   we run the specified SQL query
        #   and extract the columns specified in the meta map
        #   and generate an alert message string that is published to the alerting service
        foreach ($metadata in $this.dbQueryMetadata) {

            # All the queries depend on a timestamp column.
            # We only process new database entries since the last time the monitor was run.
            # Ex. We only process/send alerts for new preset changes (since the last run).
            [Hashtable] $parameters = @{ lastRun = $this.lastRun }
            
            [PSObject] $results = $this.dbClient.ExecSQL($metadata.sql, $parameters)
            
            if ($results) {
            
                foreach ($result in $results) {     

                    # Start constructing the alert message
                    [String] $message = "[$($metadata.name)] : "
                    
                    # Extract the columns that are specified in the meta map
                    [int] $i = 0
                    foreach ($key in $metadata.meta.Keys) {

                        $columnName = $metadata.meta[$key]
                        $value = $result[$columnName]
                        $message += "$key = [$value] "
                        
                        # Append a comma if it's not the last item
                        if ($i + 1 -lt $metadata.meta.Keys.Count) {
                            $message += ", "
                            $i++
                        }
                    }
                    # Provide new guid to uniquely identify each audit alert
                    # Otherwise the alerting service will assume it is the same alert and may not send it
                    $this.alertService.AddAlert([AlertType]::AUDIT, $message, [Guid]::NewGuid())               
                }
                # Send out the alert messages
                $this.alertService.Send()
            }
        }
        # Update the last run marker
        $this.lastRun = Get-Date
    }

    # Create database query metadata for the items that need to be monitored
    # and add them to the monitor
    PopulateAuditMetadata() {
        
        # Too bad we don't have a REST API to get these audit entries :(

        # Audit_Projects
        [DBQueryMetadata] $auditProject = [DBQueryMetadata]::new()
        $auditProject.name = "Project"
        $auditProject.sql = "select * from CxActivity.dbo.Audit_Projects where [TimeStamp] >= @lastRun"
        $auditProject.meta["Action"] = "Event"
        $auditProject.meta["Name"] = "ProjectName"
        $auditProject.meta["User"] = "OwnerName"
        $auditProject.meta["Timestamp"] = "TimeStamp"
        $this.AddDBQueryMetadata($auditProject)

        # Audit_Presets
        [DBQueryMetadata] $auditPresets = [DBQueryMetadata]::new()
        $auditPresets.name = "Preset"
        $auditPresets.sql = "select * from CxActivity.dbo.Audit_Presets where [TimeStamp] >= @lastRun"
        $auditPresets.meta["Action"] = "Event"
        $auditPresets.meta["Name"] = "PresetName"
        $auditPresets.meta["User"] = "OwnerName"
        $auditPresets.meta["Timestamp"] = "TimeStamp"
        $this.AddDBQueryMetadata($auditPresets)

        # Audit_Queries
        [DBQueryMetadata] $auditQueries = [DBQueryMetadata]::new()
        $auditQueries.name = "Query"
        $auditQueries.sql = "select * from CxActivity.dbo.Audit_Queries where [TimeStamp] >= @lastRun"
        $auditQueries.meta["Action"] = "Event"
        $auditQueries.meta["Name"] = "Name"
        $auditQueries.meta["User"] = "OwnerName"
        $auditQueries.meta["Timestamp"] = "TimeStamp"
        $this.AddDBQueryMetadata($auditQueries)

        # Audit Results
        [DBQueryMetadata] $auditResults = [DBQueryMetadata]::new()
        $auditResults.name = "Results"
        # Modifed version of the CxDB.dbo.[GetAllLabelsForScanByProject] stored procedure
        $auditResults.sql = 
        "SELECT DISTINCT 
        labels.[StringData] AS Action,
        labels.[UpdateDate] AS [Timestamp],
        labels.[UpdatingUser] AS Username, 
        projects.[Name] AS ProjectName, 
        queryVersion.[Name] As QueryName,
        nodeResults.File_Name AS [File], 
        nodeResults.Line, 
        nodeResults.Col	AS [Column]
        FROM 
        CxDB.dbo.ResultsLabels labels
        INNER JOIN CxDB.dbo.Projects projects ON labels.[ProjectId] = projects.[Id]
        INNER JOIN CxDB.dbo.PathResults scanPaths ON scanPaths.[Similarity_Hash] = labels.[SimilarityId]
        INNER JOIN CxDB.dbo.QueryVersion queryVersion ON scanPaths.QueryVersionCode = queryVersion.QueryVersionCode
        INNER JOIN CxDB.dbo.NodeResults nodeResults ON nodeResults.[ResultId] = labels.[ResultId] AND nodeResults.Path_Id = labels.PathID AND nodeResults.Node_Id = 1
        LEFT JOIN (
            SELECT QueryVersion.QueryVersionCode FROM CxDB.dbo.QueryVersion INNER JOIN CxDB.dbo.QueryGroup ON QueryVersion.PackageId  = QueryGroup.PackageId) QueryIDs2 
        ON  QueryIDs2.QueryVersionCode = scanPaths.QueryVersionCode
        WHERE labels.LabelType=1 and labels.UpdateDate >= @lastRun"

        $auditResults.meta.Add("Action", "Action")
        $auditResults.meta.Add("Query", "QueryName")
        $auditResults.meta.Add("Project", "ProjectName")
        $auditResults.meta.Add("File", "File")
        $auditResults.meta.Add("Line", "Line")
        $auditResults.meta.Add("Column", "Column")
        $auditResults.meta.Add("User", "Username")
        $auditResults.meta.Add("Timestamp", "Timestamp")
        $this.AddDBQueryMetadata($auditResults)        
    }
}


# -----------------------------------------------------------------
# Queue Monitor
# -----------------------------------------------------------------
Class QueueMonitor {

    hidden [IO] $io
    # Threshold for number of scans in queued state
    hidden [int] $queuedScansThreshold
    # Threshold for time spent in queued state (minutes)
    hidden [TimeSpan] $queuedTimeThreshold
    # Algo that estimates scan duration
    hidden [ScanTimeAlgo] $scanTimeAlgo
    hidden [AlertService] $alertService
    hidden [RESTClient] $cxSastRestClient
    hidden [DateTimeUtil] $dateUtil
    
    # CxSAST 8.9 Scan Stages
    # New, PreScan, Queued, Scanning, PostScan, Finished, Canceled, Failed, SourcePullingAndDeployment, None

    # Prior-to-Running states
    static [String[]] $queuedStates = @("New", "Queued", "SourcePullingAndDeployment", "PreScan")

    # Running States
    static [String[]] $runningStates = @("Scanning", "PostScan")

    # Failed States
    static [String[]] $failedStates = @("Failed")

    # Finished States
    static [String[]] $finishedStates = @("Canceled", "Deleted", "Finished")    

    # Constructs a QueueMonitor
    QueueMonitor ([ScanTimeAlgo] $scanTimeAlgo, [AlertService] $alertService) {
        $this.io = [IO]::new()
        $this.dateUtil = [DateTimeUtil]::new()
        $this.queuedScansThreshold = $script:config.monitor.thresholds.queuedScansThreshold
        $this.queuedTimeThreshold = [TimeSpan]::FromMinutes($script:config.monitor.thresholds.queuedTimeThresholdMinutes)
        $this.scanTimeAlgo = $scanTimeAlgo
        $this.alertService = $alertService
    }

    # Check on the CxSAST queue
    Monitor() {
        # Create a RESTBody specific to CxSAST REST API calls
        $cxSastRestBody = [RESTBody]::new($script:CX_REST_GRANT_TYPE, $script:CX_REST_SCOPE, $script:CX_REST_CLIENT_ID, $script:CX_REST_CLIENT_SECRET)
        # Create a REST Client for CxSAST REST API
        $this.cxSastRestClient = [RESTClient]::new($script:config.cx.host, $cxSastRestBody)
        
        # Login to the CxSAST server
        [bool] $isLoginOk = $this.cxSastRestClient.login($script:config.cx.username, $script:config.cx.password)

        if ($isLoginOk -eq $True) {
            # Fetch Queue Status
            $qStatusResp = $this.GetQueueStatus()
        
            # Process the response
            $this.ProcessResponse($qStatusResp)

            # Check Portal responsiveness
            $this.CheckPortalResponsiveness()
        }
        
    }

    # Check for Portal responsiveness
    CheckPortalResponsiveness() {
        # Check portal responsiveness
        $stopwatch = [system.diagnostics.stopwatch]::StartNew()
        $response = $this.GetLoginPage()
        $stopwatch.Stop()

        # NOTE: Watch out for the condition where the Invoke-WebRequest -TimeoutSec is smaller than the restResponseThresholdSeconds threshold
        if ($response) {
            if ($response.StatusCode -eq 200) {
                $this.io.Log("Portal is responsive. Portal responded in [$($stopwatch.elapsed.TotalSeconds)] seconds.")
            }
            else {
                $this.io.LogEvent("Portal responded with HTTP [$($response.StatusCode)]")
            }
        }
        
        # Check if the portal response exceeded threshold
        if ($stopwatch.elapsed.TotalSeconds -gt $script:config.monitor.thresholds.restResponseThresholdSeconds) {
            $message = "Slow Portal response. Response Time: [$($stopWatch.elapsed.TotalSeconds)] seconds. Threshold: [$($script:config.monitor.thresholds.restResponseThresholdSeconds)] seconds."
            $this.io.LogEvent($message)
            $this.alertService.AddAlert([AlertType]::PORTAL_SLOW, $message, "")
        }
    }

    # Fetches the status of jobs in the CxSAST scan queue
    [Object] GetQueueStatus () {
        [String] $apiUrl = "/sast/scansQueue"
        return $this.cxSastRestClient.invokeAPI($apiUrl, [RESTMethod]::GET, $null, $script:config.monitor.apiResponseTimeoutSeconds)
    }

    # Try to fetch the portal login /CxWebClient/Login.aspx page
    # proxy for portal performance
    [Object] GetLoginPage () { 
        [Object] $resp = $null
        [String] $pageUrl = $script:config.cx.host + "/CxWebClient/Login.aspx"
        try {     
            $resp = Invoke-WebRequest -UseBasicParsing -Uri $pageUrl -TimeoutSec $script:config.monitor.apiResponseTimeoutSeconds
        }
        catch {
            $resp = $_.Exception.Response
            $this.io.Log("ERROR: [$($_.Exception.Message)]")
        }
        return $resp
    }    

    # Processes response from CxSAST Queue Status REST API call
    ProcessResponse ([Object] $apiResp) {

        # If there are entries in the queue
        if ($apiResp.Count -gt 0) {

            # Split entries for processing
            [Object[]] $queuedEntries = $apiResp | Where-Object { [QueueMonitor]::queuedStates -contains $_.stage.value }
            [Object[]] $runningEntries = $apiResp | Where-Object { [QueueMonitor]::runningStates -contains $_.stage.value }
            [Object[]] $failedEntries = $apiResp | Where-Object { [QueueMonitor]::failedStates -contains $_.stage.value }
            [Object[]] $finishedEntries = $apiResp | Where-Object { [QueueMonitor]::finishedStates -contains $_.stage.value }

            $this.io.LogEvent("Queued: $($queuedEntries.Count), Running: $($runningEntries.Count), Failed: $($failedEntries.Count), Finished: $($finishedEntries.Count)")

            # Save the queuedEntries to cross-check against idle engines later
            $script:queuedEntriesDto = $queuedEntries

            # Process finished scans first, so that we can derive thresholds
            $this.ProcessFinishedScans($finishedEntries) 
            $this.ProcessQueuedScans($queuedEntries) 
            $this.ProcessRunningScans($runningEntries) 
            $this.ProcessFailedScans($failedEntries)             
        }
    }    
    
    # Processes Finished scans.
    # Finished scans are interesting because we can 
    # derive a good estimate of the next similar
    # scan's exec time.
    # The ScanTimeAlgo injected into the QueueMonitor
    # will determine how exactly the estimate is 
    # calculated.
    ProcessFinishedScans ([Object[]] $finishedScans) {

        # If we don't have anything to process, return    
        if (!$finishedScans -or $finishedScans.Count -eq 0) {
            return
        }

        # Store scan info for next scan duration estimate calculations
        foreach ($scan in $finishedScans) {
            $this.scanTimeAlgo.StoreScanDuration($scan)
        }        
    }

    # Processes Queued scans.
    # There are two primary areas of interest here:
    #   1. Number of scans in the queue
    #   2. How long scans stay in the queued state
    ProcessQueuedScans ([Object[]] $queuedScans) {

        # If we don't have anything to process, return
        if (!$queuedScans -or $queuedScans.Count -eq 0) {
            return
        }

        # JSON structures for queue monitor
        [PSCustomObject] $queueScanExcess = $null

        # If the number of scans in the queue exceeds 
        # a threshold, send out an alert.
        # If an alert has been sent, 
        #       wait for a configurable number of minutes before checking 
        #       if the number of queued items has increased since the last time the alert was sent
        #  before sending out the next alert
        
        if ($queuedScans -and $queuedScans.Count -gt $this.queuedScansThreshold) {
            [String] $alertMsg = "Queued: [$($queuedScans.Count)]. Threshold: [$($this.queuedScansThreshold)]"
            $this.alertService.AddAlert([AlertType]::QUEUE_SCAN_EXCESS, $alertMsg, "") 
            # Create a JSON structure for the excess scans
            [PSCustomObject] $queueScanExcess = [ordered] @{
                EventDate = ""
                ScansQueued = "$($queuedScans.Count)"
                Threshold   = "$($this.queuedScansThreshold)"
            }
        }

        # For every queued scan  
        [System.Collections.ArrayList] $scanIds = @()
        foreach ($scan in $queuedScans) {
            
            $scanIds.Add($scan.Id)
            
            # Calculate queued time
            [DateTime] $dateCreated = [Xml.XmlConvert]::ToDateTime($scan.dateCreated)
            [String] $queuedDate = ""
            if ($scan.queuedOn) {
                [DateTime] $queuedOn = [Xml.XmlConvert]::ToDateTime($scan.queuedOn)
                $queuedDate = $this.dateUtil.ToUTCAndFormat($queuedOn)
            }
            [DateTime] $now = Get-Date
            [TimeSpan] $queuedTIme = New-TimeSpan -Start $dateCreated -End $now

            # If the queued duration exceeds a threshold, send an alert.
            # The threshold is provided as a configurable parameter.
            if ($queuedTIme -gt $this.queuedTimeThreshold) {
                
                [String] $scanInfo = $this.GetScanIdentifierForHumans($scan)
                [String] $scanKey = $this.GetKey($scan)
                [String] $alertMsg = "$scanInfo. Queued: [$queuedTIme]. Threshold: [$($this.queuedTimeThreshold)]"
                $this.alertService.AddAlert([AlertType]::QUEUE_SCAN_TIME_EXCEEDED, $alertMsg, $scanKey) 

                # Create a JSON structure for scans that exceed threshold for queued state
                [PSCustomObject] $scanDetail = [ordered] @{
                    EventDate       = ""
                    Threshold       = "$($this.queuedTimeThreshold)"
                    ScanId          = "$($scan.Id)"
                    ProjectId       = "$($scan.project.id)"
                    ProjectName     = "$($scan.project.name)"
                    Origin          = "$($scan.origin)"
                    IsPublic        = "$($scan.isPublic)"
                    IsIncremental   = "$($scan.isIncremental)"
                    ScanRequestDate = "$($this.dateUtil.ToUTCAndFormat($dateCreated))"
                    QueuedDate      = "$queuedDate"
                }  
                $this.io.WriteJSON([AlertType]::QUEUE_SCAN_TIME_EXCEEDED, $scanDetail) 
            }  
        } 

        # If there are excess scans in the queue
        # write out the corresponding JSON file
        if ($queueScanExcess) {
            $queueScanExcess.Add("ScanIDs", $scanIds)
            $this.io.WriteJSON([AlertType]::QUEUE_SCAN_EXCESS, $queueScanExcess) 
        }  
        
        # Sends out alerts if there are any
        $this.alertService.Send()                 
    }

    # Processes Running scans
    ProcessRunningScans ([Object[]] $runningScans) {

        foreach ($scan in $runningScans) {
            
            [double] $estimatedMinutes = $this.scanTimeAlgo.Estimate($scan)
            $estimated = [TimeSpan]::FromMinutes($estimatedMinutes)
            
            # Calculate elapsed time
            [double] $elapsedMinutes = $this.scanTimeAlgo.GetScanDuration($scan)
            $elapsed = [TimeSpan]::FromMinutes($elapsedMinutes)
                        
            [String] $scanInfo = $this.GetScanIdentifierForHumans($scan) + " Elapsed: [$elapsed]. Threshold: duration [$estimated]"
            
            # If the scan duration exceeds estimate
            # mark the scan as 'slow'.
            if ($elapsedMinutes -gt $estimatedMinutes) {
                $scanKey = $this.GetKey($scan)
                $this.alertService.AddAlert([AlertType]::SCAN_SLOW, $scanInfo, $scanKey)

                # Create a JSON structure for slow scans that exceed estimated threshold
                [DateTime] $dateCreated = [Xml.XmlConvert]::ToDateTime($scan.dateCreated)
                [PSCustomObject] $scanDetail = [ordered] @{
                    EventDate                         = ""
                    ScanId                            = "$($scan.id)"
                    ProjectId                         = "$($scan.project.id)"
                    ProjectName                       = "$($scan.project.name)"
                    Origin                            = "$($scan.origin)"
                    IsIncremental                     = "$($scan.isIncremental)"
                    ScanRequestDate                   = "$($this.dateUtil.ToUTCAndFormat($dateCreated))"
                    Loc                               = "$($scan.loc)"
                    ScanStatus                        = "$($scan.stage.value)"
                    ScanDurationMilliseconds          = "$($elapsedMinutes * 60 * 1000)"
                    EstimatedScanDurationMilliseconds = "$($estimatedMinutes * 60 * 1000)"
                    ScannedLanguages                  = $scan.languages          
                }  
                $this.io.WriteJSON([AlertType]::SCAN_SLOW, $scanDetail)
            }
            else {
                # Log scan data
                $this.io.LogEvent($scanInfo)
            }
        }

        # Sends out alerts if there are any
        $this.alertService.Send()
    }

    # Processes Failed scans
    # Sends out alerts for failed scans
    ProcessFailedScans ([Object[]] $failedScans) {
        
        [System.Collections.ArrayList] $failedScans = @()

        foreach ($scan in $failedScans) {            
            $scanInfo = $this.GetScanIdentifierForHumans($scan)
            $scanKey = $this.GetKey($scan)
            $reason = $scan.stageDetails
            if ($reason) { $reason = "(Reason: $reason)" }
            $this.alertService.AddAlert([AlertType]::SCAN_FAILED, "$scanInfo $reason", $scanKey)

            [DateTime] $dateCreated = [Xml.XmlConvert]::ToDateTime($scan.dateCreated)

            # Create JSON structure for failed scans
            [PSCustomObject] $failed = [ordered] @{     
                EventDate        = ""       
                ScanId           = "$($scan.id)"
                ProjectId        = "$($scan.project.id)"
                ProjectName      = "$($scan.project.name)"
                Origin           = "$($scan.origin)"
                IsPublic         = "$($scan.isPublic)"
                IsIncremental    = "$($scan.isIncremental)"
                ScanRequestDate  = "$($this.dateUtil.ToUTCAndFormat($dateCreated))"
                Loc              = "$($scan.loc)"
                FailReason       = "$reason"
                ScannedLanguages = $scan.languages
            }
            $this.io.WriteJSON([AlertType]::SCAN_FAILED, $failed)
        }

        # Sends out alerts only if there are any
        $this.alertService.Send()
    }

    # Returns a human readable Scan Identifier
    [String] GetScanIdentifierForHumans($scan) {
        [String] $scanType = if ($scan.isIncremental -eq $True) { "Incremental" } else { "Full" }
        return "Scan [id: $($scan.id), project: $($scan.project.Name), type: $scanType, stage: $($scan.stage.value), loc: $($scan.loc), stage/total %: $($scan.stagePercent)/$($scan.totalPercent), engine: $($scan.engine.id)]"
    } 

    # Returns a machine readable Scan key
    [String] GetKey([Object] $scan) {
        [String] $scanType = if ($scan.isIncremental -eq $True) { "I" } else { "F" }
        return "$($scan.id)_$($scan.project.Name)_$scanType"
    } 
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
#
# Execution entry
#
# -----------------------------------------------------------------
# -----------------------------------------------------------------

# Check if PS v5+
$psv = $PSVersionTable.PSVersion.Major
if ($psv -and $psv -lt 5) {
    Write-Host "Requires PSv5 and greater."
    Exit
}

# Load configuration
[PSCustomObject] $config = [Config]::new().GetConfig()
# Override if values were explicitly overridden via the commandline
if ($cxUser) { $config.cx.username = $cxUser }
if ($cxPass) { $config.cx.password = $cxPass }
if ($dbUser) { $config.cx.db.username = $dbUser }
if ($dbPass) { $config.cx.db.password = $dbPass }


# Create an IO utility object
[IO] $io = [IO]::new()

# Create the Alert Service
[AlertService] $alertService = [AlertService]::new()

# Load a scan time estimation algo
[ScanTimeAlgo] $scanTimeAlgo = [DefaultScanTimeAlgo]::new()

# Create Queue Monitor and inject dependencies - scan duration calculator and alerting service
[QueueMonitor] $qMonitor = [QueueMonitor]::new($scanTimeAlgo, $alertService)

# Create Engine(s) monitor
[EngineMonitor] $engineMonitor = [EngineMonitor]::new($alertService)

if ($audit) {
    # Create a DB Client
    [DBClient] $dbClient = [DBClient]::new($config.cx.db.instance, $config.cx.db.username, $config.cx.db.password)

    # Create Audit(s) monitor
    [AuditMonitor] $auditMonitor = [AuditMonitor]::new($alertService)
    # Inject a DB Client
    $auditMonitor.SetDbClient($dbClient)
}

# Spit out pretty headers
$io.WriteHeader()

# Force TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

[Object[]] $queuedEntriesDto = $null

# Continuous monitoring
$io.Log("Monitoring CxSAST Health")
while ($True) {
        
    # Process Queue Status response
    $qMonitor.Monitor()

    # Check the engine(s)
    $engineMonitor.Monitor()

    # Poll Audit DBs
    if ($audit) {
        $auditMonitor.Monitor()
    }

    # Wait a bit before polling again
    Start-Sleep -Seconds $script:config.monitor.pollIntervalSeconds
}
