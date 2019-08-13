<#
    Checkmarx CxSAST Health Monitoring System
    Version 1.0
    Gem Immauel (gem.immanuel@checkmarx.com)
    Checkmarx Professional Services

    Usage: .\CxHealthMonitor.ps1 [-cxUser cxaccount] [-cxUser cxpassword]

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
    $cxPass = ""    
)

# CxSAST REST API auth values
[String] $CX_REST_GRANT_TYPE = "password"
[String] $CX_REST_SCOPE = "sast_rest_api"
[String] $CX_REST_CLIENT_ID = "resource_owner_client"
[String] $CX_REST_CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"

# -----------------------------------------------------------------
# Input/Output Utility
# -----------------------------------------------------------------
Class IO {
    
    static [String] $LOG_FILE = "cx_health_mon.log"
    static [String] $EVENT_FILE = "cx_health_mon_events.log"

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

    # Write a pretty header output
    WriteHeader() {
        Write-Host "-----------------------------------------" -ForegroundColor Green
        Write-Host "Checkmarx Health Monitor" -ForegroundColor Green        
        Write-Host "Checkmarx CxSAST: $($script:config.cx.host)"
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
        filter timestamp { "$(Get-Date -Format G): $_" }
        return $message | timestamp
    }
}

# -----------------------------------------------------------------
# Abstract Alert System
# -----------------------------------------------------------------
Class AlertSystem {
    
    [String] $name = "Unknown Name. Alert System Name not explicitly set."
    [String] $systemType = "Unknown system type. Alert System Type not explicitly set."
    [IO] $io = [IO]::new()

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
        [String] $timestamp = Get-Date -Format "MMM dd HH:mm:ss"

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

    # Constructs the email alert system object
    EmailAlertSystem ([String] $systemType, [String] $name, [String] $smtpHost, [int] $smtpPort, [String] $smtpUsername, [String] $smtpPassword, [String] $smtpSender, [String[]] $recipients, [String] $subject) {
        $this.io = [IO]::new()
        $this.systemType = $systemType
        $this.name = $name
        $this.smtpHost = $smtpHost
        $this.smtpPort = $smtpPort
        $this.smtpSender = $smtpSender
        $this.recipients = $recipients
        $this.subject = $subject
        [CredentialsUtil] $credUtil = [CredentialsUtil]::new()
        $this.smtpCredentials = $credUtil.GetPSCredential($smtpUsername, $smtpPassword)

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
            Send-MailMessage -From $this.smtpSender -Body $message -Subject $this.subject -To $this.recipients -Priority High -SmtpServer $this.smtpHost -Port $this.smtpPort -UseSsl -Credential $this.smtpCredentials                             
        }
        catch {
            $this.io.Log("ERROR: [$($_.Exception.Message)] Could not send email alert. Verify email configuration.")
        }
    }
}

# Enumerates types of alerts that we send
# Helps keep track of which type of alert
# was sent when and for which scan/project.
Enum AlertType {
    SCAN_FAILED
    SLOW_SCAN
    SCAN_TOO_LONG_IN_QUEUE
    TOO_MANY_SCANS_IN_QUEUE
    ENGINE_NOT_RESPONDING
    ENGINE_SLOW_TO_RESPOND
    SLOW_API_CALLS
    ENGINE_OFFLINE
    SLOW_ENGINE
    SLOW_PORTAL
    ENGINE_ERROR
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
        # Register alerting systems specified in configuratoin file
        foreach ($alertingSystem in $script:config.alertingSystems) {
    
            # For now, we register each type of alerting systems separately.
            # Enhancement would be to have configuration self-declare system type
            # and have a factory create the system for you :)    

            # Register SMTP systems, if configured
            if ($alertingSystem.smtp) {
                foreach ($smtpSystem in $alertingSystem.smtp) {
                    [AlertSystem] $emailAlertSystem = [EmailAlertSystem]::new($smtpSystem.systemType, $smtpSystem.name, $smtpSystem.host, $smtpSystem.port, $smtpSystem.user, $smtpSystem.password, $smtpSystem.sender, $smtpSystem.recipients, $smtpSystem.subject)    
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
                    $batchMessage += "$message`n"
                }
                $alertSystem.Send($batchMessage) 
            }
            else {
                foreach ($message in $this.alerts) {
                    $alertSystem.Send($message)
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
        [String] $key = $this.GetKey($scan)
        
        # Add scan if no prior scans exist for given key
        if (!$this.scanHistory.containsKey($key)) {
            # TODO: This table will need to be flushed either on a timely basis, or some other criteria
            $this.scanHistory.Add($key, $scan)
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
    login ([String] $username, [String] $password) {
        $body = @{
            username      = $username
            password      = $password
            grant_type    = $this.restBody.grantType
            scope         = $this.restBody.scope
            client_id     = $this.restBody.clientId
            client_secret = $this.restBody.clientSecret
        }
    
        try {
            $loginUrl = $this.baseUrl + "/auth/identity/connect/token"
            $response = Invoke-RestMethod -uri $loginUrl -method POST -body $body -contenttype 'application/x-www-form-urlencoded'
        }
        catch {
            $this.io.Log("StatusCode:" + $_.Exception.Response.StatusCode.value__)
            $this.io.Log("StatusDescription:" + $_.Exception.Response.StatusDescription)
            throw "Could not authenticate against Checkmarx REST API"
        }
    
        # Track token internally
        $this.token = $response.token_type + " " + $response.access_token
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
# Engine(s) Monitor
# -----------------------------------------------------------------
Class EngineMonitor {

    hidden [IO] $io
    hidden [AlertService] $alertService
    hidden [RESTClient] $cxSastRestClient
    
    # Constructs a EngineMonitor
    EngineMonitor ([AlertService] $alertService) {
        $this.io = [IO]::new()
        $this.alertService = $alertService
    }

    Monitor() {
        # Create a RESTBody specific to CxSAST REST API calls
        $cxSastRestBody = [RESTBody]::new($script:CX_REST_GRANT_TYPE, $script:CX_REST_SCOPE, $script:CX_REST_CLIENT_ID, $script:CX_REST_CLIENT_SECRET)
        # Create a REST Client for CxSAST REST API
        $this.cxSastRestClient = [RESTClient]::new($script:config.cx.host, $cxSastRestBody)
        # Login to the CxSAST server
        $this.cxSastRestClient.login($script:config.cx.username, $script:config.cx.password)

        # Fetch Queue Status
        $resp = $this.GetEngineStatus()
        
        # Process the response
        $this.ProcessResponse($resp)
    }

    # Fetches the status of the engines
    [Object] GetEngineStatus () {        
        [String] $apiUrl = "/sast/engineServers"
        $resp = $this.cxSastRestClient.invokeAPI($apiUrl, [RESTMethod]::GET, $null, $script:config.monitor.apiResponseTimeoutSeconds)
        return $resp
    }

    # Try to reach the specific engine's WSDL
    [Object] GetEngineWSDL ($apiUri) { 
        [Object] $resp = $null
        for ($i = 0; $i -lt $script:config.monitor.retries; $i++) {             
            try {     
                $resp = Invoke-WebRequest -Uri $apiUri -TimeoutSec $script:config.monitor.apiResponseTimeoutSeconds
                break
            }
            catch {
                $resp = $_.Exception.Response
                $this.io.Log("ERROR: [$($_.Exception.Message)]")
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

                # Try connecting if not offline
                if ($engine.status.value -eq "Offline") {
                    $this.alertService.AddAlert([AlertType]::ENGINE_OFFLINE, $engineInfo, $engineInfo)
                }
                else {
                    # Attempt to access the Engine's WSDL and report response time
                    $stopwatch = [system.diagnostics.stopwatch]::StartNew()
                    $wsdlResp = $this.GetEngineWSDL($engine.uri)
                    $stopwatch.Stop()   
                    
                    $this.io.Log($engineInfo + " Responded in [$($stopwatch.elapsed.TotalSeconds)] seconds.")

                    # Log any response other than HTTP 200 OK
                    if ($wsdlResp.StatusCode -ne [system.net.httpstatuscode]::OK) {
                        $message = $engineInfo + " Responded [$($wsdlResp.StatusCode)] instead of [OK]"
                        $this.io.LogEvent($message)
                        $this.alertService.AddAlert([AlertType]::ENGINE_ERROR, $message, $engineInfo)
                    }

                    # Check API call elapsed time
                    if ($stopwatch.elapsed.TotalSeconds -gt $script:config.monitor.thresholds.engineResponseThresholdSeconds) {
                        $message = $engineInfo + " Response Time: [$($stopWatch.elapsed.TotalSeconds)] seconds. Threshold: [$($script:config.monitor.thresholds.engineResponseThresholdSeconds)] seconds."
                        $this.io.LogEvent($message)
                        $this.alertService.AddAlert([AlertType]::SLOW_ENGINE, $message, $engineInfo) 
                    }

                }
            }
            # Send out alerts
            $this.alertService.Send()

        }
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
        $this.cxSastRestClient.login($script:config.cx.username, $script:config.cx.password)

        # Fetch Queue Status
        $stopwatch = [system.diagnostics.stopwatch]::StartNew()
        $qStatusResp = $this.GetQueueStatus()
        $stopwatch.Stop()

        $this.io.Log("Portal is responsive. Get Queue Information responded in [$($stopwatch.elapsed.TotalSeconds)] seconds.")

        # TODO: Assumption is that this is a good proxy for Portal responsiveness
        if ($stopwatch.elapsed.TotalSeconds -gt $script:config.monitor.thresholds.restResponseThresholdSeconds) {
            $message = "Slow Portal response. Response Time: [$($stopWatch.elapsed.TotalSeconds)] seconds. Threshold: [$($script:config.monitor.thresholds.restResponseThresholdSeconds)] seconds."
            $this.io.LogEvent($message)
            $this.alertService.AddAlert([AlertType]::SLOW_PORTAL, $message, "")
        }

        # Process the response
        $this.ProcessResponse($qStatusResp)
    }

    # Fetches the status of jobs in the CxSAST scan queue
    [Object] GetQueueStatus () {
        [String] $apiUrl = "/sast/scansQueue"
        return $this.cxSastRestClient.invokeAPI($apiUrl, [RESTMethod]::GET, $null, $script:config.monitor.apiResponseTimeoutSeconds)
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

        # If the number of scans in the queue exceeds 
        # a threshold, send out an alert.
        # If an alert has been sent, 
        #       wait for a configurable number of minutes before checking 
        #       if the number of queued items has increased since the last time the alert was sent
        #  before sending out the next alert
        if ($queuedScans -and $queuedScans.Count -gt $this.queuedScansThreshold) {
            [String] $alertMsg = "Queued: [$($queuedScans.Count)]. Threshold: [$($this.queuedScansThreshold)]"
            $this.alertService.AddAlert([AlertType]::TOO_MANY_SCANS_IN_QUEUE, $alertMsg, "") 
        }

        # For every queued scan  
        foreach ($scan in $queuedScans) {
             
            # Calculate queued time
            [DateTime] $dateCreated = [Xml.XmlConvert]::ToDateTime($scan.dateCreated)
            [DateTime] $now = Get-Date
            [TimeSpan] $queuedTIme = New-TimeSpan -Start $dateCreated -End $now

            # If the queued duration exceeds a threshold, send an alert.
            # The threshold is provided as a configurable parameter.
            if ($queuedTIme -gt $this.queuedTimeThreshold) {
                
                [String] $scanInfo = $this.GetScanIdentifierForHumans($scan)
                [String] $scanKey = $this.GetKey($scan)
                [String] $alertMsg = "$scanInfo. Queued: [$queuedTIme]. Threshold: [$($this.queuedTimeThreshold)]"
                $this.alertService.AddAlert([AlertType]::SCAN_TOO_LONG_IN_QUEUE, $alertMsg, $scanKey) 
            }
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
                $this.alertService.AddAlert([AlertType]::SLOW_SCAN, $scanInfo, $scanKey)
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
        
        foreach ($scan in $failedScans) {            
            $scanInfo = $this.GetScanIdentifierForHumans($scan)
            $scanKey = $this.GetKey($scan)
            $reason = $scan.stageDetails
            if ($reason) { $reason = "(Reason: $reason)" }
            $this.alertService.AddAlert([AlertType]::SCAN_FAILED, "$scanInfo $reason", $scanKey)
        }

        # Sends out alerts only if there are any
        $this.alertService.Send()
    }

    # Returns a human readable Scan Identifier
    [String] GetScanIdentifierForHumans($scan) {
        [String] $scanType = if ($scan.isIncremental -eq $True) { "Incremental" } else { "Full" }
        return "Scan [$($scan.id), $($scan.project.Name), $scanType, $($scan.stage.value)]"
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


# Create an IO utility object
$io = [IO]::new()

# Create the Alert Service
[AlertService] $alertService = [AlertService]::new()

# Load a scan time estimation algo
[ScanTimeAlgo] $scanTimeAlgo = [DefaultScanTimeAlgo]::new()

# Create Queue Monitor and inject dependencies - scan duration calculator and alerting service
[QueueMonitor] $qMonitor = [QueueMonitor]::new($scanTimeAlgo, $alertService)

# Create Engine(s) monitor
[EngineMonitor] $engineMonitor = [EngineMonitor]::new($alertService)

# Spit out pretty headers
$io.WriteHeader()

# Force TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Continuous monitoring
$io.Log("Monitoring CxSAST Health")
while ($True) {
        
    # Process Queue Status response
    $qMonitor.Monitor()

    # Check the engine(s)
    $engineMonitor.Monitor()

    # Wait a bit before polling again
    Start-Sleep -Seconds $script:config.monitor.pollIntervalSeconds
}
