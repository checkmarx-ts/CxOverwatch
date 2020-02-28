$msg = "Enter the username and password for the service account that will run the task and connect to the database"

#$credential = $Host.UI.PromptForCredential("Task username and passowrd", $msg, "$env:userdomain\$env:username", $env:userdomain)

$dbUser = $credential.UserName
$dbPass = $credential.GetNetworkCredential().Password
$CxOverwatchHome = "C:\ProgramData\checkmarx\CxOverwatch"
$TaskName = "Checkmarx CxOverwatch Monitor"
$TaskDescription = "Checkmarx CxOverwatch Monitoring - monitors the scan queue and engine status."

#$principal = $STPrin = New-ScheduledTaskPrincipal -UserId "NETWORK SERVICE" #-LogonType ServiceAccount

$action = New-ScheduledTaskAction -WorkingDirectory "$CxOverwatchHome" -Execute 'powershell.exe' -Argument "-File ${CxOverwatchHome}\CxHealthMonitor.ps1"

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 5) -ExecutionTimeLimit 0

$trigger_startup = New-ScheduledTaskTrigger -AtStartup # -Weekly -DaysOfWeek Sunday -At 8pm
$trigger_daily = New-ScheduledTaskTrigger -Once -At "12:00am" -RepetitionDuration (New-TimeSpan -Days (365 * 20)) -RepetitionInterval (New-TimeSpan -Hours 24)
$triggers = @()
$triggers += $trigger_startup
$triggers += $trigger_daily

Register-ScheduledTask -Action $action -Trigger $triggers -TaskName "${TaskName}" -Description "${TaskDescription}" -Settings $settings -User "$dbUser" -Password "$dbPass" #-Principal $principal
