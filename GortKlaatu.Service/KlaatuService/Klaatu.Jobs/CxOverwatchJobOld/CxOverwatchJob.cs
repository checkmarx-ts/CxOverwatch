// --------------------------------------------------------------------------------------------------------------------
// <copyright file="CxOverwatchJob.cs" company="Gort Technology">
//   Copyright ©2020 Phillip H. Blanton (https://Gort.co)
// </copyright>
// <summary>
//   Defines the CxOverwatchJob type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Quartz;
using Quartz.Util;
using LogManager = NLog.LogManager;

namespace Klaatu.Jobs
{
	/// <summary>
	/// Class Definition
	/// </summary>
	public class CxOverwatchJob : IJob
	{
		private static readonly NLog.Logger Logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.Name);

/*
 Standard Syslog Severities
*/
		#region Job Configuration Properties

		/// <summary>
		/// Gets or sets a value indicating whether to actually execute the job, or just do a test run and only log the job.
		/// </summary>
		public bool LogOnly { get; set; }
		private string LogOnlyText => LogOnly ? "-LogOnly" : string.Empty;

		/// <summary>
		/// Test Message
		/// </summary>
		public string Message { get; set; }
		
		#region CxAPI
		/// <summary>
		/// Host
		/// </summary>
		/// <returns>Host URL</returns>
		public string CxAPIHost { get; set; }

		/// <summary>
		/// User Name for accessing the CxAPI
		/// </summary>
		public string CxAPIUsername { get; set; }

		/// <summary>
		/// Password for accessing the CxAPI
		/// </summary>
		public string CxAPIPassword { get; set; }

		/// <summary>
		/// Checkmarx database connection string
		/// </summary>
		public string CxDBConnStr { get; set; }
		
		/// <summary>
		/// Checkmarx Database Username
		/// </summary>
		public string CxDBUser { get; set; }
		
		/// <summary>
		/// Checkmarx Database Password
		/// </summary>
		public string CxDBPassword { get; set; }

		#endregion //CxAPI

		#region Monitor

		/// <summary>
		/// UseUTCTimeOnClient: "true" or "false" - if true forces UTC for calculation of time on the client. Useful when script runs on a machine in a local time zone but server runs in UTC.
		/// </summary>
		public bool UseUTCTimeOnClient { get; set; }

		/// <summary>
		/// ApiResponseTimeoutSeconds: Specified in seconds, this is how long the monitor will wait for a response from the monitored system, before timing out and trying again (see 'retries').
		/// </summary>
		public int APIResponseTimeoutSeconds { get; set; }

		/// <summary>
		/// PollIntervalSeconds: Polling cadence - how often the monitor will connect to the Checkmarx server for monitoring purposes.
		/// </summary>
		public int PollIntervalSeconds { get; set; }

		/// <summary>
		/// QueuedScansThreshold: Threshold for the maximum number of scans in the CxSAST Queue, beyond which alerts will be sent.
		/// </summary>
		public int QueuedScansThreshold { get; set; }

		/// <summary>
		/// QueuedTimeThresholdMinutes: Threshold for the number of minutes a scan can remain in the CxSAST Queue, beyond which alerts will be sent.
		/// </summary>
		public int QueuedTimeThresholdMinutes { get; set; }

		/// <summary>
		/// ScanDurationThresholdMarginPercent: Additional duration (added as a percentage) to a scan's estimated duration, beyond which the scan will be marked 'slow'.
		/// </summary>
		public int ScanDurationThresholdMarginPercent { get; set; }

		/// <summary>
		/// ScanRateAsLOCPerHour: The scan rate, in Lines Of Code per hour - to be used in estimating a scan's expected duration.
		/// </summary>
		public int ScanRateAsLOCPerHour { get; set; }

		/// <summary>
		/// EngineResponseThresholdSeconds: Threshold (in seconds) for an engine to respond to the monitor's API call.
		/// </summary>
		public int EngineResponseThresholdSeconds { get; set; }

		/// <summary>
		/// RestResponseThresholdSeconds: Threshold (in seconds) for the CxManager to respond to the monitor's API call. This is a proxy for Portal responsiveness.
		/// </summary>
		public int RestResponseThresholdSeconds { get; set; }

		/// <summary>
		/// Retries: Number of times the monitor will attempt to connect to the monitored system before giving up.
		/// </summary>
		public int Retries { get; set; }

		#endregion //Monitor

		#region Alerts

		public bool WaitingPeriodBetweenAlertsMinutes { get; set; }
		public string SuppressionRegex { get; set; }

		/// <summary>
		/// AlertingSystem: Options are "SMTP", "Syslog" or "Slack"
		/// </summary>
		public string AlertingSystem { get; set; }

		#region SMTP Settings

		/// <summary>
		/// SMTP_Host : Hostname of the SMTP server.
		/// </summary>
		public string SMTP_Host { get; set; }

		/// <summary>
		/// SMTP_Port: Port number of the SMTP Server
		/// </summary>
		public int SMTP_Port { get; set; }

		/// <summary>
		/// SMTP_User: Username neede to access the SMTP server
		/// </summary>
		public string SMTP_User { get; set; }

		/// <summary>
		/// SMTP_Password: The password needed to acces the SMTP Server
		/// </summary>
		public string SMTP_Password { get; set; }

		/// <summary>
		/// SMTP_Sender: The sender's name for the alert email messages. Something like "CxOverwatch Checkmarx Health Check" works well.
		/// </summary>
		public string SMTP_Sender { get; set; }

		/// <summary>
		/// SMTP_Recipients: A list of email addresses to send the alert messages to.
		/// </summary>
		public string SMTP_Recipients { get; set; }

		/// <summary>
		/// SMTP_Subject: The subject line of the email Messages.
		/// </summary>
		public string SMTP_Subject { get; set; }

		/// <summary>
		/// SMTP_UseSSL: Should the SMTP client set the SSL/TLS flag for the server connection?
		/// </summary>
		public bool SMTP_UseSsl { get; set; }

		#endregion // SMTP Settings

		#region Syslog Settings

		/// <summary>
		/// SyslogName: The name of the Syslog. Options are Kiwi and Splunk
		/// </summary>
		public string SyslogName { get; set; }

		/// <summary>
		/// SyslogHost: The hostname of the Syslog server
		/// </summary>
		public string SyslogHost { get; set; }

		/// <summary>
		/// SyslogPort: The port on which the Syslog server is listening. Common ports are Kiwi: 514, Splunk: 515.
		/// </summary>
		public int SyslogPort { get; set; }

		#endregion //Syslog Settings

		#region Slack Settings

		/// <summary>
		/// SlackName: Normally "Slack".
		/// </summary>
		public string SlackName{ get; set; }

		/// <summary>
		/// SlackHook: ie: https://hooks.slack.com/services/xxxxxxxxxxxxxxxxxxx
		/// </summary>
		public string SlackHook{ get; set; }

		#endregion //Slack Settings


		#endregion //Alerts

		#endregion //Job Configuration Properties

		private IAlertLog _alertingSystem;

		private IAlertLog AlertSystem()
		{
			if (_alertingSystem == null)
			{
				if (AlertingSystem.ToUpper() == "SPLUNK" || AlertingSystem.ToUpper() == "KIWI")
				{
					Logger.Info($"CxOverwatchJob::AlertSystem{LogOnlyText}  - Initializing Syslog for {AlertingSystem}.");
					var result = _alertingSystem = new SysLogAlertSystem(AlertingSystem, SyslogHost, SyslogPort, LogOnly);
				}
				else if (AlertingSystem.ToUpper() == "SMTP")
				{
					Logger.Info($"CxOverwatchJob::AlertSystem{LogOnlyText}  - Initializing SMTP for {SMTP_Host}.");
					_alertingSystem = new SMTPAlertSystem(SMTP_Host, SMTP_Port, SMTP_User, SMTP_Password, SMTP_Sender, SMTP_Recipients, SMTP_UseSsl, LogOnly);
				}
				else if (AlertingSystem.ToUpper() == "SLACK")
				{
					Logger.Info($"CxOverwatchJob::AlertSystem{LogOnlyText}  - Initializing Slack interface for {SlackHook}.");
					_alertingSystem = new SlackAlertSystem(SlackHook, LogOnly);
				}
			}

			if (_alertingSystem == null)
			{
				Logger.Fatal($"CxOverwatchJob::AlertSystem{LogOnlyText}  - Fatal Error Initializing AlertSystem!");
				throw new Exception($"CxOverwatchJob::AlertSystem{LogOnlyText} - Fatal Error Initializing AlertSystem!");
			}

			return _alertingSystem;
		}

		/// <summary>
		/// Executes the job
		/// </summary>
		/// <returns>True or False</returns>
		public bool ExecuteJob(IJobExecutionContext context)
		{
			// If error encountered, log it and return false.
			Logger.Trace("CxOverwatchJob::ExecuteJob - Start");

			JobKey jobKey = context.JobDetail.Key;
			var name = $"Name: {jobKey.Name}";
			var group = !jobKey.Group.IsNullOrWhiteSpace() ? $", Group: {jobKey.Group}" : "";

			// Do the CxOverwatch Monitoring here...


			Logger.Info($"CxOverwatchJob::ExecuteJob{LogOnlyText}  - Execution completed at {DateTime.Now} with JobKey({name}{group})");
			return true;
		}

		/// <summary>
		/// The ExecuteInternal method
		/// </summary>
		/// <param name="context">Passed in context</param>
		public Task Execute(IJobExecutionContext context)
		{
			try
			{
				Logger.Debug($"CxOverwatchJob::Execute{LogOnlyText} - Start");

				var executed = ExecuteJob(context);

				Logger.Debug(executed
					? $"CxOverwatchJob::Execute{LogOnlyText} - Process data end succeeded"
					: $"CxOverwatchJob::Execute{LogOnlyText} - Process data end failed");

				if (context.NextFireTimeUtc != null)
				{
					Logger.Debug($"CxOverwatchJob::Execute{LogOnlyText} - Execute finished. Message='{Message}'. Next fire time='{context.NextFireTimeUtc.Value.ToLocalTime()}'");
				}
			}
			catch (Exception ex)
			{
				Logger.Error($"CxOverwatchJob{LogOnlyText}=>{ex}");
			}
			return Task.CompletedTask;
		}
	}

}