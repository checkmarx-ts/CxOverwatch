// --------------------------------------------------------------------------------------------------------------------
// CxHealthCheck.cs
// <summary>
//   Defines the Kohl's CxHealthCheck Job type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Quartz;
using System.IO;
using Klaatu.Core;
using Quartz.Util;
using LogManager = NLog.LogManager;

namespace Klaatu.Jobs
{
	/// <summary>
	/// 
	/// </summary>
	public class CxHealthCheck : IJob
	{
		/// <summary>
		/// The Logger
		/// </summary>
		private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
		private static DateTime LastEmailSent;

		#region Configuration Parameters
		// These parameter values are loaded from the ProjectKiller.xml file.

		/// <summary>
		/// Gets or sets a value indicating whether to log the work only
		/// </summary>
		public bool LogOnly { get; set; }

		/// <summary>
		/// Test Message
		/// </summary>
		public string Message { get; set; }

		/// <summary>
		/// Delay between sending notification email. 
		/// The first time the service is detected as down an email will be sent, but more messages won't be sent more than once every this many minutes.
		/// </summary>
		public int NotificationSendDelayMinutes { get; set; }

		/// <summary>
		/// Checkmarx API Username
		/// </summary>
		public string CxApiUsername { get; set; }

		/// <summary>
		/// Checkmarx API Password
		/// </summary>
		public string CxApiPassword { get; set; }

		/// <summary>
		/// Relative Directory for serializing email message objects.
		/// </summary>
		public string EmailOutbox { get; set; }

		/// <summary>
		/// Subject Line for notification emails
		/// </summary>
		public string EmailSubjectLine { get; set; }

		/// <summary>
		/// Subject Line for notification emails
		/// </summary>
		public string EmailBody { get; set; }

		/// <summary>
		/// Semicolon-delimited list of email addresses to send the notifications to
		/// </summary>
		public string RecipientsTo { get; set; }

		/// <summary>
		/// Semicolon-delimited list of email addresses for the CC field.
		/// </summary>
		public string RecipientsCc { get; set; }

		/// <summary>
		/// Semicolon-delimited list of email addresses for the BCC field.
		/// </summary>
		public string RecipientsBcc { get; set; }

		#endregion Configuration Parameters

		#region Private Methods
		/// <summary>
		/// Empty of we are running for real.
		/// </summary>
		//private string LogOnlyText => LogOnly ? "LogOnly" : "";
		private string LogOnlyText
		{
			get { if (LogOnly) return "LogOnly"; return ""; }
		}

		#endregion Private Methods

		/// <summary>
		/// Executes the job
		/// </summary>
		/// <returns>True or False</returns>
		public bool ExecuteJob()
		{
			Logger.Info(message: $"CxHealthCheck::ExecuteJob{LogOnlyText} - Start");

			bool success = false;
			// Initialize Client
			try
			{
				var user = Encoders.Base64Decode(CxApiUsername);
				Logger.Info(message: $"CxHealthCheck::ExecuteJob{LogOnlyText} - Attempting Login as {user}");
				//TODO: Fix the Connected Services references then uncomment this.
				// Log in check the upness of the Checkmarx API. We log in the API even during "Logonly" operations. Logging in is safe.
				//CmxClientFactory.InitializeClient(CxApiUsername, CxApiPassword);
				//success = CmxClientFactory.CxWsSoapClient != null;
			}
			catch (Exception ex)
			{
				var errorText = ex.InnerException != null ? ex.InnerException.Message : "Unknown Error";
				Logger.Error(message: $"CxHealthCheck::ExecuteJob{LogOnlyText} - ERROR! Cound not initialize CxApiClient. Error was {errorText}");
				success = false;
			}
			finally
			{
				//TODO: Fix the Connected Services references then uncomment this.
				// CmxClientFactory.Close();
			}

			if (success)
			{
				Logger.Info(message: $"CxHealthCheck::ExecuteJob{LogOnlyText} - The Checkmarx system is up and responsive. Finished.");
				return true;
			}

			// If we get here, then the checkmarx service is down...
			Logger.Error(message: $"CxHealthCheck::ExecuteJob{LogOnlyText} - ERROR! Could not log into the CxWsSOAP Service! Checkmarx is unresponsive.");

			if (!LogOnly)
			{
				// Don't send an email more than once every NotificationSendDelayMinutes.
				if (LastEmailSent == null || LastEmailSent < DateTime.Now.AddMinutes(NotificationSendDelayMinutes * -1))
				{
					// Send email notification that the system is down
					string outboxPath = Path.Combine(Utilities.CurrentDirectory, EmailOutbox);
					if (!Directory.Exists(outboxPath))
						Directory.CreateDirectory(outboxPath);

					// Set computed variables
					string now = string.Format("{0:dddd, MMMM d, yyyy} at {0:t}", DateTime.Now);
					string subject = string.Format(EmailSubjectLine);
					string body = string.Format(EmailBody, now);

					// Send email...
					EmailJobMessage mailMessage = new EmailJobMessage(subject, body, RecipientsTo, RecipientsCc, RecipientsBcc);
					Logger.Info(message: $"CxHealthCheck::ExecuteJob{LogOnlyText} - Email message prepared for {RecipientsTo}");
					string filename = mailMessage.Serialize(outboxPath);

					if (string.IsNullOrEmpty(filename))
					{
						Logger.Error(message: $"CxHealthCheck::ExecuteJob - Error! Failed to serialize email message to {RecipientsTo} regarding Checkmarx being down. Cannot send email.");
						return false;
					}

					Logger.Debug(message: $"CxHealthCheck::ExecuteJob - Prepared email message to {RecipientsTo} regarding Checkmarx being down.");

					// the -10 seconds ensures that the next message is sent at the first run after the NotificationSendDelayMinutes have elapsed. 
					// The job runs about every five minutes and I didn't want to miss the next appropriate message by a few milliseconds.
					LastEmailSent = DateTime.Now.AddSeconds(-10);
				}
			}
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
				Logger.Debug(message: $"CxHealthCheck::ExecuteInternal{LogOnlyText} start.");

				if (ExecuteJob())
					Logger.Info(message: $"CxHealthCheck::ExecuteInternal{LogOnlyText} - Process data end succeeded");
				else
					Logger.Error(message: $"CxHealthCheck::ExecuteInternal{LogOnlyText} - Process data end FAILURE!");

				Logger.Info(context.NextFireTimeUtc != null
								? $"CxHealthCheck::ExecuteInternal{LogOnlyText} - ExecuteInternal finished. Next fire time='{context.NextFireTimeUtc.Value.ToLocalTime()}'."
								: $"CxHealthCheck::ExecuteInternal{LogOnlyText} - ExecuteInternal finished. This job is not scheduled to run again this session.");
			}
			catch (Exception ex)
			{
				Logger.Error(message: $"CxHealthCheck{LogOnlyText} - Error! {ex}");
			}
			return Task.CompletedTask;
		}

	}
}
