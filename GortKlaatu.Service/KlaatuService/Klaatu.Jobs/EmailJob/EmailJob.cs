// --------------------------------------------------------------------------------------------------------------------
// <copyright file="EmailJob.cs" company="Gort Technology">
//   Copyright ©2017 Gort Technology
// </copyright>
// <summary>
//   Defines the EmailJob type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.IO;
using System.Threading.Tasks;
using Quartz;
using Quartz.Util;
using LogManager = NLog.LogManager;
using System.Net.Mail;
using Klaatu.Core;

namespace Klaatu.Jobs
{
	//	using Klaatu.KlaatuConnector.KlaatuServiceReference;

	/// <summary>
	/// Class Definition
	/// </summary>
	public class EmailJob : IJob
	{
		/// <summary>
		/// The Logger
		/// </summary>
		private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

		#region Parameter Properties

		/// <summary>
		/// Gets or sets a value indicating whether to log the work only
		/// </summary>
		public bool LogOnly { get; set; }

		/// <summary>
		/// Relative path to the outbox.
		/// </summary>
		public string RelativeOutboxDir { get; set; }

		/// <summary>
		/// Relative path to the outbox.
		/// </summary>
		public string RelativeSentboxDir { get; set; }

		/// <summary>
		/// Email incoming server name
		/// </summary>
		public string SmtpServerName { get; set; }

		/// <summary>
		/// Emailaddress Parameter
		/// </summary>
		public string SmtpSender { get; set; }

		/// <summary>
		/// Incoming IMAP Port
		/// </summary>
		public int SmtpPort { get; set; }

		/// <summary>
		/// Password parameter
		/// </summary>
		public string SmtpPassword { get; set; }

		/// <summary>
		/// UseSsl parameter
		/// </summary>
		public bool SmtpUseSsl { get; set; }

		//private string LogOnlyText => LogOnly ? "LogOnly" : "";
		private string LogOnlyText
		{
			get { if (LogOnly) return "LogOnly"; return ""; }
		}


		#endregion // Parameter Properties

		/// <summary>
		/// Executes the job
		/// </summary>
		/// <returns>True or False</returns>
		public bool ExecuteJob()
		{
			Logger.Trace("EmailJob::ExecuteJob" + LogOnlyText + " - Start");

			string outboxPath = Path.Combine(Utilities.CurrentDirectory, RelativeOutboxDir);

			if (!Directory.Exists(outboxPath))
			{
				Logger.Info("EmailJob::ExecuteJob{0} - There is no outbox defined at {1}. No messages to send. Skipping.", LogOnlyText, outboxPath);
				return true;
			}

			// Get any email objects in the outbox...
			string[] files = Directory.GetFiles(outboxPath, "*.email");
			if (files.Length == 0)
			{
				Logger.Info("EmailJob::ExecuteJob{0} - There were no messages to send. Finished.", LogOnlyText);
				return true;
			}

			SmtpClient smtpClient = new SmtpClient(SmtpServerName, SmtpPort);
			smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;

			try
			{
				// If we get here then we have emails to send and a valid SMTPClient with which to send them...
				foreach (string emailFile in files)
				{
					if (LogOnly)
					{
						Logger.Info("EmailJob::ExecuteJobLogOnly - Here's where we'd send the email message contained in {0} Skipping instead.", Path.GetFileName(emailFile));
						continue;
					}

					Logger.Info("EmailJob::ExecuteJob - Sending email '{0}'", Path.GetFileName(emailFile));

					EmailJobMessage emailJobMessage = new EmailJobMessage(emailFile);
					MailMessage eMailMsg = new MailMessage();
					eMailMsg.IsBodyHtml = true;
					eMailMsg.Body += emailJobMessage.Body;
					eMailMsg.BodyEncoding = System.Text.Encoding.UTF8;
					eMailMsg.Subject = emailJobMessage.Subject;
					eMailMsg.SubjectEncoding = System.Text.Encoding.UTF8;
					eMailMsg.From = new MailAddress(SmtpSender, "Checkmarx Notify");//.From = new MailAddress(SmtpSender);

					string[] emailToList = emailJobMessage.ToList.Split(';');
					foreach (string addr in emailToList)
					{
						if (string.IsNullOrEmpty(addr))
							continue;
						try
						{
							eMailMsg.To.Add(new MailAddress(addr));
						}
						catch (Exception ex)
						{
							Logger.Error("EmailJob::ExecuteJob - Error handling email address {0}. The error is {1}", addr, ex.Message);
							// swallow the error after logging and keep going
						}

					}

					string[] emailCCList = emailJobMessage.CcList.Split(';');
					foreach (string addr in emailCCList)
					{
						if (string.IsNullOrEmpty(addr))
							continue;
						try
						{
							eMailMsg.CC.Add(new MailAddress(addr));
						}
						catch (Exception ex)
						{
							Logger.Error("EmailJob::ExecuteJob - Error handling email address {0}. The error is {1}", addr, ex.Message);
							// swallow the error after logging and keep going
						}

					}

					string[] emailBCCList = emailJobMessage.BccList.Split(';');
					foreach (string addr in emailBCCList)
					{
						if (string.IsNullOrEmpty(addr))
							continue;
						try
						{
							eMailMsg.Bcc.Add(new MailAddress(addr));
						}
						catch (Exception ex)
						{
							Logger.Error("EmailJob::ExecuteJob - Error handling email address {0}. The error is {1}", addr, ex.Message);
							// swallow the error after logging and keep going
						}
					}

					try
					{
						smtpClient.Send(eMailMsg);
						MoveEmailMessage(emailFile);
						Logger.Info("EmailJob::ExecuteJob - Mail Sent");

						// send async not working for some reason
						//smtpClient.SendAsync(eMailMsg, emailFile);
					}
					catch (Exception ex)
					{
						Logger.Error("EmailJob::ExecuteJob - Error sending email from file '{0}'; Error was '{1}'.", Path.GetFileName(emailFile), ex.Message);
						// After logging, swallow error so we can keep going.
					}
					finally
					{
						// clean up...
						eMailMsg.Dispose();
					}
				}
			}
			catch (Exception ex)
			{
				Logger.Error("EmailJob::ExecuteJob - Unknown error sending email. Error was '{0}'.", ex.Message);
				return false;
			}
			finally
			{
				if (smtpClient != null)
					smtpClient.Dispose();
			}

			string switchtext = LogOnly ? "skipping" : "sending";
			Logger.Info("EmailJob::ExecuteJob" + LogOnlyText + " - Finished " + switchtext + " " + files.Length + " messages.");
			return true;
		}

		private void MoveEmailMessage(string filename)
		{
			if (!string.IsNullOrEmpty(filename))
			{
				string filepart = Path.GetFileName(filename);
				if (!string.IsNullOrEmpty(filepart))
				{
					Logger.Info("EmailJob::ExecuteJob - Message {0} sent. Moving file to SentBox.", filepart);

					string sentBox = Path.Combine(Utilities.CurrentDirectory, RelativeSentboxDir);
					if (!Directory.Exists(sentBox))
						Directory.CreateDirectory(sentBox);

					File.Move(filename, Path.Combine(sentBox, filepart));
				}
			}
		}

		/// <summary>
		/// The ExecuteInternal method
		/// </summary>
		/// <param name="context">Passed in context</param>
		public Task Execute(IJobExecutionContext context)
		{
			try
			{
				Logger.Debug("EmailJob::ExecuteInternal" + LogOnlyText + " start");

				if (ExecuteJob())
					Logger.Info("EmailJob::ExecuteInternal{0} - Process data end succeeded", LogOnlyText);
				else
					Logger.Error("EmailJob::ExecuteInternal{0} - Process data end FAILURE!", LogOnlyText);

				Logger.Info(context.NextFireTimeUtc != null
					 ? string.Format("EmailJob::ExecuteInternal{0} - Finished. Next fire time='{1}'", LogOnlyText, context.NextFireTimeUtc.Value.ToLocalTime())
					 : string.Format("EmailJob::ExecuteInternal{0} - Finished. This job is not scheduled to fire again", LogOnlyText));
			}
			catch (Exception ex)
			{
				Logger.Error("EmailJob" + LogOnlyText + ex);
			}
			return Task.CompletedTask;
		}
	}
}
