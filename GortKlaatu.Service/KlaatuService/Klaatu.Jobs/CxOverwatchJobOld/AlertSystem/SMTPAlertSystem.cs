// --------------------------------------------------------------------------------------------------------------------
// Converted from CxOverwatch by Phillip H. Blanton (https://Gort.co)
// <summary>
//   Defines the SMTPAlertSystem type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Mail;
using System.ServiceModel.Description;
using NLog;

namespace Klaatu.Jobs
{
	class SMTPAlertSystem: IAlertLog
	{
		private static readonly Logger Logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.Name);

		private string _host;
		private int _port;
		private string _user;
		private string _password;
		private string _sender;
		private string _recipients;
		private string _subject;
		private bool _useSSL;
		private string _logOnlyText;
		private bool _logOnly;
		
		public SMTPAlertSystem(string host, int port, string user, string password, string sender, string recipients, bool useSSL, bool logOnly)
		{
			Logger.Info($"SMTPAlertSystem::Constructor - Start.");
			_host = host;
			_port = port;
			_user = user;
			_password = password;
			_sender = sender;
			_recipients = recipients;
			_useSSL = useSSL;
			_logOnlyText = logOnly ? "-LogOnly" : string.Empty;
			_logOnly = logOnly;
		}

		public bool Send(string message)
		{
			return Send(message, "Checkmarx Health Monitor Alert");
		}

		public bool Send(string message, string subject)
		{
			Logger.Info($"SMTPAlertSystem::Send{_logOnlyText} - Sending email alert to {_recipients}");

			SmtpClient smtpClient = null;
			try
			{
				if (_logOnly)
				{
					Logger.Info(
						"SMTPAlertSystem::Send-LogOnly - Here's where we'd send the email message; Skipping instead.");
					return true;
				}

				smtpClient = new SmtpClient(_host, _port);
				smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
				smtpClient.EnableSsl = _useSSL;

				// If credentials are provided then use 'em
				if (!string.IsNullOrEmpty(_user) && !string.IsNullOrEmpty(_password))
				{
					smtpClient.Credentials = new System.Net.NetworkCredential(_user, _password);
				}
				else
				{
					smtpClient.Credentials = CredentialCache.DefaultNetworkCredentials;
				}

				MailMessage eMailMsg = new MailMessage();
				eMailMsg.IsBodyHtml = true;
				eMailMsg.Body += message;
				eMailMsg.BodyEncoding = System.Text.Encoding.UTF8;
				eMailMsg.Subject = subject;
				eMailMsg.SubjectEncoding = System.Text.Encoding.UTF8;
				eMailMsg.From = new MailAddress(_sender, "Checkmarx Health Monitor");
				eMailMsg.Priority = MailPriority.High;

				string[] emailToList = _recipients.Split(';');
				foreach (string addr in emailToList)
				{
					var address = addr.Trim();
					if (string.IsNullOrEmpty(address))
						continue;
					try
					{
						eMailMsg.To.Add(new MailAddress(address));
						Logger.Info($"SMTPAlertSystem::Send - Adding {address} to recipients list.");
					}
					catch (Exception ex)
					{
						Logger.Error(
							$"SMTPAlertSystem::Send - Error adding email address {address}. The error is {ex.Message}");
						// swallow the error after logging and keep going
					}
				}

				try
				{
					smtpClient.Send(eMailMsg);
					Logger.Info("SMTPAlertSystem::Send - EMail Sent.");
				}
				catch (Exception ex)
				{
					Logger.Error($"SMTPAlertSystem::Send - Error sending email. Error was '{ex.Message}'.");
					return false;
				}
				finally
				{
					// clean up...
					eMailMsg.Dispose();
				}
			}
			catch (Exception ex)
			{
				Logger.Error($"SMTPAlertSystem::Send - Fatal exception building email. Error was '{ex.Message}'.");
				return false;
			}
			finally
			{
				smtpClient?.Dispose();
			}

			return true;
		}

	}
}
