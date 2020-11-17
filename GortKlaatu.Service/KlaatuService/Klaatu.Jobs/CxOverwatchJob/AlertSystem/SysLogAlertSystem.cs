// --------------------------------------------------------------------------------------------------------------------
// Converted from CxOverwatch by Phillip H. Blanton (https://Gort.co)
// <summary>
//   Defines the SysLogAlertSystem type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Net.Sockets;
using System.Text;
using NLog;

namespace Klaatu.Jobs
{
	class SysLogAlertSystem: IAlertLog
	{
		public SysLogAlertSystem(string name, string syslogServer, int syslogPort, bool LogOnly)
		{
			_name = name;
			_syslogServer = syslogServer;
			_syslogPort = syslogPort;
			_logOnlyText = LogOnly ? "-LogOnly" : string.Empty;
		}

		private static readonly Logger Logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.Name);

		private string _syslogServer { get; set; }
		private int _syslogPort { get; set; }
		private string _logOnlyText { get; set; }
		private string _name { get; set; }

		private SyslogSeverity _syslogSeverity = SyslogSeverity.Info;
		public bool Send(string message, SyslogSeverity severity)
		{
			_syslogSeverity = severity;
			return Send(message);
		}

		// Sends given message over UDP to configured syslog server/port
		public bool Send(string message)
		{
			// If there is no message, not much to do
			if (string.IsNullOrEmpty(message))
			{
				return false;
			}

			// Prepend 'Checkmarx' as marker
			message = $"Checkmarx: {message}";

			// Syslog Facility 1 : User-level message 
			int facility = 1;
			string hostname = "??";
			// Calculate the priority        
			int priority = (facility * 8) + (int) _syslogSeverity;
			// "MMM dd HH:mm:ss" or "yyyy:MM:dd:-HH:mm:ss zzz"
			var timestamp = DateTime.Now.ToUniversalTime().ToString("MMM dd HH:mm:ss");

			// Syslog packet format
			var syslogMessage = $"<{priority}>{timestamp} {hostname} {message}";

			// Create encoded syslog packet
			Encoding ascii = Encoding.ASCII;
			Encoding unicode = Encoding.Unicode;

			byte[] unicodeBytes = unicode.GetBytes(syslogMessage);
			byte[] asciiBytes = Encoding.Convert(unicode, ascii, unicodeBytes);

			// Connect to the syslog server and send packet over UDP
			UdpClient udpClient = new UdpClient();
			udpClient.Connect(_syslogServer, _syslogPort);
			udpClient.Send(asciiBytes, asciiBytes.Length);

			Logger.Debug($"CxOverwatchJob::SysLogAlertSystem{_logOnlyText} - Sent syslog message to {_name} : {_syslogServer}");

			return true;
		}

	}

}
