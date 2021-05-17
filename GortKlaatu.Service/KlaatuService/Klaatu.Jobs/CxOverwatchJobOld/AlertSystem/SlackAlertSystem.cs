// --------------------------------------------------------------------------------------------------------------------
// Converted from CxOverwatch by Phillip H. Blanton (https://Gort.co)
// <summary>
//   Defines the SlackAlertSystem type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using NLog;

namespace Klaatu.Jobs
{
	class SlackAlertSystem : IAlertLog
	{
		private static readonly Logger Logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.Name);

		private string _hook;
		private string _logOnlyText;

		public SlackAlertSystem(string hook, bool logOnly)
		{
			_hook = hook;
			_logOnlyText = logOnly ? " - LogOnly" : string.Empty;
		}

		public bool Send(string message)
		{
			Logger.Info($"SlackAlertSystem::Send{_logOnlyText} - Sending Slack alert.");
			// This looks odd but it replaces the single backslash with double backslash.
			// Need to do this for the slack body
			// This may nt be necessary but I converted to code directly from the powershell script.
			message = message.Replace('\\', '\\');
			
			// message has to be in json format so Slack can parse it
			string body = $"{{\"text\":\"{message}\"}}";

			Uri uri = new Uri(_hook);

			var client = new RestClient(_hook, HttpVerb.POST, "application/json");
			var json = client.MakeRequest(body);

			return json.Length > 0;
		}
	}
}