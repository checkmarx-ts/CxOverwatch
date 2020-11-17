// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SampleJob.cs" company="Gort Technology">
//   Copyright ©2020 Phillip H. Blanton (https://Gort.co)
// </copyright>
// <summary>
//   Defines the SampleJob type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using LogManager = NLog.LogManager;
using Quartz;
using Quartz.Util;

namespace Klaatu.Jobs
{
	/// <summary>
	/// Class Definition
	/// </summary>
	public class SampleJob : IJob
	{
		private static readonly NLog.Logger Logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.Name);

		/// <summary>
		/// Gets or sets a value indicating whether to log the work only
		/// </summary>
		public bool LogOnly { get; set; }

		/// <summary>
		/// Test Message
		/// </summary>
		public string Message { get; set; }

		/// <summary>
		/// Gets LogOnly text if the job is running in LogOnly mode.
		/// </summary>
		private string LogOnlyText => LogOnly ? "-LogOnly" : string.Empty;

		/// <summary>
		/// Executes the job
		/// </summary>
		/// <returns>True or False</returns>
		public bool ExecuteJob(IJobExecutionContext context)
		{
			Logger.Trace("KlaatuJob::ExecuteJob - Start");

			//This job only prints out its job name and the date and time that it is running
			JobKey jobKey = context.JobDetail.Key;
			var name = $"Name: {jobKey.Name}";
			var group = !jobKey.Group.IsNullOrWhiteSpace() ? $", Group: {jobKey.Group}" : "";
			Logger.Info("SampleJob::ExecuteJob{0} is executed at {1:r} with JobKey({2} {3})", LogOnlyText, DateTime.Now, name, group);

			// Do something here...

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
				Logger.Debug($"SampleJob::Execute{LogOnlyText} start");

				var executed = ExecuteJob(context);

				Logger.Debug(executed
					? $"SampleJob::Execute{LogOnlyText} Process data end succeeded"
					: $"SampleJob::Execute{LogOnlyText} Process data end failed");

				if (context.NextFireTimeUtc != null)
				{
					Logger.Debug($"SampleJob::Execute{LogOnlyText} Execute finished. Message='{Message}'. Next fire time='{context.NextFireTimeUtc.Value.ToLocalTime()}'");
				}
			}
			catch (Exception ex)
			{
				Logger.Error($"SampleJob{LogOnlyText}=>{ex}");
			}
			return Task.CompletedTask;
		}


	}
}