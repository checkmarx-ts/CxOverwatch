// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AsyncService.cs" company="Gort Security">
//   Copyright 2017 Phillip H. Blanton
// </copyright>
// <summary>
//   Defines the AsyncService type for the Klaatu service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.Collections.Specialized;
using System.ServiceProcess;
using System.Threading;
using Quartz;
using Quartz.Impl;
using LogManager = NLog.LogManager;

namespace Klaatu.Service
{
	/// <summary>
	/// The async service.
	/// </summary>
	public partial class Service : ServiceBase
	{
		/// <summary>
		/// The Logger
		/// </summary>
		private static readonly NLog.Logger Logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType.Name);

		/// <summary>
		/// coordinate the keep alive logging thread
		/// </summary>
		private static readonly object SynchRoot = new object();

		/// <summary>
		/// Gets or sets a value indicating whether this is started.
		/// </summary>
		/// <value>
		/// <c>true</c> if started; otherwise, <c>false</c>.
		/// </value>
		public bool Started { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="Service"/> class. 
		/// Async service constructor
		/// </summary>
		public Service()
		{
			InitializeComponent();
		}

		/// <summary>
		/// on Start
		/// </summary>
		/// <param name="args">arguments</param>
		protected override void OnStart(string[] args)
		{
			Logger.Trace("Klaatu.Service::OnStart - KeepAlive");
			var workerThread = new Thread(this.KeepAlive);
			lock (SynchRoot)
			{
				this.Started = true;
				workerThread.Start();
			}
			Logger.Trace("Klaatu.Service::OnStart - Started = true keep alive, Start");
		}

		/// <summary>
		/// On Stop
		/// </summary>
		protected override async void OnStop()
		{ 
			Logger.Trace("Klaatu.Service::OnStop - Shutting down stopping keep alive thread, Stop");
			await _scheduler.Shutdown(true);
			SchedulerMetaData metaData = await _scheduler.GetMetaData();
			Logger.Info("Executed " + metaData.NumberOfJobsExecuted + " jobs.");
			Started = false;
		}

		#region Initialize
		private NameValueCollection _properties;
		private ISchedulerFactory _schedulerFactory;
		private IScheduler _scheduler;
		/// <summary>
		/// Initializes Scheduler Factory
		/// </summary>
		private async void Initialize()
		{
			// LoadConfiguration();
			if (_schedulerFactory == null)
			{
				if (_properties == null)
				{
					_properties = new NameValueCollection
					{
						["quartz.plugin.triggHistory.type"] = "Quartz.Plugin.History.LoggingJobHistoryPlugin, Quartz.Plugins",
						["quartz.plugin.jobInitializer.type"] = "Quartz.Plugin.Xml.XMLSchedulingDataProcessorPlugin, Quartz.Plugins",
						["quartz.plugin.jobInitializer.fileNames"] = "jobs.xml",
						["quartz.plugin.jobInitializer.failOnFileNotFound"] = "true",
						["quartz.plugin.jobInitializer.scanInterval"] = "120"
					};
				}
				_schedulerFactory = new StdSchedulerFactory(_properties);
			}
			_scheduler = await _schedulerFactory.GetScheduler();
		}
		#endregion Initialize

		#region KeepAlive
		/// <summary>
		/// keep the service alive until stopped
		/// </summary>
		private async void KeepAlive()
		{
			try
			{
				// First time through, initialize.
				if (_scheduler == null)
				{
					Initialize();
				}

				// start the scheduler
				try
				{
					await _scheduler.Start();
					Started = true;
					Logger.Info("Klaatu.Service::KeepAlive: Scheduler Started.");
				}
				catch (Exception ex)
				{
					Started = false;
					Logger.Error($"Klaatu.Service::KeepAlive: Fatal Error! Failed to start scheduler! '{ex.Message}'");
					return;
				}

				// Give the service 30 seconds to stabilize
				while (Started)
				{
					for (int i = 0; i < 30; i++)
					{
						lock (SynchRoot)
						{
							if (!Started)
							{
								Logger.Trace("Klaatu.Service::KeepAlive: Not Started.");
								return;
							}
						}
						Thread.Sleep(1000);
					}
					Logger.Info("Klaatu.Service::KeepAlive: Service Stable.");
				}
			}
			catch (Exception ex)
			{
				Logger.Error($"Klaatu.Service::KeepAlive: Fatal Error! '{ex.Message}'");
				throw;
			}
		}
		#endregion KeepAlive
	}
}