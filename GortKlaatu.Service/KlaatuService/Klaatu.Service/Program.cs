// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Program.cs" company="Phasepoint">
//   Copyright ©2017 Gort Technology  
// </copyright>
// <summary>
//   Defines the Program type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System.ServiceProcess;

namespace Klaatu.Service
{
	/// <summary>
	/// The service program class
	/// </summary>
	public static class Program
	{
		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		public static void Main()
		{
			var qbService = new Service { ServiceName = "Klaatu.Service" };
			var servicesToRun = new ServiceBase[] { qbService };
#if (DEBUG)
			Gort.ServiceDebugger.ServiceLoader.StartServices(servicesToRun);
#else
			ServiceBase.Run(servicesToRun);
#endif
		}
	}
}
