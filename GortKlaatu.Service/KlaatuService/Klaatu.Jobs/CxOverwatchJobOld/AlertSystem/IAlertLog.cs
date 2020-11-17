// --------------------------------------------------------------------------------------------------------------------
// Converted from CxOverwatch by Phillip H. Blanton (https://Gort.co)
// </copyright>
// <summary>
//   Defines the IAlertLog type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace Klaatu.Jobs
{
	public interface IAlertLog
	{
		bool Send(string message);

	}

}
