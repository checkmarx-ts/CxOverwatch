// --------------------------------------------------------------------------------------------------------------------
// Converted from CxOverwatch by Phillip H. Blanton (https://Gort.co)
// <summary>
//   Defines the RestClient type for the Klaatu async service.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

using System;
using System.IO;
using System.Net;
using System.Text;

namespace Klaatu.Jobs
{

	public class RestClient
	{
		public string EndPoint { get; set; }
		public HttpVerb Method { get; set; }
		public string ContentType { get; set; }
		public string PostData { get; set; }

		public RestClient()
		{
			EndPoint = "";
			Method = HttpVerb.GET;
			ContentType = "text/xml";
			PostData = "";
		}

		public RestClient(string endpoint, string contentType = "text/xml")
		{
			EndPoint = endpoint;
			Method = HttpVerb.GET;
			ContentType = contentType;
			PostData = "";
		}

		public RestClient(string endpoint, HttpVerb method, string contentType = "text/xml")
		{
			EndPoint = endpoint;
			Method = method;
			ContentType = contentType;
			PostData = "";
		}

		public string MakeRequest(string parameters)
		{
			var request = (HttpWebRequest) WebRequest.Create(EndPoint + parameters);

			request.Method = Method.ToString();
			request.ContentLength = 0;
			request.ContentType = ContentType;

			if (!string.IsNullOrEmpty(PostData) && Method == HttpVerb.POST)
			{
				var encoding = new UTF8Encoding();
				var bytes = Encoding.GetEncoding("iso-8859-1").GetBytes(PostData);
				request.ContentLength = bytes.Length;

				using (var writeStream = request.GetRequestStream())
				{
					writeStream.Write(bytes, 0, bytes.Length);
				}
			}

			using (var response = (HttpWebResponse) request.GetResponse())
			{
				var responseValue = string.Empty;

				if (response.StatusCode != HttpStatusCode.OK)
				{
					var message = String.Format("Request failed. Received HTTP {0}", response.StatusCode);
					throw new ApplicationException(message);
				}

				// grab the response
				using (var responseStream = response.GetResponseStream())
				{
					if (responseStream != null)
						using (var reader = new StreamReader(responseStream))
						{
							responseValue = reader.ReadToEnd();
						}
				}

				return responseValue;
			}
		}

	} // class

}
