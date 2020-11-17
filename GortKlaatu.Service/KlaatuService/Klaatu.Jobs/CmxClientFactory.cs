using Klaatu.Core;
using Klaatu.Jobs.CxSDK;
using Klaatu.Jobs.CxWsResolver;
using System.ServiceModel;

namespace Klaatu.Jobs
{
	public static class CmxClientFactory
	{
		// Biggerize it if necessary...
		private const int CxApiSoapMessageSize = 20000000;

		/// <summary>
		/// The Logger
		/// </summary>
		private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

		private static string _sessionId;
		private static CxSDKWebServiceSoapClient _client;

		/// <summary>
		/// Valid session ID. Set during Initialization.
		/// </summary>
		public static string SessionId { get { return _sessionId; } }

		/// <summary>
		/// Initializes the WCF Connection to the CxWsWebClient.
		/// </summary>
		/// <returns>An initialized and connected instance of the CxWsWebClient.</returns>
		public static void InitializeClient(string cxApiUsername, string cxApiPassword)
		{
			Logger.Debug("CmxClientFactory::InitializeClient - Start");

			if (_client != null)
			{
				Logger.Info("CmxClientFactory::InitializeClient - Checkmarx Web Service Client is connected.");
				return;
			}

			Logger.Debug("CmxClientFactory::InitializeClient - Resolving SDK Endpoint");
			// Set the resolver URL in the app.config file.
			CxWSResolverSoapClient cxResolverProxy = new CxWSResolverSoapClient();
			int APIVersion = 1; // declaring for readability rather than just throwing a "1" into the call below.
			CxWSResponseDiscovery resolverResponse = cxResolverProxy.GetWebServiceUrl(CxWsResolver.CxClientType.SDK, APIVersion);

			if (!resolverResponse.IsSuccesfull)
			{
				// Failed to find endpoint.
				Logger.Error("CmxClientFactory::InitializeClient - Unable to resolve Cx Web Service.");
				return;
			}

			string sdkEndpoint = resolverResponse.ServiceURL;
			Logger.Debug("CmxClientFactory::InitializeClient - CxWsWebService Resolved Endpoint = " + sdkEndpoint);

			var binding = new BasicHttpsBinding
			{
				// Biggerize e'rthang 'cause sometimes the messages are too big for defaults.
				MaxReceivedMessageSize = CxApiSoapMessageSize,
				MaxBufferSize = CxApiSoapMessageSize,
				MaxBufferPoolSize = CxApiSoapMessageSize,
				ReaderQuotas =
				  {
						MaxDepth = 32,
						MaxArrayLength = CxApiSoapMessageSize,
						MaxStringContentLength = CxApiSoapMessageSize
				  },
				Security = { Mode = BasicHttpsSecurityMode.Transport },
				MessageEncoding = WSMessageEncoding.Text,
			};

			_client = new CxSDKWebServiceSoapClient(binding, new EndpointAddress(sdkEndpoint));

			Credentials cred = new Credentials()
			{
				User = Encoders.Base64Decode(cxApiUsername),
				Pass = Encoders.Base64Decode(cxApiPassword)
			};

			Logger.Info("CmxClientFactory::InitializeClient - Attempting Login");
			CxWSResponseLoginData loginResult = _client.Login(cred, 1033); // 1033 is the language ID for "English".
			_sessionId = loginResult.SessionId;

			if (string.IsNullOrEmpty(SessionId))
			{
				Logger.Error("CmxClientFactory::InitializeClient - Error: Invalid SessionID.");
				_client = null;
				return;
			}
			Logger.Debug("CmxClientFactory::InitializeClient - Success! CxAPI SessionID = " + SessionId + ".");
		}

		/// <summary>
		/// Gets the soap client used to communicate with Checkmarx
		/// </summary>
		public static CxSDKWebServiceSoapClient CxWsSoapClient
		{
			get
			{
				if (_client == null)
				{
					Logger.Error("CmxClientFactory::CxWsSoapClient - ERROR! The soap client isn't initialized. Call CmxClientFactory.Initialize(username, password) first.");
					return null;
				}
				return _client;
			}
		}

		public static void Close()
		{
			if (_client != null && _client.State != CommunicationState.Closed)
				_client.Close();
			_client = null;
		}
	}
}
