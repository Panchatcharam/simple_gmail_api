#pragma once
#include <memory>
#include <string>
#include "googleapis/client/auth/file_credential_store.h"
#include "googleapis/client/auth/oauth2_authorization.h"
#include "googleapis/client/data/data_reader.h"
#if HAVE_OPENSSL
#include "googleapis/client/data/openssl_codec.h"
#endif
#include "googleapis/client/transport/curl_http_transport.h"
#include "googleapis/client/transport/http_authorization.h"
#include "googleapis/client/transport/http_transport.h"
#include "googleapis/client/transport/http_request_batch.h"
#include "googleapis/client/util/status.h"
#include "googleapis/strings/strcat.h"
#include "google/gmail_api/gmail_api.h"
#include "google/gmail_api/list_messages_response.h"
#include "encryptor.h"

namespace googleapis 
{
	using google_gmail_api::GmailService;
	using google_gmail_api::Label;
	using google_gmail_api::ListLabelsResponse;
	using google_gmail_api::ListMessagesResponse;
	using google_gmail_api::Message;
	using google_gmail_api::UsersResource_LabelsResource_GetMethod;
	using google_gmail_api::UsersResource_LabelsResource_ListMethod;
	using google_gmail_api::UsersResource_MessagesResource_GetMethod;
	using google_gmail_api::UsersResource_MessagesResource_ListMethod;
	using google_gmail_api::UsersResource_MessagesResource_ListMethodPager;

	using client::ClientServiceRequest;
	using client::DateTime;
	using client::FileCredentialStoreFactory;
	using client::HttpRequestBatch;
	using client::HttpResponse;
	using client::HttpTransport;
	using client::HttpTransportLayerConfig;
	using client::JsonCppArray;
	using client::OAuth2Credential;
	using client::OAuth2AuthorizationFlow;
	using client::OAuth2RequestOptions;
#if HAVE_OPENSSL
	using client::OpenSslCodecFactory;
#endif
	using client::StatusCanceled;
	using client::StatusInvalidArgument;
	using client::StatusOk;

	class GmailSample
	{
	public:
		GmailSample();
		~GmailSample() {}
		googleapis::util::Status Startup();
		void Run();
		void SetAppPath(std::string & path);
		std::string GetAppPath();
		uint64 m_uiCount;

	private:
		// Gets authorization to access the user's personal calendar data.
		googleapis::util::Status Authorize();
		void ReadEmailMessages();
		static googleapis::util::Status PromptShellForAuthorizationCode(OAuth2AuthorizationFlow* flow,
			const OAuth2RequestOptions& options,
			string* authorization_code);
		googleapis::util::Status ValidateUserName(const string& name);
		int64 ParseMilliSecElapsed(const string& date, bool endDate = false);
		bool ValidateDate(int month, int day, int year);

		OAuth2Credential credential_;
		static std::unique_ptr<GmailService> service_;
		static std::unique_ptr<OAuth2AuthorizationFlow> flow_;
		std::unique_ptr<HttpTransportLayerConfig> config_;
		std::unique_ptr<Encryptor> crypto;
		int64 retrievalPeriodStart;
		int64 retrievalPeriodEnd;
		std::string strAppPath;
		std::string strStartPeriod;
		std::string strEndPeriod;
	};

	// static
	std::unique_ptr<GmailService> GmailSample::service_;
	std::unique_ptr<OAuth2AuthorizationFlow> GmailSample::flow_;
}
