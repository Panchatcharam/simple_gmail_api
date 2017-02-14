// trying.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "email_access.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iterator>

using std::fstream;
using namespace googleapis;

int main()
{
	std::unique_ptr<GmailSample> gmail(new GmailSample());
	// Construct secret path
	wchar_t result[MAX_PATH];
	std::wstring exePath(result, GetModuleFileName(NULL, result, MAX_PATH));
	std::string appPath(exePath.begin(), exePath.end());
	gmail->SetAppPath(appPath.substr(0, appPath.find_last_of("\\")));

	googleapis::util::Status status = gmail->Startup();
	if (!status.ok()) 
	{
		std::cerr << "Could not initialize application." << std::endl;
		std::cerr << status.error_message() << std::endl;
		return -1;
	}

	gmail->Run();
	std::cout << "Email Reading complete!!"<<std::endl;
	if (gmail->m_uiCount)
	{
		std::cout<<"The encrypted files are available at " << gmail->GetAppPath() + "\\encrypt\\" << std::endl;
	}
	else
	{
		std::cout << "No emails found for the specified period" << std::endl;
	}
	std::cout << "Press any Key to Exit..." << std::endl;
	std::cin.get();
	return 0;
}

GmailSample::GmailSample(): crypto(new Encryptor()), 
						    config_(new HttpTransportLayerConfig()),
						    retrievalPeriodStart(0),
							retrievalPeriodEnd(0),
						    strAppPath(""),
							m_uiCount(0),
							strStartPeriod(""),
							strEndPeriod("")
{
}

void GmailSample::SetAppPath(std::string & path)
{
	this->strAppPath = path;
}

std::string GmailSample::GetAppPath()
{
	return this->strAppPath;
}

void GmailSample::Run()
{
	std::cout <<"Getting User Authorization" << std::endl;
	googleapis::util::Status status = Authorize();
	if (!status.ok())
	{
		std::cout << "Could not authorize: " << status.error_message() << std::endl;
		return;
	}

	std::cout <<"\nStart reading Gmail emails " << std::endl;
	std::cout<<std::endl;
	ReadEmailMessages();
}

util::Status GmailSample::Startup()
{
	// Set up HttpTransportLayer.
	googleapis::util::Status status;
	config_.reset(new HttpTransportLayerConfig);
	client::HttpTransportFactory* factory =
		new client::CurlHttpTransportFactory(config_.get());
	config_->ResetDefaultTransportFactory(factory);
	std::string secretPath = GetAppPath() + "\\secret\\client_secret.json";

	// Set up OAuth 2.0 flow for getting credentials to access personal data.
	flow_.reset(OAuth2AuthorizationFlow::MakeFlowFromClientSecretsPath(\
		secretPath, config_->NewDefaultTransportOrDie(), &status));

	if (!status.ok())
	{
		return status;
	}

	flow_->set_default_scopes(GmailService::SCOPES::GMAIL_READONLY);
	flow_->mutable_client_spec()->set_redirect_uri(OAuth2AuthorizationFlow::kOutOfBandUrl);
	flow_->set_authorization_code_callback(
		NewPermanentCallback(&PromptShellForAuthorizationCode, flow_.get()));

	string home_path("");
	status = FileCredentialStoreFactory::GetSystemHomeDirectoryStorePath(&home_path);
	if (status.ok()) 
	{
		FileCredentialStoreFactory store_factory(home_path);
		// Use a credential store to save the credentials between runs so that
		// we dont need to get permission again the next time we run. We are
		// going to encrypt the data in the store, but leave it to the OS to
		// protect access since we do not authenticate users in this sample.
#if HAVE_OPENSSL
		OpenSslCodecFactory* openssl_factory = new OpenSslCodecFactory;
		status = openssl_factory->SetPassphrase(
			flow_->client_spec().client_secret());
		if (!status.ok()) return status;
		store_factory.set_codec_factory(openssl_factory);
#endif
		flow_->ResetCredentialStore(store_factory.NewCredentialStore("gmailConsoleApp", &status));
	}

	if (!status.ok())
	{
		return status;
	}

	// Now we'll initialize the gmail api service proxy that we'll use
	// to interact with the email from this sample program.
	HttpTransport* transport = config_->NewDefaultTransport(&status);
	if (!status.ok())
	{
		return status;
	}
	service_.reset(new GmailService(transport));
	return status;
}

util::Status GmailSample::Authorize()
{
	string email("");
	do
	{
		std::cout << "\n Please enter a valid Google Email Address : ";
		std::getline(std::cin, email);
	} while (!ValidateUserName(email).ok());

	do
	{
		do
		{
			std::cout << "\n Enter Start of the retrieval Period (yyyy/mm/dd) : ";
			std::getline(std::cin, strStartPeriod);
		} while ((retrievalPeriodStart = ParseMilliSecElapsed(strStartPeriod)) == 0);

		do
		{
			std::cout << "\n Enter End of the retrieval Period (yyyy/mm/dd) : ";
			std::getline(std::cin, strEndPeriod);
		} while ((retrievalPeriodEnd = ParseMilliSecElapsed(strEndPeriod,true)) == 0);

		if (retrievalPeriodStart > retrievalPeriodEnd)
		{
			std::cout << "\n Start period cannot be greater than end period" << std::endl;
		}
	} while (retrievalPeriodStart > retrievalPeriodEnd);

	OAuth2RequestOptions options = {};
	options.email = email;
	googleapis::util::Status status = flow_->RefreshCredentialWithOptions(options, &credential_);
	if (!status.ok())
	{
		return status;
	}

	credential_.set_flow(flow_.get());
	std::cout << "\nAuthorized " << email << std::endl;
	return StatusOk();
}

int64 GmailSample::ParseMilliSecElapsed(const string& date, bool endDate)
{
	time_t rawtime = 0;
	struct tm * timeinfo = {};
	time_t timeElapsed = 0;
	std::vector<std::string> token;
	char sep = '/';
	for (size_t p = 0, q = 0; p != date.npos; p = q)
	{
		token.push_back(date.substr(p + (p != 0), (q = date.find(sep, p + 1)) - p - (p != 0)));
	}

	if (token.size() == 3)
	{
		int year(std::stoi(token[0])), month(std::stoi(token[1])), day(std::stoi(token[2]));
		if (ValidateDate(month, day,year))
		{
			time(&rawtime);
			timeinfo = localtime(&rawtime);
			timeinfo->tm_year = year - 1900;
			timeinfo->tm_mon = month - 1;
			timeinfo->tm_mday = day;
			timeinfo->tm_hour = endDate ? 23 : 0;
			timeElapsed = (mktime(timeinfo) * 1000);
		}
	}

	if (timeElapsed == 0)
	{
		std::cout << "\n Invalid Date Format" <<std::endl;
	}
	else if (!endDate && (timeElapsed > (time(nullptr) * 1000)))
	{
		std::cout << "\n Start date cannot be future date" << std::endl;
		timeElapsed = 0;
	}

	return timeElapsed;
}

bool GmailSample::ValidateDate(int month, int day, int year)
{
	if (!(1 <= month && month <= 12))
		return false;
	if (!(1 <= day && day <= 31))
		return false;
	if ((day == 31) && (month == 2 || month == 4 || month == 6 || month == 9 || month == 11))
		return false;
	if ((day == 30) && (month == 2))
		return false;
	if ((month == 2) && (day == 29) && (year % 4 != 0))
		return false;
	if ((month == 2) && (day == 29) && (year % 400 == 0))
		return true;
	if ((month == 2) && (day == 29) && (year % 100 == 0))
		return false;
	if ((month == 2) && (day == 29) && (year % 4 == 0))
		return true;

	return true;
}

void GmailSample::ReadEmailMessages()
{
	int64 uiProgCount = 0;
	int64 uiReadCount = 0;
	bool readComplete = false;

	std::string format("");
	const StringPiece userId(credential_.email());
	std::unique_ptr<UsersResource_MessagesResource_ListMethod> method(
		service_->get_users().get_messages().NewListMethod(&credential_, userId));
	client::JsonCppArray<string > vec = method->get_label_ids();
	//std::string date = "in:inbox after:2014/01/01 before:2014/01/30";
	std::string query = "in:inbox after:"+strStartPeriod+"before:"+strEndPeriod;
	method->set_q(query);
	method->set_max_results(1000);
	method->set_pretty_print(true);
	std::unique_ptr<ListMessagesResponse> msg_list(ListMessagesResponse::New());
	while (!readComplete)
	{
		//std::cout << "\n Page Token: " << method->get_page_token() << std::endl;
		util::Status listReadStstus = method->ExecuteAndParseResponse(msg_list.get());
		if (!listReadStstus.ok())
		{
			std::cout << listReadStstus.error_message() << std::endl;
			return;
		}

		if (msg_list.get()->has_messages())
		{
			Json::Value val = msg_list->Storage("messages");
			int64 msgDate = 0;
			//std::cout << "\n Total Message: " << msg_list.get()->get_result_size_estimate() << std::endl;
			//std::cout << "\n  Page Token: " << msg_list.get()->get_next_page_token() << std::endl;
			for( auto itr = val.begin(); itr != val.end(); ++itr)
			{
				{
					std::string	msgId = static_cast<Json::Value>(*itr).get("id", "UTF-16").asString();
					UsersResource_MessagesResource_GetMethod msgMethod(service_.get(),&credential_, userId, msgId);
					std::unique_ptr<Message> msg(Message::New());
					util::Status msgReadStatus = msgMethod.ExecuteAndParseResponse(msg.get());
					if (!msgReadStatus.ok())
					{
						std::cout<< msgReadStatus.error_message()<<std::endl;
						return;
					}

					msgDate = msg.get()->get_internal_date();
					if ((msgDate >= retrievalPeriodStart) && (msgDate <= retrievalPeriodEnd))
					{
						m_uiCount++;
						std::stringbuf strbuf;
						std::ostream ostr(&strbuf);
						msg.get()->StoreToJsonStream(&ostr);
						std::ofstream ofs;
						std::string path = GetAppPath() + "\\encrypt\\" + msgId + ".json";
						ofs.open(path, std::ios::out | std::ios::app);
						ofs << strbuf.str();
						ofs.close();
						crypto->EncryptGivenFile(const_cast<char*>(path.c_str()));
					}
					else if (msgDate < retrievalPeriodStart)
					{
						readComplete = true;
						break;
					}
					uiReadCount++;
				}
				
				switch (++uiProgCount)
				{
				case 1:
					format = "Reading email.  (Read Count : %d, Process count : %d)\r";
					break;
				case 2:
					format = "Reading email.. (Read Count : %d, Process count : %d)\r";
					break;
				case 3:
					format = "Reading email...(Read Count : %d, Process count : %d)\r";
					break;
				default:
					format = "Reading email   (Read Count : %d, Process count : %d)\r";
					uiProgCount = 0;
					break;
				}
				printf(format.c_str(), uiReadCount, m_uiCount);
			}
		}
		if (!readComplete && msg_list.get()->has_next_page_token())
		{
			method->set_page_token(msg_list.get()->get_next_page_token().as_string());
			method->mutable_http_request()->Clear();
			method->mutable_http_request()->set_credential(&credential_);
			msg_list->Clear();
		}
		else
		{
			readComplete = true;
		}
	}
	std::cout << std::endl;
}

OAuth2AuthorizationFlow* OAuth2AuthorizationFlow::MakeFlowFromClientSecretsPath(
	const string& path, HttpTransport* transport,
	googleapis::util::Status* status)
{
	// Open file
	std::ifstream ifs;
	ifs.open(path, std::ifstream::in);

	// Determine that no error has occured
	if (!ifs.fail())
	{
		std::string str((std::istreambuf_iterator<char>(ifs)),std::istreambuf_iterator<char>());
		ifs.close();
		return MakeFlowFromClientSecretsJson(str, transport, status);
	}
	else
	{
		ifs.close();
		std::cout << "\n Unable to read secret file, press any key to exit!!!" << std::endl;
		std::cin.get();
		exit(EXIT_FAILURE);
	}
}

googleapis::util::Status GmailSample::PromptShellForAuthorizationCode(OAuth2AuthorizationFlow* flow,
	const OAuth2RequestOptions& options,
	string* authorization_code)
{
	string url = flow->GenerateAuthorizationCodeRequestUrlWithOptions(options);
	std::cout << std::endl;
	std::cout << "Please enter the following URL into a browser:\n" << url << std::endl;
	std::cout << std::endl;
	std::cout << "Enter the browser's response to confirm authorization: ";

	authorization_code->clear();
	std::cin >> *authorization_code;
	if (authorization_code->empty())
	{
		return StatusCanceled("Canceled");
	}
	else
	{
		return StatusOk();
	}
}

googleapis::util::Status GmailSample::ValidateUserName(const string& name)
{
	if (name.empty())
	{
		std::cout << "\n Username empty" << std::endl;
		return StatusInvalidArgument("");
	}
	else if (name.find("/") != string::npos)
	{
		std::cout << "\n UserNames cannot contain '/'" << std::endl;
		return StatusInvalidArgument("");
	}
	else if (name.find(" ") != string::npos)
	{
		std::cout << "\n UserNames cannot contain space" << std::endl;
		return StatusInvalidArgument("");
	}
	else if (name.find("@gmail.com") == string::npos)
	{
		std::cout << "\n UserName does not contain @gmail.com" << std::endl;
		return StatusInvalidArgument("");
	}
	else if (name == "." || name == "..")
	{
		std::cout << "\n " << name << " is not a valid UserName" << std::endl;
		return StatusInvalidArgument("");
	}
	return StatusOk();
}