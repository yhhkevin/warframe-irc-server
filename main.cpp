#include <iostream>


#include <console.hpp>
#include <dnsOsResolver.hpp>
#include <HttpRequestTask.hpp>
#include <IrcServer.hpp>
#include <json.hpp>
#include <netConfig.hpp>

#include <ServerWebService.hpp>
#include <sha256.hpp>
#include <Socket.hpp>

#include <urlenc.hpp>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <vector>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#ifdef DOCKER
#include <signal.h>
#endif

using namespace soup;

static std::string http_host;
static bool http_use_tls;

static int16_t mgmt_port;
static bool mgmt_loopback_only;

static bool public_chats_allow_noobies;

static std::string create_token(const std::string& accountId, const std::string& nonce)
{
	soup::sha256::HmacState st(nonce);
	st.append("accountId=", 10);
	st.append(accountId.data(), accountId.size());
	st.append("&ct=IRC", 7);
	st.finalise();
	return string::bin2hexLower(st.getDigest());
}

struct AuthPendingTag {};

struct AuthenticatedUserData
{
	std::string accountId;
	std::string token;
	std::string guildId;
	std::string allianceId;
	bool guildChatModerator = false;
	bool allianceChatModerator = false;
	bool administrator = false;
	bool noobie = false;
};

struct VerifyCredsTask final : public soup::Task
{
	SharedPtr<Worker> s;
	HttpRequestTask hrt;
	std::string accountId;
	std::string token;

	VerifyCredsTask(Socket& _s, std::string&& accountId, std::string&& token)
		: s(Scheduler::get()->getShared(_s)), hrt(buildRequest(accountId, token)), accountId(std::move(accountId)), token(std::move(token))
	{
		//SOUP_ASSERT(s);
	}

	static HttpRequest buildRequest(const std::string& accountId, const std::string& token)
	{
		std::string path = "/custom/getAccountInfo?accountId=";
		path.append(accountId);
		path.append("&token=");
		path.append(token);
		path.append("&ct=IRC");

		HttpRequest hr(http_host, std::move(path));
		hr.use_tls = http_use_tls;
		return hr;
	}

	void onTick() final
	{
		if (static_cast<Socket*>(s.get())->isWorkDoneOrClosed())
		{
			setWorkDone();
		}
		else if (hrt.tickUntilDone())
		{
			if (hrt.result.has_value())
			{
				if (hrt.result->status_code == 200)
				{
					AuthenticatedUserData aud{ std::move(accountId), std::move(token) };
					if (auto jr = json::decode(hrt.result->body); jr && jr->isObj())
					{
						if (auto GuildId = jr->reinterpretAsObj().find("GuildId"))
						{
							aud.guildId = GuildId->asStr();
							aud.guildChatModerator = (jr->reinterpretAsObj().at("GuildPermissions").asInt() & 512);
							if (auto AllianceId = jr->reinterpretAsObj().find("AllianceId"))
							{
								aud.allianceId = AllianceId->asStr();
								aud.allianceChatModerator = (jr->reinterpretAsObj().at("GuildRank").asInt() <= 1)
														&& (jr->reinterpretAsObj().at("AlliancePermissions").asInt() & 512)
														;
							}
						}
						if (auto IsAdministrator = jr->reinterpretAsObj().find("IsAdministrator"))
						{
							aud.administrator = IsAdministrator->asBool();
						}
						if (auto CompletedVorsPrize = jr->reinterpretAsObj().find("CompletedVorsPrize"))
						{
							aud.noobie = !CompletedVorsPrize->asBool();
						}
					}
					std::cout << "Successful auth, guildId=" << aud.guildId << std::endl;
					static_cast<Socket*>(s.get())->custom_data.addStructToMap(AuthenticatedUserData, std::move(aud));
				}
				else
				{
					static_cast<Socket*>(s.get())->send(":Soup WALLOPS :Failed to validate your credentials.\r\n");
				}
			}
			static_cast<Socket*>(s.get())->custom_data.removeStructFromMap(AuthPendingTag);
			setWorkDone();
		}
	}
};

struct ReportDropTask final : public soup::Task
{
	HttpRequestTask hrt;

	ReportDropTask(const AuthenticatedUserData& aud)
		: hrt(buildRequest(aud.accountId, aud.token))
	{
	}

	static HttpRequest buildRequest(const std::string& accountId, const std::string& token)
	{
		std::string path = "/custom/ircDropped?accountId=";
		path.append(accountId);
		path.append("&token=");
		path.append(token);
		path.append("&ct=IRC");

		HttpRequest hr(http_host, std::move(path));
		hr.use_tls = http_use_tls;
		return hr;
	}

	void onTick() final
	{
		if (hrt.tickUntilDone())
		{
			setWorkDone();
		}
	}
};

struct VerifyChannelJoinTask final : public soup::Task
{
	SharedPtr<Worker> s;
	const std::string& channel_name;
	Promise<std::string>& reject_reason_promise;

	VerifyChannelJoinTask(Socket& _s, const std::string& channel_name, Promise<std::string>& reject_reason_promise)
		: s(Scheduler::get()->getShared(_s)), channel_name(channel_name), reject_reason_promise(reject_reason_promise)
	{
	}

	void onTick() final
	{
		if (static_cast<Socket*>(s.get())->isWorkDoneOrClosed())
		{
			return setWorkDone();
		}
		if (static_cast<Socket*>(s.get())->custom_data.isStructInMap(AuthPendingTag))
		{
			return;
		}
		if (static_cast<Socket*>(s.get())->custom_data.isStructInMap(AuthenticatedUserData)
			&& static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(AuthenticatedUserData).noobie
			)
		{
			if (channel_name.substr(0, 2) == "#R" // Recruiting
				|| channel_name.substr(0, 2) == "#T" // Trade
				|| channel_name.substr(0, 2) == "#G" // Region
				|| channel_name.substr(0, 2) == "#Q" // Q&A
				)
			{
				if (!public_chats_allow_noobies)
				{
					std::cout << "Rejecting " << static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(IrcClientData).nick << " from " << channel_name << " due to being a noobie" << std::endl;
					reject_reason_promise.fulfil("Censored");
					return setWorkDone();
				}
			}
		}
		reject_reason_promise.fulfil({});
		setWorkDone();
	}
};

struct LoggingIrcServer : public soup::IrcServer
{
	void onClientConnected(Socket& s) final
	{
		std::cout << s.toString() << " has connected\n";
		s.send("NOTICE * :Auth AAAAAAA:*** skipping identd (disabled by server administrator)\r\n");
	}

	void onClientDisconnected(Socket& s) final
	{
		std::cout << s.toString() << " has disconnected\n";
		if (s.custom_data.isStructInMap(AuthenticatedUserData))
		{
			this->add<ReportDropTask>(s.custom_data.getStructFromMapConst(AuthenticatedUserData));
		}
	}

	void onClientLineReceived(Socket& s, const std::string& line) final
	{
		std::cout << s.toString() << " | " << line << "\n";
		if (line.substr(0, 4) == "USER")
		{
			// Needed for client to understand that it has indeed connected to the server in U16.5 ~ U27.3
			s.send(":Soup 305 Soup :You are no longer marked as being away\r\n");

			std::string accountId = line.substr(5, 24);
			std::string token;
			if (auto arr = string::explode(line, ' '); arr.size() == 5)
			{
				auto realname = arr[4];
				if (realname.c_str()[0] != ':') // Not a real IRC client?
				{
					if (realname.starts_with("token=")) // Bootstrapper 0.13.0 and above with secure_connections set to true
					{
						token = realname.substr(6);
					}
					else if (realname.starts_with("nonce=")) // Bootstrapper 0.10.4 and above
					{
						//s.send(":Soup WALLOPS :Your client sent your accountId-nonce pair (granting full account access) over an insecure transport.\r\n");
						token = create_token(accountId, realname.substr(6));
						// std::cout << s.toString() << " | " << token << "\n";
					}
					else if (realname.size() != 40) // U8 and below
					{
						//s.send(":Soup WALLOPS :Your client sent your accountId-nonce pair (granting full account access) over an insecure transport.\r\n");
						token = create_token(accountId, std::move(realname));
					}
				}
			}
			if (!token.empty())
			{
				s.custom_data.addStructToMap(AuthPendingTag, AuthPendingTag{});
				this->add<VerifyCredsTask>(s, std::move(accountId), std::move(token));
			}
			else
			{
				s.send(":Soup WALLOPS :Your client did not provide credentials. You will be chatting unauthenticated.\r\n");
			}
		}
	}

	void canClientJoinChannel(Socket& s, const std::string& channel_name, Promise<std::string>& reject_reason_promise) final
	{
		this->add<VerifyChannelJoinTask>(s, channel_name, reject_reason_promise);
	}

	void onClientJoinedChannel(Socket& s, const std::string& channel_name, IrcChannelMembershipData& md) final
	{
		if (s.custom_data.isStructInMap(AuthenticatedUserData))
		{
			if (channel_name.substr(0, 2) == "#C")
			{
				md.op = (s.custom_data.getStructFromMapConst(AuthenticatedUserData).guildId == channel_name.substr(2)
					&& s.custom_data.getStructFromMapConst(AuthenticatedUserData).guildChatModerator
					);
			}
			else if (channel_name.substr(0, 2) == "#A")
			{
				md.op = (s.custom_data.getStructFromMapConst(AuthenticatedUserData).allianceId == channel_name.substr(2)
					&& s.custom_data.getStructFromMapConst(AuthenticatedUserData).allianceChatModerator
					);
			}
			else
			{
				md.op = s.custom_data.getStructFromMapConst(AuthenticatedUserData).administrator;
			}
		}
		else
		{
			md.op = false;
		}
		if (md.op)
		{
			std::cout << "Giving " << s.custom_data.getStructFromMapConst(IrcClientData).nick << " oper in " << channel_name << std::endl;
		}
	}
};

static SSL_CTX* g_ssl_ctx = nullptr;

void handle_tls_connection(SOCKET client_fd)
{
	SSL* ssl = SSL_new(g_ssl_ctx);
	SSL_set_fd(ssl, (int)client_fd);   // OpenSSL 需要 int

	if (SSL_accept(ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
		closesocket(client_fd);
		SSL_free(ssl);
		return;
	}

	// 连接本地明文 IRC 端口 6667
	int backend_fd = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(6667);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	if (connect(backend_fd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		perror("connect to backend 6667");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		closesocket(client_fd);
		return;
	}

	// 双向转发
	char buf[4096];
	while (true)
	{
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(client_fd, &fds);
		FD_SET(backend_fd, &fds);

		if (select(0, &fds, nullptr, nullptr, nullptr) == SOCKET_ERROR)
			break;

		if (FD_ISSET(client_fd, &fds))
		{
			int n = SSL_read(ssl, buf, sizeof(buf));
			if (n <= 0) break;
			send(backend_fd, buf, n, 0);
		}
		if (FD_ISSET(backend_fd, &fds))
		{
			int n = recv(backend_fd, buf, sizeof(buf), 0);
			if (n <= 0) break;
			SSL_write(ssl, buf, n);
		}
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(client_fd);
	closesocket(backend_fd);
}

void start_tls_proxy(uint16_t listen_port)
{
	// OpenSSL 初始化只需一次，放到 main() 里做更合适（见下方说明）
	// 这里直接使用全局的 g_ssl_ctx

	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == INVALID_SOCKET)
	{
		std::cerr << "socket() failed for port " << listen_port
			<< ": " << WSAGetLastError() << std::endl;
		return;
	}

	int opt = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(listen_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		std::cerr << "bind() failed for port " << listen_port
			<< ": " << WSAGetLastError() << std::endl;
		closesocket(listen_fd);
		return;
	}

	if (listen(listen_fd, 10) == SOCKET_ERROR)
	{
		std::cerr << "listen() failed for port " << listen_port
			<< ": " << WSAGetLastError() << std::endl;
		closesocket(listen_fd);
		return;
	}

	std::cout << "TLS proxy listening on " << listen_port
		<< ", forwarding to 6667" << std::endl;

	while (true)
	{
		SOCKET client_fd = accept(listen_fd, nullptr, nullptr);
		if (client_fd != INVALID_SOCKET)
		{
			std::thread(handle_tls_connection, client_fd).detach();
		}
	}
}

bool init_openssl()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	g_ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (!g_ssl_ctx)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}

	SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

	if (SSL_CTX_use_certificate_file(g_ssl_ctx, "cert/cert.pem", SSL_FILETYPE_PEM) <= 0 ||
		SSL_CTX_use_PrivateKey_file(g_ssl_ctx, "cert/key.pem", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	if (SSL_CTX_check_private_key(g_ssl_ctx) != 1)
	{
		std::cerr << "Private key does not match certificate" << std::endl;
		return false;
	}
	return true;
}

// Try to pick an ECDHE ciphersuite first so that even if our private key is not-so-private a passive listener can't decrypt our traffic.

#ifdef DOCKER
	#define CONFIG_PATH "conf/irc_config.json"
#else
	#define CONFIG_PATH "irc_config.json"
#endif

int main()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "WSAStartup failed" << std::endl;
		return 1;
	}
	try
	{
		soup::console.init(false);

		{
			UniquePtr<JsonNode> config = json::decode(string::fromFile(CONFIG_PATH));

			bool modified = false;
			if (!config || !config->isObj())
			{
				modified = true;
				config = soup::make_unique<JsonObject>();
			}
#ifdef DOCKER
			if (!config->reinterpretAsObj().contains("http_host")) { modified = true; config->reinterpretAsObj().add("http_host", "spaceninjaserver"); }
#else
			if (!config->reinterpretAsObj().contains("http_host")) { modified = true; config->reinterpretAsObj().add("http_host", "localhost"); }
#endif
			if (!config->reinterpretAsObj().contains("http_port")) { modified = true; config->reinterpretAsObj().add("http_port", 80); }
			if (!config->reinterpretAsObj().contains("http_use_tls")) { modified = true; config->reinterpretAsObj().add("http_use_tls", false); }
			if (!config->reinterpretAsObj().contains("mgmt_port")) { modified = true; config->reinterpretAsObj().add("mgmt_port", 6688); }
			if (!config->reinterpretAsObj().contains("mgmt_loopback_only")) { modified = true; config->reinterpretAsObj().add("mgmt_loopback_only", true); }
			if (!config->reinterpretAsObj().contains("public_chats_allow_noobies")) { modified = true; config->reinterpretAsObj().add("public_chats_allow_noobies", false); }
			if (modified)
			{
				string::toFile(CONFIG_PATH, config->reinterpretAsObj().encodePretty());
			}

			http_host = config->reinterpretAsObj().at("http_host").asStr().value;
			http_use_tls = config->reinterpretAsObj().at("http_use_tls").asBool().value;
			if (uint16_t http_port = config->reinterpretAsObj().at("http_port").asInt().value; http_port != (http_use_tls ? 443 : 80))
			{
				http_host.push_back(':');
				http_host.append(std::to_string(config->reinterpretAsObj().at("http_port").asInt().value));
			}
			mgmt_port = config->reinterpretAsObj().at("mgmt_port").asInt().value;
			mgmt_loopback_only = config->reinterpretAsObj().at("mgmt_loopback_only").asBool().value;
			public_chats_allow_noobies = config->reinterpretAsObj().at("public_chats_allow_noobies").asBool().value;
		}

		LoggingIrcServer serv;
		if (!std::filesystem::is_directory("cert"))
		{
			std::cerr << "Could not find a cert folder in the working directory\n";
			return 1;
		}

		// Soup 只监听明文端口 6667
		if (!serv.bind(6667, &serv.srv))
		{
			std::cerr << "Failed to bind to port 6667\n";
			WSACleanup();
			return 1;
		}
		std::cout << "Listening for plaintext IRC on 6667" << std::endl;

		// 初始化 OpenSSL
		if (!init_openssl())
		{
			std::cerr << "OpenSSL initialization failed" << std::endl;
			WSACleanup();
			return 1;
		}

		// 为 6695-6699 每个端口启动一个 TLS 代理线程
		for (uint16_t port = 6695; port <= 6699; ++port)
		{
			std::thread(start_tls_proxy, port).detach();
		}

		ServerWebService web_srv([](soup::Socket& s, soup::HttpRequest&& req, soup::ServerWebService&)
		{
			if (mgmt_loopback_only && !s.peer.ip.isLoopback())
			{
				ServerWebService::sendText(s, "This service is available via loopback only.");
				return;
			}

			if (req.path == "/")
			{
				ServerWebService::sendHtml(s, R"EOC(<p>Send redtext</p>
<input type="text" />
<input type="submit" onclick="sendRedtext();" />
<script>
	function sendRedtext() {
		fetch("/redtext?" + encodeURIComponent(document.querySelector("input[type=text]").value));
	}
</script>)EOC");
			}
			else if (req.path.substr(0, 9) == "/redtext?")
			{
				std::string msg = ":Soup WALLOPS :";
				msg.append(urlenc::decode(req.path.substr(9)));
				msg.append("\r\n");
				static_cast<IrcServer*>(Scheduler::get())->broadcast(msg);
			}
			else
			{
				ServerWebService::send404(s);
			}
		});
		if (serv.bind(mgmt_port, &web_srv))
		{
			std::cout << "Management interface available at http://localhost:" << mgmt_port;
			if (mgmt_loopback_only)
			{
				std::cout << " (loopback only)";
			}
			std::cout << std::endl;
		}

		netConfig::get().dns_resolver = soup::make_shared<dnsOsResolver>();

#ifdef DOCKER
		// Ctrl+C not killing your software? According to the professional ChatGPTs hired by Docker Inc, it's not an issue. Why? Because there's a workaround!
		signal(SIGTERM, [](int) { exit(0); });
#endif

		serv.run();
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		WSACleanup();
		return 1;
	}

	WSACleanup();
	return 0;
}
