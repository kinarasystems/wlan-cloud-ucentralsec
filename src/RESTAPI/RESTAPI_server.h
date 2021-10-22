//
//	License type: BSD 3-Clause License
//	License copy: https://github.com/Telecominfraproject/wlan-cloud-ucentralgw/blob/master/LICENSE
//
//	Created by Stephane Bourque on 2021-03-04.
//	Arilia Wireless Inc.
//

#ifndef UCENTRAL_UCENTRALRESTAPISERVER_H
#define UCENTRAL_UCENTRALRESTAPISERVER_H

#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/NetException.h"

#include "framework/MicroService.h"

namespace OpenWifi {

    class RESTAPI_Server : public SubSystemServer {

    public:
        static RESTAPI_Server *instance() {
            if (instance_ == nullptr) {
                instance_ = new RESTAPI_Server;
            }
            return instance_;
        }

        int Start() override;
        void Stop() override;
        void reinitialize(Poco::Util::Application &self) override;

        inline const std::string & AssetDir() { return AsserDir_; }
        inline const std::string & GetPasswordPolicy() const { return PasswordPolicy_; }
        inline const std::string & GetAccessPolicy() const { return AccessPolicy_; }
    private:
		static RESTAPI_Server *instance_;
        std::vector<std::unique_ptr<Poco::Net::HTTPServer>>   RESTServers_;
		Poco::ThreadPool	Pool_;
		std::string         AsserDir_;
		std::string         PasswordPolicy_;
		std::string         AccessPolicy_;
		RESTAPI_GenericServer   Server_;

        RESTAPI_Server() noexcept:
            SubSystemServer("RESTAPIServer", "REST-SRV", "openwifi.restapi")
        {
        }
    };

    inline RESTAPI_Server * RESTAPI_Server() { return RESTAPI_Server::instance(); };

    class RequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
        public:
        RequestHandlerFactory(RESTAPI_GenericServer &Server) :
                Logger_(RESTAPI_Server()->Logger()),
                Server_(Server){}

            Poco::Net::HTTPRequestHandler *createRequestHandler(const Poco::Net::HTTPServerRequest &request) override;
        private:
            Poco::Logger    & Logger_;
            RESTAPI_GenericServer   &Server_;
    };


} //   namespace

#endif //UCENTRAL_UCENTRALRESTAPISERVER_H
