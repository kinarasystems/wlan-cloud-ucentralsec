#pragma once

#include "StorageService.h"
#include "framework/RESTAPI_Handler.h"
namespace OpenWifi {
	class RESTAPI_permissions_handler : public RESTAPIHandler {
	  public:
		RESTAPI_permissions_handler(const RESTAPIHandler::BindingMap &bindings, Poco::Logger &L,
							   RESTAPI_GenericServerAccounting &Server, uint64_t TransactionId,
							   bool Internal)
			: RESTAPIHandler(bindings, L,
							 std::vector<std::string>{Poco::Net::HTTPRequest::HTTP_GET,
                                        Poco::Net::HTTPRequest::HTTP_PUT,
                                        Poco::Net::HTTPRequest::HTTP_OPTIONS},
							 Server, TransactionId, Internal) {}
		static auto PathName() { return std::list<std::string>{"/api/v1/permissions/{role}"}; };

	  private:
		PermissionDB &DB_ = StorageService()->PermissionDB();

		void DoGet() final;
		void DoPost() final{};
		void DoDelete() final{};
		void DoPut() final;
	};
} // namespace OpenWifi
