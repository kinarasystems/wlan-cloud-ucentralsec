#pragma once

#include "framework/orm.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"

namespace OpenWifi {

	typedef Poco::Tuple<std::string,  //  id
						std::string,  //  role
						std::string,  //  model
						std::string  //  permission
						>
		PermissionRecordTuple;
	typedef std::vector<PermissionRecordTuple> PermissionRecordTupleTupleList;

	class PermissionDB : public ORM::DB<PermissionRecordTuple, SecurityObjects::PermissionEntry> {
	  public:
		PermissionDB(const std::string &name, const std::string &shortname, OpenWifi::DBType T,
				 Poco::Data::SessionPool &P, Poco::Logger &L);
		virtual ~PermissionDB() {}
		inline uint32_t Version() override { return 1; }

		bool Upgrade(uint32_t from, uint32_t &to) override;
    bool GetPermissions(const std::string &role, SecurityObjects::PermissionMap &permisions);
    bool AddPermission(const std::string &role, const std::string &model, const std::string &permission);
	};

} // namespace OpenWifi
