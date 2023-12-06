//
// Created by stephane bourque on 2022-11-04.
//


#include "RESTAPI_permissions_handler.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"

namespace OpenWifi {

	void RESTAPI_permissions_handler::DoGet() {
    std::string role = GetBinding("role", "");
		if (SecurityObjects::UserTypeFromString(role) == SecurityObjects::UNKNOWN) {
			return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
		}

    // TODO restrict this to certain roles?

    SecurityObjects::PermissionMap permissions;
    if (StorageService()->PermissionDB().GetPermissions(role, permissions)) {
      Poco::JSON::Object Answer = SecurityObjects::permissions_to_json(permissions);
      return ReturnObject(Answer);
    } 

    return NotFound();
	}

  void RESTAPI_permissions_handler::DoPut() {
    std::string role = GetBinding("role", "");
		if (SecurityObjects::UserTypeFromString(role) == SecurityObjects::UNKNOWN) {
			return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
		}

    const auto &Obj = ParsedBody_;
		if (Obj == nullptr) {
			return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
		}

    SecurityObjects::PermissionMap permissions;
    try {
      permissions = SecurityObjects::permissions_from_json(Obj);
    } catch (...) {
      return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
    }

    if (StorageService()->PermissionDB().UpdatePermissions(role, permissions)) {
      return OK();
    }

    return InternalError(RESTAPI::Errors::CouldNotUpdatePermissions);
  }

  void RESTAPI_permissions_handler::DoPost() {
    std::string role = GetBinding("role", "");
		if (SecurityObjects::UserTypeFromString(role) == SecurityObjects::UNKNOWN) {
			return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
		}

    const auto &Obj = ParsedBody_;
		if (Obj == nullptr) {
			return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
		}
    auto model = GetS("model", Obj);
		auto permission = GetS("permission", Obj);

    StorageService()->PermissionDB().AddPermission(role, model, permission);
  }
} // namespace OpenWifi