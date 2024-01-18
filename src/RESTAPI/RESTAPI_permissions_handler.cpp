//
// Created by stephane bourque on 2022-11-04.
//

#include "AuthService.h"
#include "RESTAPI_permissions_handler.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"

namespace OpenWifi {

  /**
   * Get all permissions of a role
   * Returns a map like { model: { permission: true }}
  */
  void RESTAPI_permissions_handler::DoGet() {
    std::string role = GetBinding("role", "");
    SecurityObjects::USER_ROLE roleEnum = SecurityObjects::UserTypeFromString(role);
    if (roleEnum == SecurityObjects::UNKNOWN) {
      return BadRequest(RESTAPI::Errors::MissingOrInvalidParameters);
    }

    SecurityObjects::PermissionMap permissions;
    if (StorageService()->PermissionDB().GetPermissions(role, permissions)) {
      Poco::JSON::Object Answer = SecurityObjects::permissions_to_json(permissions);
      return ReturnObject(Answer);
    } 

    return NotFound();
  }

  /**
   * Given a role and a map of permissions in the body (e.g. { model: { permission: true }})
   * Replace existing permissions of that role with new ones
  */
  void RESTAPI_permissions_handler::DoPut() {
    if (!UserInfo_.userinfo.userPermissions[SecurityObjects::PM_PERMISSIONS][SecurityObjects::PT_UPDATE]) {
      return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
    }

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
      AuthService()->PermissionsUpdated(role);
      return OK();
    }

    return InternalError(RESTAPI::Errors::CouldNotUpdatePermissions);
  }
} // namespace OpenWifi
