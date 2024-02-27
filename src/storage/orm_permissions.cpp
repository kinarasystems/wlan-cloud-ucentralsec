//
// Created by stephane bourque on 2022-11-04.
//

#include "orm_permissions.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"
#include "StorageService.h"
#include "fmt/format.h"
#include "framework/orm.h"
#include "framework/MicroServiceFuncs.h"

namespace OpenWifi {
	static ORM::FieldVec PermissionDB_Fields{ORM::Field{"id", 36, true},
										 ORM::Field{"role", ORM::FieldType::FT_TEXT},
										 ORM::Field{"model", ORM::FieldType::FT_TEXT},
										 ORM::Field{"permission", ORM::FieldType::FT_TEXT}};

	static ORM::IndexVec MakeIndices(const std::string &shortname) {
		return ORM::IndexVec{{std::string(shortname + "model_index"),
							  ORM::IndexEntryVec{{std::string("model"), ORM::Indextype::ASC}}}};
	};

	PermissionDB::PermissionDB(const std::string &TableName, const std::string &Shortname,
					   OpenWifi::DBType T, Poco::Data::SessionPool &P, Poco::Logger &L)
		: DB(T, TableName.c_str(), PermissionDB_Fields, MakeIndices(Shortname), P, L,
			 Shortname.c_str()) {}

	bool PermissionDB::Upgrade([[maybe_unused]] uint32_t from, uint32_t &to) {
		to = Version();
		std::vector<std::string> Script{};

		for (const auto &i : Script) {
			try {
				auto Session = Pool_.get();
				Session << i, Poco::Data::Keywords::now;
			} catch (...) {
			}
		}
		return true;
	}

  /**
   * Given a role and a PermissionMap, get permissions of that role from the DB
   * and write it into the map
   * Return whether this was successful
  */
  bool PermissionDB::GetPermissions(const std::string &role, SecurityObjects::PermissionMap &permissions) {
    SecurityObjects::USER_ROLE roleEnum = SecurityObjects::UserTypeFromString(role);
    // Root has all permissions
    if (roleEnum == SecurityObjects::ROOT) {
      permissions = SecurityObjects::GetAllPermissions(true);
      return true;
    }
    
    std::string whereClause;
		whereClause = fmt::format("role='{}' ", Poco::toLower(role));
    try {
        permissions = SecurityObjects::GetAllPermissions(false);

        uint64_t offset = 0;
        uint64_t limit = 500;
        while (true) {
          std::vector<SecurityObjects::PermissionEntry> records;
          GetRecords(offset, limit, records, whereClause);
          if (records.empty()) {
            break;
          }
          for (auto &record : records) {
            SecurityObjects::PERMISSION_MODEL model = SecurityObjects::PermModelFromString(record.model);
            SecurityObjects::PERMISSION_TYPE permission = SecurityObjects::PermTypeFromString(record.permission);
            permissions[model][permission] = true;
          }
          offset += limit;
        }
        return true;
    } catch (const Poco::Exception &E) {
			Logger().log(E);
		}
		return false;
  }

  /**
   * Given a role and a PermissionMap, replace the permissions of that role with the
   * new permissions
   * Return whether this was successful
  */
  bool PermissionDB::UpdatePermissions(const std::string &role, SecurityObjects::PermissionMap &permissions) {
    std::string whereClause;
		whereClause = fmt::format("role='{}' ", Poco::toLower(role));
    try {
        uint64_t offset = 0;
        uint64_t limit = 500;
        std::vector<Types::UUID_t> toDelete;
    
        // Create a copy of the input permissions to keep track of which ones
        // need to be added to the db
        SecurityObjects::PermissionMap toCreate;
        for (auto &[model, modelPerms] : permissions) {
          for (auto &[permission, allowed] : modelPerms) {
            toCreate[model][permission] = permissions[model][permission];
          }
        }

        while (true) {
          std::vector<SecurityObjects::PermissionEntry> records;
          GetRecords(offset, limit, records, whereClause);
          if (records.empty()) {
            break;
          }

          // Compare input permissions to DB permissions to decide what to add/remove
          for (auto &record : records) {
            SecurityObjects::PERMISSION_MODEL model = SecurityObjects::PermModelFromString(record.model);
            SecurityObjects::PERMISSION_TYPE permission = SecurityObjects::PermTypeFromString(record.permission);
            if (!permissions[model][permission]) {
              // DB permission is not found in input or is false, it should be deleted
              toDelete.push_back(record.id);
            } else {
              // Permission was found in the input and the DB, no need to create it
              toCreate[model][permission] = false;
            }
          }
          offset += limit;
        }

        if (!toDelete.empty()) {
          std::string deleteIdsString;
          for (Types::UUID_t &id : toDelete) {
            deleteIdsString += fmt::format("'{}',", id);
          }
          deleteIdsString.pop_back();
          std::string deleteWhere = fmt::format("id IN ({}) ", deleteIdsString);
          DeleteRecords(deleteWhere);
        }

        for (auto &[model, modelPerms] : permissions) {
          for (auto &[permission, allowed] : modelPerms) {
            if(toCreate[model][permission]) {
              AddPermission(role, model, permission);
            }
          }
        }

        return true;
    } catch (const Poco::Exception &E) {
			Logger().log(E);
		}
		return false;
  }

  /**
   * Given a role, model, and permission, add the permission to the DB
   * Return whether this was successful
  */
  bool PermissionDB::AddPermission(const std::string &role, const SecurityObjects::PERMISSION_MODEL &model, const SecurityObjects::PERMISSION_TYPE &permission) {
    try {
      SecurityObjects::PermissionEntry record;
      record.id = MicroServiceCreateUUID();
      record.role = role;
      record.model = SecurityObjects::PermModelToString(model);
      record.permission = SecurityObjects::PermTypeToString(permission);
      return CreateRecord(record);
		} catch (const Poco::Exception &E) {
			std::cout << "What: " << E.what() << " name: " << E.name() << std::endl;
			Logger().log(E);
		}
		return false;
  }
} // namespace OpenWifi

template <>
void ORM::DB<OpenWifi::PermissionRecordTuple, OpenWifi::SecurityObjects::PermissionEntry>::Convert(
	const OpenWifi::PermissionRecordTuple &In, OpenWifi::SecurityObjects::PermissionEntry &Out) {
	Out.id = In.get<0>();
	Out.role = In.get<1>();
	Out.model = In.get<2>();
	Out.permission = In.get<3>();
}

template <>
void ORM::DB<OpenWifi::PermissionRecordTuple, OpenWifi::SecurityObjects::PermissionEntry>::Convert(
	const OpenWifi::SecurityObjects::PermissionEntry &In, OpenWifi::PermissionRecordTuple &Out) {
	Out.set<0>(In.id);
	Out.set<1>(In.role);
	Out.set<2>(In.model);
	Out.set<3>(In.permission);
}
