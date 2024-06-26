//
// Created by stephane bourque on 2021-06-21.
//

#include "RESTAPI_user_handler.h"
#include "ACLProcessor.h"
#include "AuthService.h"
#include "MFAServer.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "SMSSender.h"
#include "SMTPMailerService.h"
#include "StorageService.h"
#include "TotpCache.h"
#include "framework/MicroServiceFuncs.h"
#include "framework/ow_constants.h"

namespace OpenWifi {

	void RESTAPI_user_handler::DoGet() {
		std::string Id = GetBinding("id", "");
		if (Id.empty()) {
			return BadRequest(RESTAPI::Errors::MissingUserID);
		}

		Poco::toLowerInPlace(Id);
		std::string Arg;
		SecurityObjects::UserInfo UInfo;
		if (HasParameter("byEmail", Arg) && Arg == "true") {
			if (!StorageService()->UserDB().GetUserByEmail(Id, UInfo)) {
				return NotFound();
			}
		} else if (!StorageService()->UserDB().GetUserById(Id, UInfo, true)) {
			return NotFound();
		}

		if (!Internal_ && !ACLProcessor::Can(UserInfo_.userinfo, UInfo, ACLProcessor::READ)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		Poco::JSON::Object UserInfoObject;
		Sanitize(UserInfo_, UInfo);
		UInfo.to_json(UserInfoObject);
		ReturnObject(UserInfoObject);
	}

	void RESTAPI_user_handler::DoDelete() {
		std::string Id = GetBinding("id", "");
		if (Id.empty()) {
			return BadRequest(RESTAPI::Errors::MissingUserID);
		}

		SecurityObjects::UserInfo UInfo;
		if (!StorageService()->UserDB().GetUserById(Id, UInfo)) {
			return NotFound();
		}

		if (!ACLProcessor::Can(UserInfo_.userinfo, UInfo, ACLProcessor::DELETE)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		if (!StorageService()->UserDB().DeleteUser(UserInfo_.userinfo.email, Id)) {
			return NotFound();
		}

		AuthService()->DeleteUserFromCache(Id);
		StorageService()->AvatarDB().DeleteAvatar(UserInfo_.userinfo.email, Id);
		StorageService()->PreferencesDB().DeletePreferences(UserInfo_.userinfo.email, Id);
		StorageService()->UserTokenDB().RevokeAllTokens(Id);
		StorageService()->ApiKeyDB().RemoveAllApiKeys(Id);
		Logger_.information(
			fmt::format("User '{}' deleted by '{}'.", Id, UserInfo_.userinfo.email));
		OK();
	}

	void RESTAPI_user_handler::DoPost() {

		std::string Id = GetBinding("id", "");
		if (Id != "0") {
			return BadRequest(RESTAPI::Errors::IdMustBe0);
		}

		SecurityObjects::UserInfo NewUser;
		const auto &RawObject = ParsedBody_;
		if (!NewUser.from_json(RawObject)) {
			return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
		}

		if (NewUser.userRole == SecurityObjects::UNKNOWN) {
			return BadRequest(RESTAPI::Errors::InvalidUserRole);
		}

		if (UserInfo_.userinfo.userRole == SecurityObjects::ROOT) {
			NewUser.owner = GetParameter("entity", "");
		} else {
			NewUser.owner = UserInfo_.userinfo.owner;
		}

		if (!ACLProcessor::Can(UserInfo_.userinfo, NewUser, ACLProcessor::CREATE)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		Poco::toLowerInPlace(NewUser.email);
		if (!Utils::ValidEMailAddress(NewUser.email)) {
			return BadRequest(RESTAPI::Errors::InvalidEmailAddress);
		}

		SecurityObjects::UserInfo Existing;
		if (StorageService()->SubDB().GetUserByEmail(NewUser.email, Existing)) {
			return BadRequest(RESTAPI::Errors::UserAlreadyExists);
		}

		if (!NewUser.currentPassword.empty()) {
			if (!AuthService()->ValidatePassword(NewUser.currentPassword)) {
				return BadRequest(RESTAPI::Errors::InvalidPassword);
			}
		}

		if (NewUser.name.empty())
			NewUser.name = NewUser.email;

		//  You cannot enable MFA during user creation
		NewUser.userTypeProprietaryInfo.mfa.enabled = false;
		NewUser.userTypeProprietaryInfo.mfa.method = "";
		NewUser.userTypeProprietaryInfo.mobiles.clear();
		NewUser.userTypeProprietaryInfo.authenticatorSecret.clear();
		NewUser.validated = true;

		if (!StorageService()->UserDB().CreateUser(NewUser.email, NewUser)) {
			Logger_.information(fmt::format("Could not add user '{}'.", NewUser.email));
			return BadRequest(RESTAPI::Errors::RecordNotCreated);
		}

		if (GetBoolParameter("email_verification")) {
			if (AuthService::VerifyEmail(NewUser))
				Logger_.information(
					fmt::format("Verification e-mail requested for {}", NewUser.email));
			StorageService()->UserDB().UpdateUserInfo(UserInfo_.userinfo.email, NewUser.id,
													  NewUser);
		}

		if (!StorageService()->UserDB().GetUserByEmail(NewUser.email, NewUser)) {
			Logger_.information(fmt::format("User '{}' but not retrieved.", NewUser.email));
			return NotFound();
		}

		Poco::JSON::Object UserInfoObject;
		Sanitize(UserInfo_, NewUser);
		NewUser.to_json(UserInfoObject);
		ReturnObject(UserInfoObject);
		Logger_.information(fmt::format("User '{}' has been added by '{}')", NewUser.email,
										UserInfo_.userinfo.email));
	}

	void RESTAPI_user_handler::DoPut() {

		std::string Id = GetBinding("id", "");
		if (Id.empty()) {
			return BadRequest(RESTAPI::Errors::MissingUserID);
		}

		SecurityObjects::UserInfo Existing;
		if (!StorageService()->UserDB().GetUserById(Id, Existing)) {
			return NotFound();
		}

		// Non-admin/root user is attempting to modify a user that is not themselves
		if ((UserInfo_.userinfo.userRole != SecurityObjects::USER_ROLE::ADMIN && UserInfo_.userinfo.userRole != SecurityObjects::USER_ROLE::ROOT) && (UserInfo_.userinfo.id != Id)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		if (!ACLProcessor::Can(UserInfo_.userinfo, Existing, ACLProcessor::MODIFY)) {
			return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
		}

		if (GetBoolParameter("resetMFA")) {
			if ((UserInfo_.userinfo.userRole == SecurityObjects::ROOT) ||
				(UserInfo_.userinfo.userRole == SecurityObjects::ADMIN &&
				 Existing.userRole != SecurityObjects::ROOT) ||
				(UserInfo_.userinfo.id == Id)) {
				Existing.userTypeProprietaryInfo.mfa.enabled = false;
				Existing.userTypeProprietaryInfo.mfa.method.clear();
				Existing.userTypeProprietaryInfo.mobiles.clear();
				Existing.modified = OpenWifi::Now();
				Existing.notes.push_back(
					SecurityObjects::NoteInfo{.created = OpenWifi::Now(),
											  .createdBy = UserInfo_.userinfo.email,
											  .note = "MFA Reset by " + UserInfo_.userinfo.email});
				StorageService()->UserDB().UpdateUserInfo(UserInfo_.userinfo.email, Id, Existing);
				SecurityObjects::UserInfo NewUserInfo;
				StorageService()->UserDB().GetUserByEmail(UserInfo_.userinfo.email, NewUserInfo);
				Poco::JSON::Object ModifiedObject;
				Sanitize(UserInfo_, NewUserInfo);
				NewUserInfo.to_json(ModifiedObject);
				return ReturnObject(ModifiedObject);
			} else {
				return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
			}
		}

		if (GetBoolParameter("forgotPassword")) {
			Existing.changePassword = true;
			Logger_.information(fmt::format("FORGOTTEN-PASSWORD({}): Request for {}",
											Request->clientAddress().toString(), Existing.email));
			SecurityObjects::ActionLink NewLink;

			NewLink.action = OpenWifi::SecurityObjects::LinkActions::FORGOT_PASSWORD;
			NewLink.id = MicroServiceCreateUUID();
			NewLink.userId = Existing.id;
			NewLink.created = OpenWifi::Now();
			NewLink.expires = NewLink.created + (24 * 60 * 60);
			NewLink.userAction = true;
			StorageService()->ActionLinksDB().CreateAction(NewLink);
			return OK();
		}

		SecurityObjects::UserInfo NewUser;
		const auto &RawObject = ParsedBody_;
		if (!NewUser.from_json(RawObject)) {
			return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
		}

		// some basic validations
		if (RawObject->has("userRole") &&
			SecurityObjects::UserTypeFromString(RawObject->get("userRole").toString()) ==
				SecurityObjects::UNKNOWN) {
			return BadRequest(RESTAPI::Errors::InvalidUserRole);
		}

		if (RawObject->has("owner")) {
			if (UserInfo_.userinfo.userRole == SecurityObjects::ROOT && Existing.owner.empty()) {
				AssignIfPresent(RawObject, "owner", Existing.owner);
			}
		}

		// The only valid things to change are: changePassword, name,
		AssignIfPresent(RawObject, "name", Existing.name);
		AssignIfPresent(RawObject, "description", Existing.description);
		AssignIfPresent(RawObject, "location", Existing.location);
		AssignIfPresent(RawObject, "locale", Existing.locale);
		AssignIfPresent(RawObject, "changePassword", Existing.changePassword);
		AssignIfPresent(RawObject, "suspended", Existing.suspended);
		AssignIfPresent(RawObject, "blackListed", Existing.blackListed);

		if (RawObject->has("userRole")) {
			auto NewRole =
				SecurityObjects::UserTypeFromString(RawObject->get("userRole").toString());
			if (NewRole != Existing.userRole) {
				if (UserInfo_.userinfo.userRole != SecurityObjects::ROOT &&
					NewRole == SecurityObjects::ROOT) {
					return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
				}
				if (Id == UserInfo_.userinfo.id) {
					return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
				}
				Existing.userRole = NewRole;
			}
		}

		if (RawObject->has("notes")) {
			SecurityObjects::NoteInfoVec NIV;
			NIV = RESTAPI_utils::to_object_array<SecurityObjects::NoteInfo>(
				RawObject->get("notes").toString());
			for (auto const &i : NIV) {
				SecurityObjects::NoteInfo ii{.created = (uint64_t)OpenWifi::Now(),
											 .createdBy = UserInfo_.userinfo.email,
											 .note = i.note};
				Existing.notes.push_back(ii);
			}
		}
		if (RawObject->has("currentPassword")) {
			if (!AuthService()->ValidatePassword(RawObject->get("currentPassword").toString())) {
				return BadRequest(RESTAPI::Errors::InvalidPassword);
			}
			if (!AuthService()->SetPassword(RawObject->get("currentPassword").toString(),
											Existing)) {
				return BadRequest(RESTAPI::Errors::PasswordRejected);
			}
		}

		if (GetBoolParameter("email_verification")) {
			if (AuthService::VerifyEmail(Existing))
				Logger_.information(
					fmt::format("Verification e-mail requested for {}", Existing.email));
		}

		if (RawObject->has("userTypeProprietaryInfo")) {
			if (NewUser.userTypeProprietaryInfo.mfa.enabled) {
				if (!MFAMETHODS::Validate(NewUser.userTypeProprietaryInfo.mfa.method)) {
					return BadRequest(RESTAPI::Errors::BadMFAMethod);
				}

				if (NewUser.userTypeProprietaryInfo.mfa.enabled &&
					NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::SMS &&
					!SMSSender()->Enabled()) {
					return BadRequest(RESTAPI::Errors::SMSMFANotEnabled);
				}

				if (NewUser.userTypeProprietaryInfo.mfa.enabled &&
					NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::EMAIL &&
					!SMTPMailerService()->Enabled()) {
					return BadRequest(RESTAPI::Errors::EMailMFANotEnabled);
				}

				Existing.userTypeProprietaryInfo.mfa.method =
					NewUser.userTypeProprietaryInfo.mfa.method;
				Existing.userTypeProprietaryInfo.mfa.enabled = true;

				if (NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::SMS) {
					if (NewUser.userTypeProprietaryInfo.mobiles.empty()) {
						return BadRequest(RESTAPI::Errors::NeedMobileNumber);
					}
					if (!SMSSender()->IsNumberValid(
							NewUser.userTypeProprietaryInfo.mobiles[0].number,
							UserInfo_.userinfo.email)) {
						return BadRequest(RESTAPI::Errors::NeedMobileNumber);
					}
					Existing.userTypeProprietaryInfo.mobiles =
						NewUser.userTypeProprietaryInfo.mobiles;
					Existing.userTypeProprietaryInfo.mobiles[0].verified = true;
					Existing.userTypeProprietaryInfo.authenticatorSecret.clear();
				} else if (NewUser.userTypeProprietaryInfo.mfa.method ==
						   MFAMETHODS::AUTHENTICATOR) {
					std::string Secret;
					Existing.userTypeProprietaryInfo.mobiles.clear();
					if (Existing.userTypeProprietaryInfo.authenticatorSecret.empty() &&
						TotpCache()->CompleteValidation(UserInfo_.userinfo, false, Secret)) {
						Existing.userTypeProprietaryInfo.authenticatorSecret = Secret;
					} else if (!Existing.userTypeProprietaryInfo.authenticatorSecret.empty()) {
						// we allow someone to use their old secret
					} else {
						return BadRequest(RESTAPI::Errors::AuthenticatorVerificationIncomplete);
					}
				} else if (NewUser.userTypeProprietaryInfo.mfa.method == MFAMETHODS::EMAIL) {
					Existing.userTypeProprietaryInfo.mobiles.clear();
					Existing.userTypeProprietaryInfo.authenticatorSecret.clear();
				}
			} else {
				Existing.userTypeProprietaryInfo.authenticatorSecret.clear();
				Existing.userTypeProprietaryInfo.mobiles.clear();
				Existing.userTypeProprietaryInfo.mfa.enabled = false;
			}
		}

		Existing.modified = OpenWifi::Now();
		if (StorageService()->UserDB().UpdateUserInfo(UserInfo_.userinfo.email, Id, Existing)) {
			SecurityObjects::UserInfo NewUserInfo;
			StorageService()->UserDB().GetUserByEmail(UserInfo_.userinfo.email, NewUserInfo);
			Poco::JSON::Object ModifiedObject;
			Sanitize(UserInfo_, NewUserInfo);
			NewUserInfo.to_json(ModifiedObject);
			return ReturnObject(ModifiedObject);
		}
		BadRequest(RESTAPI::Errors::RecordNotUpdated);
	}
} // namespace OpenWifi