//
//	License type: BSD 3-Clause License
//	License copy: https://github.com/Telecominfraproject/wlan-cloud-ucentralgw/blob/master/LICENSE
//
//	Created by Stephane Bourque on 2021-03-04.
//	Arilia Wireless Inc.
//

#include "Poco/JSON/Parser.h"

#include "AuthService.h"
#include "RESTAPI_oauth2_handler.h"
#include "MFAServer.h"
#include "framework/ow_constants.h"
#include "framework/MicroService.h"
#include "StorageService.h"
#include "RESTAPI_db_helpers.h"

namespace OpenWifi {

	void RESTAPI_oauth2_handler::DoGet() {
	    bool Expired = false, Contacted = false;
        if (!IsAuthorized(Expired, Contacted)) {
            if(Expired)
                return UnAuthorized(RESTAPI::Errors::ExpiredToken,EXPIRED_TOKEN);
            return UnAuthorized(RESTAPI::Errors::MissingAuthenticationInformation, INVALID_TOKEN);
        }
        bool GetMe = GetBoolParameter(RESTAPI::Protocol::ME, false);
        if(GetMe) {
            Logger_.information(fmt::format("REQUEST-ME({}): Request for {}", Request->clientAddress().toString(), UserInfo_.userinfo.email));
            Poco::JSON::Object Me;
            SecurityObjects::UserInfo   ReturnedUser = UserInfo_.userinfo;
            Sanitize(UserInfo_, ReturnedUser);
            ReturnedUser.to_json(Me);
            return ReturnObject(Me);
        }
        BadRequest(RESTAPI::Errors::UnrecognizedRequest);
	}

    void RESTAPI_oauth2_handler::DoDelete() {
	    bool Expired = false, Contacted=false;
	    if (!IsAuthorized(Expired, Contacted)) {
	        if(Expired)
	            return UnAuthorized(RESTAPI::Errors::ExpiredToken,EXPIRED_TOKEN);
	        return UnAuthorized(RESTAPI::Errors::MissingAuthenticationInformation, INVALID_TOKEN);
	    }

        auto Token = GetBinding(RESTAPI::Protocol::TOKEN, "...");
        if (Token == SessionToken_) {
            AuthService()->Logout(Token);
            return ReturnStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT, true);
        }

        Logger_.information(fmt::format("BAD-LOGOUT({}): Request for {}", Request->clientAddress().toString(), UserInfo_.userinfo.email));
        NotFound();
	}

	void RESTAPI_oauth2_handler::DoPost() {
        const auto & Obj = ParsedBody_;
        auto userId = GetS(RESTAPI::Protocol::USERID, Obj);
        auto password = GetS(RESTAPI::Protocol::PASSWORD, Obj);
        auto newPassword = GetS(RESTAPI::Protocol::NEWPASSWORD, Obj);
        auto refreshToken = GetS("refresh_token", Obj);
        auto grant_type = GetParameter("grant_type");

        Poco::toLowerInPlace(userId);

        if(!refreshToken.empty() && grant_type == "refresh_token") {
            SecurityObjects::UserInfoAndPolicy UInfo;
            if(AuthService()->RefreshUserToken(*Request, refreshToken, UInfo)) {
                Poco::JSON::Object  Answer;
                UInfo.webtoken.to_json(Answer);
                return ReturnObject(Answer);
            } else {
                return UnAuthorized(RESTAPI::Errors::InvalidCredentials, CANNOT_REFRESH_TOKEN);
            }
        }

        if(GetBoolParameter(RESTAPI::Protocol::REQUIREMENTS)) {
            Logger_.information(fmt::format("POLICY-REQUEST({}): Request.", Request->clientAddress().toString()));
            Poco::JSON::Object  Answer;
            Answer.set(RESTAPI::Protocol::PASSWORDPATTERN, AuthService()->PasswordValidationExpression());
            Answer.set(RESTAPI::Protocol::ACCESSPOLICY, AuthService()->GetAccessPolicy());
            Answer.set(RESTAPI::Protocol::PASSWORDPOLICY, AuthService()->GetPasswordPolicy());
            return ReturnObject(Answer);
        }

        if(GetBoolParameter(RESTAPI::Protocol::FORGOTPASSWORD)) {
            SecurityObjects::UserInfo UInfo1;
            auto UserExists = StorageService()->UserDB().GetUserByEmail(userId,UInfo1);
            if(UserExists) {
                Logger_.information(fmt::format("FORGOTTEN-PASSWORD({}): Request for {}", Request->clientAddress().toString(), userId));
                SecurityObjects::ActionLink NewLink;

                NewLink.action = OpenWifi::SecurityObjects::LinkActions::FORGOT_PASSWORD;
                NewLink.id = MicroService::CreateUUID();
                NewLink.userId = UInfo1.id;
                NewLink.created = OpenWifi::Now();
                NewLink.expires = NewLink.created + (24*60*60);
                NewLink.userAction = true;
                StorageService()->ActionLinksDB().CreateAction(NewLink);

                Poco::JSON::Object ReturnObj;
                SecurityObjects::UserInfoAndPolicy UInfo;
                UInfo.webtoken.userMustChangePassword = true;
                UInfo.webtoken.to_json(ReturnObj);
                return ReturnObject(ReturnObj);
            } else {
                Poco::JSON::Object ReturnObj;
                SecurityObjects::UserInfoAndPolicy UInfo;
                UInfo.webtoken.userMustChangePassword = true;
                UInfo.webtoken.to_json(ReturnObj);
                return ReturnObject(ReturnObj);
            }
        }

        if(GetBoolParameter(RESTAPI::Protocol::RESENDMFACODE)) {
            Logger_.information(fmt::format("RESEND-MFA-CODE({}): Request for {}", Request->clientAddress().toString(), userId));
            if(Obj->has("uuid")) {
                auto uuid = Obj->get("uuid").toString();
                if(MFAServer()->ResendCode(uuid))
                    return OK();
            }
            return UnAuthorized(RESTAPI::Errors::InvalidCredentials, BAD_MFA_TRANSACTION);
        }

        if(GetBoolParameter(RESTAPI::Protocol::COMPLETEMFACHALLENGE,false)) {
            Logger_.information(fmt::format("COMPLETE-MFA-CHALLENGE({}): Request for {}", Request->clientAddress().toString(), userId));
            if(Obj->has("uuid")) {
                SecurityObjects::UserInfoAndPolicy UInfo;
                if(MFAServer()->CompleteMFAChallenge(Obj,UInfo)) {
                    Poco::JSON::Object ReturnObj;
                    UInfo.webtoken.to_json(ReturnObj);
                    return ReturnObject(ReturnObj);
                }
            }
            return UnAuthorized(RESTAPI::Errors::InvalidCredentials, MFA_FAILURE);
        }

        SecurityObjects::UserInfoAndPolicy UInfo;
        bool Expired=false;
        auto Code=AuthService()->Authorize(userId, password, newPassword, UInfo, Expired);
        if (Code==SUCCESS) {
            Poco::JSON::Object ReturnObj;
            if(AuthService()->RequiresMFA(UInfo)) {
                if(MFAServer()->StartMFAChallenge(UInfo, ReturnObj)) {
                    return ReturnObject(ReturnObj);
                }
                Logger_.warning("MFA Seems to be broken. Please fix. Disabling MFA checking for now.");
            }
            UInfo.webtoken.to_json(ReturnObj);
            return ReturnObject(ReturnObj);
        } else {

            switch(Code) {
                case INVALID_CREDENTIALS:
                    return UnAuthorized(RESTAPI::Errors::InvalidCredentials, Code);
                case PASSWORD_INVALID:
                    return UnAuthorized(RESTAPI::Errors::InvalidPassword, Code);
                case PASSWORD_ALREADY_USED:
                    return UnAuthorized(RESTAPI::Errors::PasswordRejected, Code);
                case USERNAME_PENDING_VERIFICATION:
                    return UnAuthorized(RESTAPI::Errors::UserPendingVerification, Code);
                case PASSWORD_CHANGE_REQUIRED:
                    return UnAuthorized(RESTAPI::Errors::PasswordMustBeChanged, Code);
                default:
                    return UnAuthorized(RESTAPI::Errors::InvalidCredentials); break;
            }
            return;
        }
	}
}