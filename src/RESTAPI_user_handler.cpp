//
// Created by stephane bourque on 2021-06-21.
//

#include "RESTAPI_user_handler.h"
#include "StorageService.h"
#include "Poco/JSON/Parser.h"
#include "Utils.h"
#include "RESTAPI_utils.h"

namespace uCentral {
    void RESTAPI_user_handler::handleRequest(Poco::Net::HTTPServerRequest &Request, Poco::Net::HTTPServerResponse &Response) {

        if (!ContinueProcessing(Request, Response))
            return;

        if (!IsAuthorized(Request, Response))
            return;

        ParseParameters(Request);
        if(Request.getMethod()==Poco::Net::HTTPRequest::HTTP_GET)
            DoGet(Request, Response);
        else if(Request.getMethod()==Poco::Net::HTTPRequest::HTTP_POST)
            DoPost(Request, Response);
        else if(Request.getMethod()==Poco::Net::HTTPRequest::HTTP_DELETE)
            DoDelete(Request, Response);
        else if(Request.getMethod()==Poco::Net::HTTPRequest::HTTP_PUT)
            DoPut(Request, Response);
        else
            BadRequest(Request, Response, "Unimplemented HTTP Operation.");
    }

    void RESTAPI_user_handler::DoGet(Poco::Net::HTTPServerRequest &Request, Poco::Net::HTTPServerResponse &Response) {
        try {
            std::string Id = GetBinding("id", "");
            if(Id.empty()) {
                BadRequest(Request, Response, "You must supply the ID of the user.");
                return;
            }

            SecurityObjects::UserInfo   UInfo;
            if(!Storage()->GetUserById(Id,UInfo)) {
                NotFound(Request, Response);
                return;
            }

            Poco::JSON::Object  UserInfoObject;
            UInfo.to_json(UserInfoObject);

            ReturnObject(Request, UserInfoObject, Response);
            return;
        } catch (const Poco::Exception &E ) {
            Logger_.log(E);
        }
        BadRequest(Request, Response);
    }

    void RESTAPI_user_handler::DoDelete(Poco::Net::HTTPServerRequest &Request, Poco::Net::HTTPServerResponse &Response) {
        try {
            std::string Id = GetBinding("id", "");
            if(Id.empty()) {
                BadRequest(Request, Response, "You must supply the ID of the user.");
                return;
            }
            if(!Storage()->DeleteUser(UserInfo_.userinfo.name,Id)) {
                NotFound(Request, Response);
                return;
            }
            Logger_.information(Poco::format("User '%s' deleted by '%s'.",Id,UserInfo_.userinfo.email));
            OK(Request, Response);
            return;
        } catch (const Poco::Exception &E ) {
            Logger_.log(E);
        }
        BadRequest(Request, Response);
    }

    void RESTAPI_user_handler::DoPost(Poco::Net::HTTPServerRequest &Request, Poco::Net::HTTPServerResponse &Response) {
        try {
            std::string Id = GetBinding("id", "");
            if(Id!="0") {
                BadRequest(Request, Response, "To create a user, you must set the ID to 0");
                return;
            }

            SecurityObjects::UserInfo   UInfo;
            RESTAPI_utils::from_request(UInfo,Request);

            Poco::toLowerInPlace(UInfo.email);
            if(!Utils::ValidEMailAddress(UInfo.email)) {
                BadRequest(Request, Response, "Invalid email address.");
                return;
            }

            if(!Storage()->CreateUser(UserInfo_.userinfo.name,UInfo)) {
                Logger_.information(Poco::format("Could not add user '%s'.",UInfo.email));
                BadRequest(Request, Response);
                return;
            }

            if(!Storage()->GetUserByEmail(UInfo.email, UInfo)) {
                Logger_.information(Poco::format("User '%s' but not retrieved.",UInfo.email));
                BadRequest(Request, Response);
                return;
            }

            Poco::JSON::Object  UserInfoObject;
            UInfo.to_json(UserInfoObject);

            ReturnObject(Request, UserInfoObject, Response);

            Logger_.information(Poco::format("User '%s' has been added by '%s')",UInfo.email, UserInfo_.userinfo.email));
            return;
        } catch (const Poco::Exception &E ) {
            Logger_.log(E);
        }
        BadRequest(Request, Response);
    }

    void RESTAPI_user_handler::DoPut(Poco::Net::HTTPServerRequest &Request, Poco::Net::HTTPServerResponse &Response) {
        try {
            std::string Id = GetBinding("id", "");
            if(Id.empty()) {
                BadRequest(Request, Response, "You must supply the ID of the user.");
                return;
            }

            SecurityObjects::UserInfo   LocalObject;
            if(!Storage()->GetUserById(Id,LocalObject)) {
                NotFound(Request, Response);
                return;
            }

            Poco::JSON::Parser IncomingParser;
            auto RawObject = IncomingParser.parse(Request.stream()).extract<Poco::JSON::Object::Ptr>();

            // The only valid things to change are: changePassword, name,
            if(RawObject->has("name"))
                LocalObject.name = RawObject->get("name").toString();
            if(RawObject->has("description"))
                LocalObject.description = RawObject->get("description").toString();
            if(RawObject->has("avatar"))
                LocalObject.avatar = RawObject->get("avatar").toString();
            if(RawObject->has("changePassword"))
                LocalObject.changePassword = RawObject->get("changePassword").toString()=="true";
            if(RawObject->has("owner"))
                LocalObject.owner = RawObject->get("owner").toString();
            if(RawObject->has("location"))
                LocalObject.location = RawObject->get("location").toString();
            if(RawObject->has("locale"))
                LocalObject.locale = RawObject->get("locale").toString();
            if(RawObject->has("userRole"))
                LocalObject.location = RawObject->get("userRole").toString();
            if(RawObject->has("suspended"))
                LocalObject.suspended = RawObject->get("suspended").toString()=="true";
            if(RawObject->has("blackListed"))
                LocalObject.blackListed = RawObject->get("blackListed").toString()=="true";
            if(RawObject->has("notes")) {
                SecurityObjects::NoteInfoVec NIV;
                NIV = RESTAPI_utils::to_object_array<SecurityObjects::NoteInfo>(RawObject->get("notes").toString());
                for(auto const &i:NIV) {
                    SecurityObjects::NoteInfo   ii{.created=(uint64_t)std::time(nullptr), .createdBy=UserInfo_.userinfo.email, .note=i.note};
                    LocalObject.notes.push_back(ii);
                }
            }
            if(RawObject->has("currentPassword")) {
                if(!AuthService()->SetPassword(RawObject->get("currentPassword").toString(),LocalObject)) {
                    BadRequest(Request, Response, "Password was rejected. This maybe an old password.");
                    return;
                }
            }
            if(Storage()->UpdateUserInfo(UserInfo_.userinfo.email,Id,LocalObject)) {
                Poco::JSON::Object  ModifiedObject;
                LocalObject.to_json(ModifiedObject);
                ReturnObject(Request, ModifiedObject, Response);
                return;
            }
        } catch( const Poco::Exception &E) {
            Logger_.log(E);
        }
        BadRequest(Request, Response);
    }
}