//
// Created by stephane bourque on 2021-07-01.
//

#include "RESTAPI_systemEndpoints_handler.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"

namespace OpenWifi {

    void RESTAPI_systemEndpoints_handler::DoGet() {
        auto Services = MicroService::instance().GetServices();
        SecurityObjects::SystemEndpointList L;
        for(const auto &i:Services) {
            SecurityObjects::SystemEndpoint S{
                .type = i.Type,
                .id = i.Id,
                .uri = i.PublicEndPoint};
            L.endpoints.push_back(S);
        }
        Poco::JSON::Object  Obj;
        L.to_json(Obj);
        ReturnObject(Obj);
    }
}