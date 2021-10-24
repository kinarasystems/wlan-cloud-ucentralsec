//
// Created by stephane bourque on 2021-07-10.
//

#include "RESTAPI_AssetServer.h"
#include "Poco/File.h"
#include "framework/RESTAPI_protocol.h"
#include "framework/MicroService.h"
#include "Daemon.h"

namespace OpenWifi {
    void RESTAPI_AssetServer::DoGet() {
        Poco::File  AssetFile;

        if(Request->getURI().find("/favicon.ico") != std::string::npos) {
            AssetFile = Daemon()->AssetDir() + "/favicon.ico";
        } else {
            std::string AssetName = GetBinding(RESTAPI::Protocol::ID, "");
            AssetFile = Daemon()->AssetDir() + "/" + AssetName;
        }
        if(!AssetFile.isFile()) {
            return NotFound();
        }
        SendFile(AssetFile);
    }
}