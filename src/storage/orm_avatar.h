//
// Created by stephane bourque on 2021-12-27.
//

#pragma once

#include "framework/orm.h"
#include "RESTObjects/RESTAPI_SecurityObjects.h"

namespace OpenWifi {

/*
    std::string             id;
    std::string             type;
    uint64_t                created=0;
    std::string             name;
    Poco::Data::LOB<char>   avatar;
*/

    typedef Poco::Tuple <
            std::string,            // id
            std::string,            // type
            uint64_t,               // created
            std::string,            // name
            Poco::Data::LOB<char>   // avatar
    > AvatarRecordTuple;
    typedef std::vector <AvatarRecordTuple> AvatarRecordTupleList;

    class AvatarDB : public ORM::DB<AvatarRecordTuple, SecurityObjects::Avatar> {
    public:
        AvatarDB( const std::string &name, const std::string &shortname, OpenWifi::DBType T, Poco::Data::SessionPool & P, Poco::Logger &L);

        bool SetAvatar(const std::string & Admin, std::string &Id, Poco::TemporaryFile &FileName, std::string &Type, std::string & Name);
        bool GetAvatar(const std::string & Admin, std::string &Id, Poco::TemporaryFile &FileName, std::string &Type, std::string & Name);
        bool DeleteAvatar(const std::string & Admin, std::string &Id);

    private:

    };
}