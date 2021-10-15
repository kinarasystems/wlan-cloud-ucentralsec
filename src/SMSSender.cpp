//
// Created by stephane bourque on 2021-10-09.
//

#include "SMSSender.h"
#include "Daemon.h"
#include <aws/sns/SNSClient.h>
#include <aws/sns/model/PublishRequest.h>
#include <aws/sns/model/PublishResult.h>
#include <aws/sns/model/GetSMSAttributesRequest.h>
#include "MFAServer.h"

#include "SMS_provider_aws.h"
#include "SMS_provider_twilio.h"

namespace OpenWifi {
    class SMSSender * SMSSender::instance_ = nullptr;

    int SMSSender::Start() {
        Provider_ = Daemon()->ConfigGetString("sms.provider","aws");
        if(Provider_=="aws") {
            ProviderImpl_ = std::make_unique<SMS_provider_aws>(Logger_);
        } else if(Provider_=="twilio") {
            ProviderImpl_ = std::make_unique<SMS_provider_twilio>(Logger_);
        }
        Enabled_ = ProviderImpl_->Initialize();
        return 0;
    }

    void SMSSender::Stop() {
    }

    void SMSSender::CleanCache() {
        uint64_t Now=std::time(nullptr);
        for(auto i=begin(Cache_);i!=end(Cache_);) {
            if((Now-i->Created)>300)
                i = Cache_.erase(i);
            else
                ++i;
        }
    }

    bool SMSSender::StartValidation(const std::string &Number, const std::string &UserName) {
        std::lock_guard     G(Mutex_);
        CleanCache();
        uint64_t Now=std::time(nullptr);
        auto Challenge = MFAServer::MakeChallenge();
        Cache_.emplace_back(SMSValidationCacheEntry{.Number=Number, .Code=Challenge, .UserName=UserName, .Created=Now});
        std::string Message = "Please enter the following code on your login screen: " + Challenge;
        return ProviderImpl_->Send(Number, Message);
    }

    bool SMSSender::IsNumberValid(const std::string &Number, const std::string &UserName) {
        std::lock_guard     G(Mutex_);

        for(const auto &i:Cache_) {
            if(i.Number==Number && i.UserName==UserName)
                return i.Validated;
        }
        return false;
    }

    bool SMSSender::CompleteValidation(const std::string &Number, const std::string &Code, const std::string &UserName) {
        std::lock_guard     G(Mutex_);

        for(auto &i:Cache_) {
            if(i.Code==Code && i.Number==Number && i.UserName==UserName) {
                i.Validated=true;
                return true;
            }
        }
        return false;
    }

    bool SMSSender::Send(const std::string &PhoneNumber, const std::string &Message) {
        if(!Enabled_) {
            Logger_.information("SMS has not been enabled. Messages cannot be sent.");
            return false;
        }
        return ProviderImpl_->Send(PhoneNumber,Message);
    }
}