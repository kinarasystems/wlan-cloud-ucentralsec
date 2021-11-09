//
// Created by stephane bourque on 2021-11-08.
//

#include "ActionLinkManager.h"
#include "StorageService.h"

namespace OpenWifi {

    int ActionLinkManager::Start() {
        if(!Running_)
            Thr_.start(*this);
        return 0;
    }

    void ActionLinkManager::Stop() {
        if(Running_) {
            Running_ = false;
            Thr_.wakeUp();
            Thr_.join();
        }
    }

    void ActionLinkManager::run() {
        Running_ = true ;

        while(Running_) {
            Poco::Thread::trySleep(2000);
            if(!Running_)
                break;
            std::vector<SecurityObjects::ActionLink>    Links;
            {
                std::lock_guard G(Mutex_);
                StorageService()->GetActions(Links);
            }

            if(Links.empty())
                continue;

            for(auto &i:Links) {
                if(!Running_)
                    break;

                if(i.action=="forgot_password") {
                    if(AuthService::SendEmailToUser(i.id, i.userId, AuthService::FORGOT_PASSWORD)) {
                        Logger_.information(Poco::format("Send password reset link to %s",i.userId));
                    }
                    StorageService()->SentAction(i.id);
                } else if (i.action=="email_verification") {
                    if(AuthService::SendEmailToUser(i.id, i.userId, AuthService::EMAIL_VERIFICATION)) {
                        Logger_.information(Poco::format("Send password reset link to %s",i.userId));
                    }
                    StorageService()->SentAction(i.id);
                } else {
                    StorageService()->SentAction(i.id);
                }
            }
        }
    }

}