//
// Created by stephane bourque on 2021-11-08.
//

#ifndef OWSEC_ACTIONLINKMANAGER_H
#define OWSEC_ACTIONLINKMANAGER_H

#include "framework/MicroService.h"

namespace OpenWifi {

    class ActionLinkManager : public SubSystemServer, Poco::Runnable {
    public:
        static ActionLinkManager * instance() {
            static ActionLinkManager instance;
            return &instance;
        }

        int Start() final;
        void Stop() final;
        void run();

    private:
        Poco::Thread        Thr_;
        std::atomic_bool    Running_ = false;

        ActionLinkManager() noexcept:
            SubSystemServer("ActionLinkManager", "ACTION-SVR", "action.server")
                {
                }
    };
    inline ActionLinkManager * ActionLinkManager() { return ActionLinkManager::instance(); }
}

#endif //OWSEC_ACTIONLINKMANAGER_H