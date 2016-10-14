/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.user.store.ws.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.user.store.ws.CleanupSchedulerTask;
import org.wso2.carbon.identity.user.store.ws.WSUserStoreManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Timer;

/**
 * @scr.component name="onprem.ws.user.store.component" immediate=true
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 */
public class WSUserStoreDSComponent {

    private static Log log = LogFactory.getLog(WSUserStoreDSComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {

            UserStoreManager remoteStoreManager = new WSUserStoreManager();
            ctxt.getBundleContext().registerService(UserStoreManager.class.getName(),
                    remoteStoreManager, null);
            scheduleCleanupTask();

            if (log.isDebugEnabled()) {
                log.debug("Carbon Remote User Store activated successfully.");
            }

        } catch (Throwable e) {
            log.error("Failed to activate Carbon Remote User Store activated successfully ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Carbon Carbon Remote User Store is deactivated ");
        }
    }

    protected void setRealmService(RealmService realmService) {
        WSUserStoreComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        WSUserStoreComponentHolder.getInstance().setRealmService(null);
    }

    public static void setRegistryService(RegistryService registryService) {
        WSUserStoreComponentHolder.getInstance().setRegistryService(registryService);
    }

    public static RegistryService getRegistryService() {
        return WSUserStoreComponentHolder.getInstance().getRegistryService();
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in user Store bundle");
        }
        WSUserStoreComponentHolder.getInstance().setRegistryService(null);
    }

    private void scheduleCleanupTask(){
        Timer time = new Timer();
        CleanupSchedulerTask cleanupSchedulerTask = new CleanupSchedulerTask();
        time.schedule(cleanupSchedulerTask, 0, 5 * 60 * 60 * 1000);
    }
}
