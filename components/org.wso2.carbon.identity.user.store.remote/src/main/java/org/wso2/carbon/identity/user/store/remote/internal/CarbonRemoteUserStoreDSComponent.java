/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.user.store.remote.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.user.store.remote.CarbonRemoteUserStoreManger;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
         name = "remote.user.store.mgt.dscomponent", 
         immediate = true)
public class CarbonRemoteUserStoreDSComponent {

    private static Log log = LogFactory.getLog(CarbonRemoteUserStoreDSComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            UserStoreManager remoteStoreManager = new CarbonRemoteUserStoreManger();
            ctxt.getBundleContext().registerService(UserStoreManager.class.getName(), remoteStoreManager, null);
            if (log.isDebugEnabled()) {
                log.debug("Carbon Remote User Store activated successfully.");
            }
        } catch (Exception e) {
            log.error("Failed to activate Carbon Remote User Store activated successfully ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Carbon Carbon Remote User Store is deactivated ");
        }
    }

    @Reference(
             name = "user.realmservice.default", 
             service = org.wso2.carbon.user.core.service.RealmService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRealmService")
    protected void setRealmService(RealmService rlmService) {
        return;
    }

    protected void unsetRealmService(RealmService realmService) {
        return;
    }
}

