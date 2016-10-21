/*
*  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.carbon.identity.user.store.ws;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.store.ws.cache.UserAttributeCache;
import org.wso2.carbon.identity.user.store.ws.cache.UserAttributeCacheEntry;
import org.wso2.carbon.identity.user.store.ws.cache.UserAttributeCacheKey;
import org.wso2.carbon.identity.user.store.ws.exception.WSUserStoreException;
import org.wso2.carbon.identity.user.store.ws.internal.WSUserStoreComponentHolder;
import org.wso2.carbon.identity.user.store.ws.security.DefaultJWTGenerator;
import org.wso2.carbon.identity.user.store.ws.security.SecurityTokenBuilder;
import org.wso2.carbon.identity.user.store.ws.util.EndpointUtil;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class WSUserStoreManager extends JDBCUserStoreManager {

    private static Log log = LogFactory.getLog(WSUserStoreManager.class);
    private static final String ENDPOINT = "EndPointURL";

    private HttpClient httpClient;
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();

    public WSUserStoreManager() {

    }

    public WSUserStoreManager(org.wso2.carbon.user.api.RealmConfiguration realmConfig,
            Map<String, Object> properties,
            ClaimManager claimManager,
            ProfileConfigurationManager profileManager,
            UserRealm realm, Integer tenantId)
            throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId, false);
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        this.userRealm = realm;
        this.httpClient = new HttpClient();
    }

    private void addAttributesToCache(String userName, Map<String, String> attributes) {

        UserAttributeCacheKey cacheKey = new UserAttributeCacheKey(userName);
        UserAttributeCacheEntry cacheEntry = new UserAttributeCacheEntry();
        cacheEntry.setUserAttributes(attributes);
        UserAttributeCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private UserAttributeCacheEntry getUserAttributesFromCache(String userName) {

        UserAttributeCacheKey cacheKey = new UserAttributeCacheKey(userName);
        return UserAttributeCache.getInstance().getValueFromCache(cacheKey);
    }

    protected void setAuthorizationHeader(HttpMethodBase request) throws WSUserStoreException {

        String token;
        SecurityTokenBuilder securityTokenBuilder = new DefaultJWTGenerator();
        token = securityTokenBuilder.buildSecurityToken(getTenantPrivateKey(tenantId));
        request.addRequestHeader("Authorization", "Bearer " + token);
    }

    private Key getTenantPrivateKey(int tenantId) throws WSUserStoreException {

        Key privateKey;
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);

        if (!(privateKeys.containsKey(tenantId))) {
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

            } else {
                try {
                    privateKey = tenantKSM.getDefaultPrivateKey();
                } catch (Exception e) {
                    throw new WSUserStoreException("Error while obtaining private key for super tenant", e);
                }
            }
            privateKeys.put(tenantId, privateKey);
        } else {
            privateKey = privateKeys.get(tenantId);
        }
        return privateKey;
    }

    private String getHostName() {
        return this.realmConfig.getUserStoreProperty(ENDPOINT);
    }

    private StringRequestEntity getAuthenticateEntity(String userName, Object password)
            throws UnsupportedEncodingException {
        return new StringRequestEntity(
                "{\"username\":" + userName + ",\"password\":" + password + "}",
                "application/json",
                "UTF-8");
    }

    public boolean doAuthenticate(String username, Object credential) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Processing authentication request for tenantId  - [" + this.tenantId + "]");
        }
        boolean authStatus = false;
        PostMethod postRequest = new PostMethod(EndpointUtil.getAuthenticateEndpoint(getHostName()));
        try {

            if (this.httpClient == null) {
                this.httpClient = new HttpClient();
            }
            setAuthorizationHeader(postRequest);
            postRequest.setRequestEntity(getAuthenticateEntity(username, credential));
            int response = httpClient.executeMethod(postRequest);
            if (response == HttpStatus.SC_OK) {
                String respStr = new String(postRequest.getResponseBody());
                JSONObject resultObj = new JSONObject(respStr);
                authStatus = (boolean) resultObj.get("authenticated");
            }

        } catch (IOException | WSUserStoreException | JSONException e) {
            log.error("Error occurred while calling backed to authenticate request for tenantId - [" + this.tenantId
                    + "]", e);
        }
        return authStatus;
    }

    public Properties getDefaultUserStoreProperties() {

        Properties properties = new Properties();
        Property endpoint = new Property(ENDPOINT, "", "Agent Server Host", null);
        Property disabled = new Property("Disabled", "false", "Disabled#Check to disable the user store", null);

        Property[] mandatoryProperties = new Property[] { endpoint };
        Property[] optionalProperties = new Property[] { disabled };

        properties.setOptionalProperties(optionalProperties);
        properties.setMandatoryProperties(mandatoryProperties);
        return properties;
    }

    private NameValuePair[] getQueryString(String paramName, String[] paramValues) {
        StringBuilder queryBuilder = new StringBuilder();

        for (String param : paramValues) {
            queryBuilder.append(",").append(param);
        }

        NameValuePair param = new NameValuePair(paramName, queryBuilder.toString().replaceFirst(",", ""));

        return new NameValuePair[] { param };
    }

    private String[] getAllClaimMapAttributes(ClaimMapping[] claimMappings) {

        List<String> mapAttributes = new ArrayList<>();
        for (ClaimMapping mapping : claimMappings) {
            mapAttributes.add(mapping.getMappedAttribute());
        }
        return mapAttributes.toArray(new String[mapAttributes.size()]);
    }

    public Map<String, String> getUserPropertyValues(String userName, String[] propertyNames, String profileName)
            throws UserStoreException {

        UserAttributeCacheEntry cacheEntry = getUserAttributesFromCache(userName);
        Map<String, String> allUserAttributes = new HashMap<>();
        Map<String, String> mapAttributes = new HashMap<>();
        if (cacheEntry == null) {
            GetMethod getMethod = new GetMethod(EndpointUtil.getUserClaimRetrievalEndpoint(getHostName(), userName));
            try {
                if (this.httpClient == null) {
                    this.httpClient = new HttpClient();
                }

                ClaimManager claimManager = WSUserStoreComponentHolder.getInstance().getRealmService()
                        .getBootstrapRealm().getClaimManager();
                getMethod.setQueryString(getQueryString("attributes",
                        getAllClaimMapAttributes(claimManager.getAllClaimMappings())));
                setAuthorizationHeader(getMethod);
                int response = httpClient.executeMethod(getMethod);
                if (response == HttpStatus.SC_OK) {
                    String respStr = new String(getMethod.getResponseBody());
                    JSONObject resultObj = new JSONObject(respStr);
                    Iterator iterator = resultObj.keys();
                    while (iterator.hasNext()) {
                        String key = (String)iterator.next();
                        allUserAttributes.put(key, (String) resultObj.get(key));
                    }
                    addAttributesToCache(userName, allUserAttributes);
                }
            } catch (IOException | JSONException | WSUserStoreException e) {
                log.error("Error occurred while calling backed to authenticate request for tenantId - [" + this.tenantId
                        + "]", e);
                return Collections.EMPTY_MAP;
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                log.error("Error occurred while calling backed to authenticate request for tenantId - [" + this.tenantId
                        + "]", e);
                return Collections.EMPTY_MAP;
            }
        } else {
            allUserAttributes = cacheEntry.getUserAttributes();
        }
        for (String propertyName : propertyNames) {
            mapAttributes.put(propertyName, allUserAttributes.get(propertyName));
        }
        return mapAttributes;
    }

    public Date getPasswordExpirationTime(String userName) throws UserStoreException {
        return null;
    }

    public String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Processing getListUsers request for tenantId  - [" + this.tenantId + "]");
        }
        GetMethod getMethod = new GetMethod(EndpointUtil.getUserListEndpoint(getHostName()));
        List<String> userList = new ArrayList<>();
        try {

            if (this.httpClient == null) {
                this.httpClient = new HttpClient();
            }

            getMethod.setQueryString(getQueryString("limit", new String[]{String.valueOf(maxItemLimit)}));
            setAuthorizationHeader(getMethod);
            int response = httpClient.executeMethod(getMethod);
            if (response == HttpStatus.SC_OK) {
                String respStr = new String(getMethod.getResponseBody());
                JSONObject resultObj = new JSONObject(respStr);
                JSONArray users = resultObj.getJSONArray("usernames");
                for (int i = 0; i < users.length(); i++) {
                    userList.add((String) users.get(i));
                }
            }

        } catch (IOException | JSONException | WSUserStoreException e) {
            log.error("Error occurred while calling backed to authenticate request for tenantId - [" + this.tenantId
                    + "]", e);
        }
        return userList.toArray(new String[userList.size()]);
    }

    public String[] getRoleListOfUser(String userName) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Processing getRoleListOfUser request for tenantId  - [" + this.tenantId + "]");
        }
        GetMethod getMethod = new GetMethod(EndpointUtil.getUserRolesListEndpoint(getHostName(), userName));
        List<String> groupList = new ArrayList<>();
        try {

            if (this.httpClient == null) {
                this.httpClient = new HttpClient();
            }

            setAuthorizationHeader(getMethod);
            int response = httpClient.executeMethod(getMethod);
            if (response == HttpStatus.SC_OK) {
                String respStr = new String(getMethod.getResponseBody());
                JSONObject resultObj = new JSONObject(respStr);
                JSONArray users = resultObj.getJSONArray("groups");
                for (int i = 0; i < users.length(); i++) {
                    groupList.add((String) users.get(i));
                }
            }
        } catch (IOException | JSONException | WSUserStoreException e) {
            log.error("Error occurred while getting user groups for tenantId - [" + this.tenantId
                    + "]", e);
        }
        return groupList.toArray(new String[groupList.size()]);
    }

    public String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Processing doGetRoleNames request for tenantId  - [" + this.tenantId + "]");
        }
        GetMethod getMethod = new GetMethod(EndpointUtil.getRoleListEndpoint(getHostName()));
        List<String> roleList = new ArrayList<>();
        try {

            if (this.httpClient == null) {
                this.httpClient = new HttpClient();
            }

            setAuthorizationHeader(getMethod);
            int response = httpClient.executeMethod(getMethod);
            if (response == HttpStatus.SC_OK) {
                String respStr = new String(getMethod.getResponseBody());
                JSONObject resultObj = new JSONObject(respStr);
                JSONArray groups = resultObj.getJSONArray("roles");
                for (int i = 0; i < groups.length(); i++) {
                    roleList.add((String) groups.get(i));
                }
            }

        } catch (IOException | JSONException | WSUserStoreException e) {
            log.error("Error occurred while get role names for tenantId - [" + this.tenantId
                    + "]", e);
        }
        return roleList.toArray(new String[roleList.size()]);
    }
}