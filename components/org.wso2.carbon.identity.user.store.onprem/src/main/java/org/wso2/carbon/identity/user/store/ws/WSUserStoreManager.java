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
import org.apache.tomcat.jdbc.pool.DataSource;
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
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.JDBCRealmUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class WSUserStoreManager extends AbstractUserStoreManager {

    private static Log log = LogFactory.getLog(WSUserStoreManager.class);
    private static final String ENDPOINT = "EndPointURL";

    private HttpClient httpClient;
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();

    public WSUserStoreManager() {

    }

    /**
     * @param realmConfig
     * @param tenantId
     * @throws UserStoreException
     */
    public WSUserStoreManager(RealmConfiguration realmConfig, int tenantId) throws UserStoreException {
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (log.isDebugEnabled()) {
            if (readGroupsEnabled) {
                log.debug("ReadGroups is enabled for " + getMyDomainName());
            } else {
                log.debug("ReadGroups is disabled for " + getMyDomainName());
            }
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()) {
                writeGroupsEnabled = true;
            }
        }

        if (log.isDebugEnabled()) {
            if (writeGroupsEnabled) {
                log.debug("WriteGroups is enabled for " + getMyDomainName());
            } else {
                log.debug("WriteGroups is disabled for " + getMyDomainName());
            }
        }

        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }

	/* Initialize user roles cache as implemented in AbstractUserStoreManager */
        initUserRolesCache();
    }

    public WSUserStoreManager(org.wso2.carbon.user.api.RealmConfiguration realmConfig,
            Map<String, Object> properties,
            ClaimManager claimManager,
            ProfileConfigurationManager profileManager,
            UserRealm realm, Integer tenantId)
            throws UserStoreException {

        this(realmConfig, tenantId);
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        this.userRealm = realm;
        this.httpClient = new HttpClient();

        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.claimManager = claimManager;
        this.userRealm = realm;

        dataSource = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("User Management Data Source is null");
        }

        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);
        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig.getUserStoreProperties()));

        this.persistDomain();
        doInitialSetup();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        initUserRolesCache();

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
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
                "{\"username\":\"" + userName + "\",\"password\":\"" + password + "\"}",
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

    @Override
    protected void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                             String profileName, boolean requirePasswordChange) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doAddUser");

    }

    @Override
    protected void doUpdateCredential(String userName, Object newCredential, Object oldCredential) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateCredential");

    }

    @Override
    protected void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateCredentialByAdmin");

    }

    @Override
    protected void doDeleteUser(String userName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteUser");

    }

    @Override
    protected void doSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doSetUserClaimValue");

    }

    @Override
    protected void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doSetUserClaimValues");

    }

    @Override
    protected void doDeleteUserClaimValue(String userName, String claimURI, String profileName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteUserClaimValue");

    }

    @Override
    protected void doDeleteUserClaimValues(String userName, String[] claims, String profileName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteUserClaimValues");

    }

    @Override
    protected void doUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateUserListOfRole");

    }

    @Override
    protected void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateRoleListOfUser");

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

    //Todo: Implement doCheckExistingRole
    @Override
    protected boolean doCheckExistingRole(String roleName) throws UserStoreException {
        return true;
    }

    @Override
    protected RoleContext createRoleContext(String roleName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #createRoleContext");
    }

    //Todo: Implement doCheckExistingUser
    @Override
    protected boolean doCheckExistingUser(String userName) throws UserStoreException {
        return true;
    }

    @Override
    protected String[] getUserListFromProperties(String property, String value, String profileName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getUserListFromProperties");
    }

    @Override
    public String[] getProfileNames(String userName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getProfileNames");
    }

    @Override
    public String[] getAllProfileNames() throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getAllProfileNames");
    }

    @Override
    public boolean isReadOnly() throws UserStoreException {
        if ("true".equalsIgnoreCase(realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY))) {
            return true;
        }
        return false;
    }

    public Date getPasswordExpirationTime(String userName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getPasswordExpirationTime");
    }

    @Override
    public int getUserId(String username) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getUserId");
    }

    @Override
    public int getTenantId(String username) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getTenantId");
    }

    @Override
    public int getTenantId() throws UserStoreException {
        return this.tenantId;
    }

    @Override
    public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getProperties");
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        return false;
    }

    @Override
    public void addRememberMe(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #addRememberMe");

    }

    @Override
    public boolean isValidRememberMeToken(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #isValidRememberMeToken");
    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getProperties");
    }

    @Override
    public boolean isBulkImportSupported() {
        return new Boolean(this.realmConfig.getUserStoreProperty("IsBulkImportSupported")).booleanValue();
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return this.realmConfig;
    }

    @Override
    protected String[] doGetSharedRoleNames(String tenantDomain, String filter, int maxItemLimit) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doGetSharedRoleNames");
    }

    //Todo: Implement doGetUserListOfRole
    @Override
    protected String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException {
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
                    String user = (String) users.get(i);
                    if(!"wso2.anonymous.user".equals(user)) {
                        String domain = this.realmConfig.getUserStoreProperty("DomainName");
                        user = UserCoreUtil.addDomainToName(user, domain);
                    }
                    userList.add(user);
                }
            }

        } catch (IOException | JSONException | WSUserStoreException e) {
            log.error("Error occurred while calling backed to authenticate request for tenantId - [" + this.tenantId
                    + "]", e);
        }
        return userList.toArray(new String[userList.size()]);
    }

    @Override
    protected String[] doGetDisplayNamesForInternalRole(String[] userNames) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doGetDisplayNamesForInternalRole");
    }

    @Override
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {
        String[] roles = this.doGetExternalRoleListOfUser(userName, "*");
        if(roles != null) {
            String[] arr$ = roles;
            int len$ = roles.length;

            for(int i$ = 0; i$ < len$; ++i$) {
                String role = arr$[i$];
                if(role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
    }

    public String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {

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

    @Override
    protected String[] doGetSharedRoleListOfUser(String userName, String tenantDomain, String filter) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doGetSharedRoleListOfUser");
    }

    @Override
    protected void doAddRole(String roleName, String[] userList, boolean shared) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doAddRole");

    }

    @Override
    protected void doDeleteRole(String roleName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteRole");

    }

    @Override
    protected void doUpdateRoleName(String roleName, String newRoleName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateRoleName");

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
                JSONArray groups = resultObj.getJSONArray("groups");
                String userStoreDomain = this.realmConfig.getUserStoreProperty("DomainName");
                for (int i = 0; i < groups.length(); i++) {
                    String roleName = (String)groups.get(i);
                    roleName = UserCoreUtil.addDomainToName(roleName, userStoreDomain);
                    roleList.add(roleName);
                }
            }

        } catch (IOException | JSONException | WSUserStoreException e) {
            log.error("Error occurred while get role names for tenantId - [" + this.tenantId
                    + "]", e);
        }
        return roleList.toArray(new String[roleList.size()]);
    }

}