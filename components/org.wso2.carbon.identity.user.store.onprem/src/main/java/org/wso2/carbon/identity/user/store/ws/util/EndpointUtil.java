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
package org.wso2.carbon.identity.user.store.ws.util;

public class EndpointUtil {

    private final static String USERS_PATH = "/users/";
    private final static String GROUPS_PATH = "/groups/";

    public static String getAuthenticateEndpoint(String hostName) {
        return hostName + "/authenticate";
    }

    public static String getUserClaimRetrievalEndpoint(String hostName, String user) {
        return hostName + USERS_PATH + user;
    }

    public static String getUserListEndpoint(String hostName) {
        return hostName + USERS_PATH;
    }

    public static String getUserRolesListEndpoint(String hostName, String userName) {
        return hostName + USERS_PATH + userName + GROUPS_PATH;
    }

    public static String getRoleListEndpoint(String hostName) {
        return hostName + GROUPS_PATH;
    }
}