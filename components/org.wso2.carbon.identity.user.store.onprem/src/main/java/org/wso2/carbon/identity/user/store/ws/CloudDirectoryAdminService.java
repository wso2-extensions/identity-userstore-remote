/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.core.util.KeyStoreManager;
import sun.misc.BASE64Encoder;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

public class CloudDirectoryAdminService extends AbstractAdmin {

    private static Log log = LogFactory.getLog(CloudDirectoryAdminService.class);
    private final static String APP_PATH = "";
    private final static String TEMP_PATH = "/resources/tmp/";

    public boolean downloadAgent() {
        try {
            String directoryName = getDirnameInTimestamp();
            copyAgentFiles(directoryName);
            copyPublicKey(directoryName);
            File file = new File(TEMP_PATH + directoryName + "/" + "agent");
            //file.zip(TEMP_PATH + dirname + "/" + "wso2agent" + ".tgz");
            //deleteDirectory(TEMP_PATH + dirname + "/" + "agent");
        } catch (Exception e) {

        }
    }

    private String getDirnameInTimestamp() {
        long milliseconds = new Date().getTime();
        return Long.toString(milliseconds);
    }


    private void deleteDirectory(String dirPath) throws IOException {
        File directory = new File(APP_PATH + dirPath);
        FileUtils.deleteDirectory(directory);
    }

    /**
     * Copy Static agent files into temporary location
     *
     * @param directoryName
     * @throws IOException
     */
    private void copyAgentFiles(String directoryName) throws IOException {
        File source = new File(APP_PATH + "/resources/agent");
        File destination = new File(APP_PATH + TEMP_PATH + directoryName + "/" + "agent" + "/");
        FileUtils.copyDirectory(source, destination);
    }

    /**
     * Copy Public key to temporary location
     *
     * This method throws General Exception since current keyStoreManager.getDefaultPublicKey() throws Exception
     * @param directoryName
     * @throws Exception
     */
    private void copyPublicKey(String directoryName) throws Exception{
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantID);
        DataOutputStream dos = null;

        try {
            File file =  new File(APP_PATH + TEMP_PATH + directoryName + "/agent/conf/security/" + "public.cert");
            FileOutputStream fos =  new FileOutputStream(file);
            dos =  new DataOutputStream(fos);
            byte []keyBytes = keyStoreManager.getDefaultPublicKey().getEncoded();
            BASE64Encoder encoder= new BASE64Encoder();
            String encoded = encoder.encodeBuffer(keyBytes);
            dos.writeBytes(encoded);
            dos.flush();
        } finally{
            try {
                dos.close();
            } catch (IOException e) {
                log.error("Error occurred while closing data stream", e);
            }
        }
    }

    public boolean testConnection(String url) {

        GetMethod getMethod = new GetMethod(url);
        boolean result;
        try {
            HttpClient httpClient = new HttpClient();
            int response = httpClient.executeMethod(getMethod);
            if (response == HttpStatus.SC_OK) {
                result = true;
            } else {
                result = false;
            }
        } catch (IOException e) {
            log.error("Error occurred while calling backed to authenticate request for tenantId - [" + this
                    .getTenantDomain()
                    + "]", e);
            result = false;
        }
        return result;
    }

}
