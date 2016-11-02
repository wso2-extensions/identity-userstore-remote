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

package org.wso2.carbon.identity.user.store.ws.util;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import sun.misc.BASE64Encoder;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Utility class to file operations such as create, delete, zip etc..
 */
public class FileUtil {

    private static Log log = LogFactory.getLog(FileUtil.class);
    public final static String AGENT_TEMP_PATH = "/repository/resources/agent/tmp/";
    public final static String AGENT_STATIC_FILES_PATH = "/repository/resources/agent/static";
    public final static String AGENT_SECURITY_FILES_PATH = "/agent/conf/security/";
    public final static String AGENT_FILE_NAME = "wso2agent.zip";
    public final static String PUBLIC_KEY_NAME = "public.cert";


    /**
     * Get directory name with timestamp
     *
     * @return directory name
     */
    public static String getDirectoryNameInTimestamp() {
        long milliseconds = new Date().getTime();
        return Long.toString(milliseconds);
    }

    /**
     * Delete temporary created directory
     *
     * @param dirPath
     * @throws java.io.IOException
     */
    public void deleteDirectory(String dirPath) throws IOException {
        File directory = new File(dirPath);
        FileUtils.deleteDirectory(directory);
    }

    /**
     * Copy files
     *
     * @param sourcePath
     * @param destinationPath
     * @throws IOException
     */
    public void copyFiles(String sourcePath, String destinationPath) throws IOException {
        File source = new File(sourcePath);
        File destination = new File(destinationPath);
        FileUtils.copyDirectory(source, destination);
    }

    /**
     * Copy Public key to temporary location
     *
     * This method throws General Exception since current keyStoreManager.getDefaultPublicKey() throws Exception
     * @param publicKeyPath
     * @throws Exception
     */
    public void copyPublicKey(String publicKeyPath) throws Exception{
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantID);
        DataOutputStream dos = null;
        KeyStore keyStore;
        PublicKey publicKey;

        try {
            File file =  new File(publicKeyPath);
            FileOutputStream fos =  new FileOutputStream(file);
            dos =  new DataOutputStream(fos);

            if(tenantID != MultitenantConstants.SUPER_TENANT_ID) {
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                Certificate publicCert = keyStore.getCertificate(tenantDomain); //Default keystore alias = tenantDomain name
                publicKey = publicCert.getPublicKey();
            } else {
                publicKey = keyStoreManager.getDefaultPublicKey();

            }

            byte []keyBytes = publicKey.getEncoded();
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

    private static String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(".", "-");
        return ksName + ".jks";
    }

    /**
     * Zip directory
     * @param srcFolder
     * @param destinationZipFile
     * @throws Exception
     */
    public void zipDirectory(String srcFolder, String destinationZipFile) throws IOException {
        FileOutputStream fileWriter = new FileOutputStream(destinationZipFile);
        ZipOutputStream zip = new ZipOutputStream(fileWriter);
        addFolderToZip("", srcFolder, zip);
        zip.flush();
        zip.close();
    }

    /**
     * Add files to zip
     * @param path
     * @param srcFile
     * @param zip
     * @param flag
     * @throws Exception
     */
    private void addFileToZip(String path, String srcFile, ZipOutputStream zip, boolean flag) throws IOException {

        File folder = new File(srcFile);

        if (flag == true) {
            zip.putNextEntry(new ZipEntry(path + "/" + folder.getName() + "/"));
        } else {
            if (folder.isDirectory()) {
                addFolderToZip(path, srcFile, zip);
            } else {
                byte[] buf = new byte[1024];
                int len;
                FileInputStream in = new FileInputStream(srcFile);
                zip.putNextEntry(new ZipEntry(path + "/" + folder.getName()));
                while ((len = in.read(buf)) > 0) {
                    zip.write(buf, 0, len);
                }
            }
        }
    }

    /**
     * Add folder to zip
     * @param path
     * @param srcFolder
     * @param zip
     * @throws Exception
     */
    private void addFolderToZip(String path, String srcFolder, ZipOutputStream zip) throws IOException {
        File folder = new File(srcFolder);

        if (folder.list().length == 0) {
            addFileToZip(path, srcFolder, zip, true);
        } else {
            for (String fileName : folder.list()) {
                if (path.equals("")) {
                    addFileToZip(folder.getName(), srcFolder + "/" + fileName, zip, false);
                } else {
                    addFileToZip(path + "/" + folder.getName(), srcFolder + "/" + fileName, zip, false);
                }
            }
        }
    }



}
