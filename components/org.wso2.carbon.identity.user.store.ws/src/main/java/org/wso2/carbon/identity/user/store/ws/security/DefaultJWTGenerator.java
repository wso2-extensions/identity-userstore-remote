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

package org.wso2.carbon.identity.user.store.ws.security;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.user.store.ws.exception.WSUserStoreException;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class DefaultJWTGenerator implements SecurityTokenBuilder {

    private Algorithm signatureAlgorithm = null;
    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";

    private static final String DEFAULT_SIGNING_ALGORITHM = "SHA512withRSA";
    private static final String IDENTITY_CLOUD_ISSUER = "wso2-identity-cloud";

    public DefaultJWTGenerator() throws WSUserStoreException {
        signatureAlgorithm = mapSignatureAlgorithm(DEFAULT_SIGNING_ALGORITHM);
    }

    protected JWSAlgorithm mapSignatureAlgorithm(String signatureAlgorithm) throws WSUserStoreException {

        switch (signatureAlgorithm) {
            case NONE:
                return new JWSAlgorithm(JWSAlgorithm.NONE.getName());
            case SHA256_WITH_RSA:
                return JWSAlgorithm.RS256;
            case SHA384_WITH_RSA:
                return JWSAlgorithm.RS384;
            case SHA512_WITH_RSA:
                return JWSAlgorithm.RS512;
            case SHA256_WITH_HMAC:
                return JWSAlgorithm.HS256;
            case SHA384_WITH_HMAC:
                return JWSAlgorithm.HS384;
            case SHA512_WITH_HMAC:
                return JWSAlgorithm.HS512;
            case SHA256_WITH_EC:
                return JWSAlgorithm.ES256;
            case SHA384_WITH_EC:
                return JWSAlgorithm.ES384;
            case SHA512_WITH_EC:
                return JWSAlgorithm.ES512;
        }
        throw new WSUserStoreException("Unsupported Signature Algorithm in identity.xml");
    }

    @Override
    public String buildSecurityToken(Key privateKey) throws WSUserStoreException {

        long lifetimeInMillis = 60 * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(IDENTITY_CLOUD_ISSUER);
        jwtClaimsSet.setSubject(CarbonContext.getThreadLocalCarbonContext().getUsername());
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, Key privateKey) throws WSUserStoreException {
        try {
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader((JWSAlgorithm) signatureAlgorithm), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new WSUserStoreException("Error occurred while signing JWT", e);
        }
    }

}
