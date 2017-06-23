/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.dlic.auth.http.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;

import java.security.AccessController;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.auth.HTTPAuthenticator;
import com.floragunn.searchguard.user.AuthCredentials;

public class HTTPJwtAuthenticator implements HTTPAuthenticator {

    static {
        printLicenseInfo();
    }
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    private static final String BEARER = "bearer ";
    private final JwtParser jwtParser;
    private final String jwtHeaderName;
    private final String jwtUrlParameter;
    private final String rolesKey;
    private final String subjectKey;

    public HTTPJwtAuthenticator(final Settings settings) {
        super();

        String signingKey = settings.get("signing_key");
        
        if(signingKey == null || signingKey.length() == 0) {
            log.error("signingKey must not be null or empty. JWT authentication will not work");
            jwtParser = null;
        } else {

            signingKey = signingKey.replace("-----BEGIN PUBLIC KEY-----\n", "");
            signingKey = signingKey.replace("-----END PUBLIC KEY-----", "");

            byte[] decoded = TextCodec.BASE64.decode(signingKey);
            Key key = null;

            try {
                key = getPublicKey(decoded, "RSA");
            } catch (Exception e) {
                log.debug("No public RSA key, try other algos ({})", e.toString());
            }

            try {
                key = getPublicKey(decoded, "EC");
            } catch (Exception e) {
                log.debug("No public ECDSA key, try other algos ({})", e.toString());
            }

            if(key != null) {
                jwtParser = Jwts.parser().setSigningKey(key);
            } else {
                jwtParser = Jwts.parser().setSigningKey(decoded);
            }

        }
        
        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header","Authorization");
        rolesKey = settings.get("roles_key");
        subjectKey = settings.get("subject_key");
    }
    
    
    @Override
    public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws ElasticsearchSecurityException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        AuthCredentials creds = AccessController.doPrivileged(new PrivilegedAction<AuthCredentials>() {
            @Override
            public AuthCredentials run() {                        
                return extractCredentials0(request);
            }
        });
        
        return creds;
    }

    private AuthCredentials extractCredentials0(final RestRequest request) {        
        if (jwtParser == null) {
            log.error("Missing Signing Key. JWT authentication will not work");
            return null;
        }
        
        String jwtToken = jwtUrlParameter==null?request.header(jwtHeaderName):request.param(jwtUrlParameter);
        
        if (jwtToken == null || jwtToken.length() == 0) {
            if(log.isDebugEnabled()) {
                log.debug("No JWT token found in '{}' {} header", jwtUrlParameter==null?jwtHeaderName:jwtUrlParameter, jwtUrlParameter==null?"header":"url parameter");
            }
            return null;
        }
        
        final int index;
        if((index = jwtToken.toLowerCase().indexOf(BEARER)) > -1) { //detect Bearer 
            jwtToken = jwtToken.substring(index+BEARER.length());
        }
                
        try {
            final Claims claims = jwtParser.parseClaimsJws(jwtToken).getBody();
            
            final String subject = extractSubject(claims, request);
            
            if (subject == null) {
            	log.error("No subject found in JWT token");
            	return null;
            }
            
            final String[] roles = extractRoles(claims, request);	
            
            return new AuthCredentials(subject, roles).markComplete();            
            
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Invalid or expired JWT token. {}",e,e.getMessage());
                e.printStackTrace();
            }
            return null;
        }
    }

    @Override
    public boolean reRequestAuthentication(final RestChannel channel, AuthCredentials creds) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED,"");
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Bearer realm=\"Search Guard\"");
        channel.sendResponse(wwwAuthenticateResponse);
        return true;
    }

    @Override
    public String getType() {
        return "jwt";
    }
    
    protected String extractSubject(final Claims claims, final RestRequest request) {
        String subject = claims.getSubject();        
        if(subjectKey != null) {
    		// try to get roles from claims, first as Object to avoid having to catch the ExpectedTypeException
            Object subjectObject = claims.get(subjectKey, Object.class);
            if(subjectObject == null) {
                log.warn("Failed to get subject from JWT claims, check if subject_key '{}' is correct.", subjectKey);
                return null;
            }
        	// We expect a String. If we find something else, convert to String but issue a warning    	
            if(!(subjectObject instanceof String)) {
        		log.warn("Expected type String for roles in the JWT for subject_key {}, but value was '{}' ({}). Will convert this value to String.", subjectKey, subjectObject, subjectObject.getClass());    					
            }
            subject = String.valueOf(subjectObject);
        }
        return subject;
    }
    
    protected String[] extractRoles(final Claims claims, final RestRequest request) {
    	// no roles key specified
    	if(rolesKey == null) {
    		return new String[0];
    	}
		// try to get roles from claims, first as Object to avoid having to catch the ExpectedTypeException
    	final Object rolesObject = claims.get(rolesKey, Object.class);
    	if(rolesObject == null) {
    		log.warn("Failed to get roles from JWT claims with roles_key '{}'. Check if this key is correct and available in the JWT payload.", rolesKey);   
    		return new String[0];
    	}
    	// We expect a String. If we find something else, convert to String but issue a warning    	
    	if (!(rolesObject instanceof String)) {
    		log.warn("Expected type String for roles in the JWT for roles_key {}, but value was '{}' ({}). Will convert this value to String.", rolesKey, rolesObject, rolesObject.getClass());    					
		}    	
    	return String.valueOf(rolesObject).split(",");    	
    }
    
    /*private static PrivateKey getPrivateKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePrivate(spec);
    }*/

    private static PublicKey getPublicKey(final byte[] keyBytes, final String algo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algo);
        return kf.generatePublic(spec);
    }
    
    public static void printLicenseInfo() {
        System.out.println("******************************************************");
        System.out.println("Search Guard JWT (JSON Web Token) is not free software");
        System.out.println("for commercial use in production.");
        System.out.println("You have to obtain a license if you ");
        System.out.println("use it in production.");
        System.out.println("*****************************************************");
    }
}
