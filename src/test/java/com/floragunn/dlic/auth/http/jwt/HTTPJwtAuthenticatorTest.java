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

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.user.AuthCredentials;
import com.google.common.io.BaseEncoding;

public class HTTPJwtAuthenticatorTest {

    
    @Test
    public void testNoKey() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder().build();
        
        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNull(creds);
    }
    
    @Test
    public void testBadKey() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(new byte[]{1,3,3,4,3,6,7,8,3,10})).build();
        
        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNull(creds);
    }
    
    @Test
    public void testInvalid() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();
        
        String jwsToken = "123invalidtoken..";
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNull(creds);
    }
    
    @Test
    public void testBearer() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();
        
        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer "+jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }
    
    @Test
    public void testNonBearer() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder().put("signing_key", BaseEncoding.base64().encode(secretKey)).build();
        
        String jwsToken = Jwts.builder().setSubject("Leonard McCoy").signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }
    
    @Test
    public void testRoles() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("roles_key", "roles")
                .build();
        
        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", "role1,role2")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(2, creds.getBackendRoles().size());
    }
    
    @Test
    public void testAlternativeSubject() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("subject_key", "asub")
                .build();
        
        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .claim("roles", "role1,role2")
                .claim("asub", "Dr. Who")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(new FakeRestRequest(headers, new HashMap<String, String>()));
        Assert.assertNotNull(creds);
        Assert.assertEquals("Dr. Who", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }
    
    @Test
    public void testUrlParam() throws Exception {
        
        byte[] secretKey = new byte[]{1,2,3,4,5,6,7,8,9,10};
        
        Settings settings = Settings.builder()
                .put("signing_key", BaseEncoding.base64().encode(secretKey))
                .put("jwt_url_parameter", "abc")
                .build();
        
        String jwsToken = Jwts.builder()
                .setSubject("Leonard McCoy")
                .signWith(SignatureAlgorithm.HS512, secretKey).compact();
        
        HTTPJwtAuthenticator jwtAuth =new HTTPJwtAuthenticator(settings);
        Map<String, String> headers = new HashMap<String, String>();
        FakeRestRequest req = new FakeRestRequest(headers, new HashMap<String, String>());
        req.params().put("abc", jwsToken);
        
        AuthCredentials creds = jwtAuth.extractCredentials(req);
        Assert.assertNotNull(creds);
        Assert.assertEquals("Leonard McCoy", creds.getUsername());
        Assert.assertEquals(0, creds.getBackendRoles().size());
    }

}
