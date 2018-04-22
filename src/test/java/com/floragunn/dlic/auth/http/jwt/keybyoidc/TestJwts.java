/*
 * Copyright 2016-2018 by floragunn GmbH - All rights reserved
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

package com.floragunn.dlic.auth.http.jwt.keybyoidc;

import java.util.Set;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.util.Strings;

import com.google.common.collect.ImmutableSet;

class TestJwts {
	static final String ROLES_CLAIM = "roles";
	static final Set<String> TEST_ROLES = ImmutableSet.of("role1", "role2");
	static final String TEST_ROLES_STRING = Strings.join(TEST_ROLES, ',');

	static final String TEST_AUDIENCE = "TestAudience";

	static final String MCCOY_SUBJECT = "Leonard McCoy";

	static final JwtToken MC_COY = create(MCCOY_SUBJECT, TEST_AUDIENCE, ROLES_CLAIM, TEST_ROLES_STRING);

	static final JwtToken MC_COY_EXPIRED = create(MCCOY_SUBJECT, TEST_AUDIENCE, ROLES_CLAIM, TEST_ROLES_STRING,
			JwtConstants.CLAIM_EXPIRY, 10);

	static final String MC_COY_SIGNED_OCT_1 = createSigned(MC_COY, TestJwk.OCT_1);

	static final String MC_COY_SIGNED_RSA_1 = createSigned(MC_COY, TestJwk.RSA_1);

	static final String MC_COY_SIGNED_RSA_X = createSigned(MC_COY, TestJwk.RSA_X);

	static final String MC_COY_EXPIRED_SIGNED_OCT_1 = createSigned(MC_COY_EXPIRED, TestJwk.OCT_1);

	static class NoKid {
		static final String MC_COY_SIGNED_RSA_1 = createSignedWithoutKeyId(MC_COY, TestJwk.RSA_1);
		static final String MC_COY_SIGNED_RSA_2 = createSignedWithoutKeyId(MC_COY, TestJwk.RSA_2);
		static final String MC_COY_SIGNED_RSA_X = createSignedWithoutKeyId(MC_COY, TestJwk.RSA_X);
	}
	
	static JwtToken create(String subject, String audience, Object... moreClaims) {
		JwtClaims claims = new JwtClaims();

		claims.setSubject(subject);
		claims.setAudience(audience);

		if (moreClaims != null) {
			for (int i = 0; i < moreClaims.length; i += 2) {
				claims.setClaim(String.valueOf(moreClaims[i]), moreClaims[i + 1]);
			}
		}

		JwtToken result = new JwtToken(claims);

		return result;
	}

	static String createSigned(JwtToken baseJwt, JsonWebKey jwk) {
		JwsHeaders jwsHeaders = new JwsHeaders();
		JwtToken signedToken = new JwtToken(jwsHeaders, baseJwt.getClaims());

		jwsHeaders.setKeyId(jwk.getKeyId());

		return new JoseJwtProducer().processJwt(signedToken, null, JwsUtils.getSignatureProvider(jwk));
	}
	
	static String createSignedWithoutKeyId(JwtToken baseJwt, JsonWebKey jwk) {
		JwsHeaders jwsHeaders = new JwsHeaders();
		JwtToken signedToken = new JwtToken(jwsHeaders, baseJwt.getClaims());

		return new JoseJwtProducer().processJwt(signedToken, null, JwsUtils.getSignatureProvider(jwk));
	}
}
