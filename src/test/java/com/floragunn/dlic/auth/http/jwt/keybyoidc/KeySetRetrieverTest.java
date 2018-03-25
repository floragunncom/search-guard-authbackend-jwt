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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.google.common.hash.Hashing;

public class KeySetRetrieverTest {
	protected static MockIpdServer mockIdpServer;

	@BeforeClass
	public static void setUp() throws Exception {
		mockIdpServer = new MockIpdServer();
	}

	@AfterClass
	public static void tearDown() {
		if (mockIdpServer != null) {
			try {
				mockIdpServer.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Test
	public void cacheTest() {
		KeySetRetriever keySetRetriever = new KeySetRetriever(mockIdpServer.getDiscoverUri(), null, true);

		keySetRetriever.get();

		Assert.assertEquals(1, keySetRetriever.getOidcCacheMisses());
		Assert.assertEquals(0, keySetRetriever.getOidcCacheHits());

		keySetRetriever.get();
		Assert.assertEquals(1, keySetRetriever.getOidcCacheMisses());
		Assert.assertEquals(1, keySetRetriever.getOidcCacheHits());
	}

	@Test
	public void clientCertTest() throws Exception {

		try (MockIpdServer sslMockIdpServer = new MockIpdServer(8084, true) {
			@Override
			protected void handleDiscoverRequest(HttpRequest request, HttpResponse response, HttpContext context)
					throws HttpException, IOException {

				MockIpdServer.SSLTestHttpServerConnection connection = (MockIpdServer.SSLTestHttpServerConnection) ((HttpCoreContext) context)
						.getConnection();

				X509Certificate peerCert = (X509Certificate) connection.getPeerCertificates()[0];

				try {
					String sha256Fingerprint = Hashing.sha256().hashBytes(peerCert.getEncoded()).toString();

					Assert.assertEquals("c81a111272028c5e670b96e56bc5660a23b103d7b7962d14122b2a9a021885a2",
							sha256Fingerprint);

				} catch (CertificateEncodingException e) {
					throw new RuntimeException(e);
				}

				super.handleDiscoverRequest(request, response, context);
			}
		}) {
			SSLContextBuilder sslContextBuilder = SSLContexts.custom();

			KeyStore trustStore = KeyStore.getInstance("JKS");
			InputStream trustStream = new FileInputStream(
					FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks").toFile());
			trustStore.load(trustStream, "changeit".toCharArray());

			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream keyStream = new FileInputStream(
					FileHelper.getAbsoluteFilePathFromClassPath("spock-keystore.jks").toFile());

			keyStore.load(keyStream, "changeit".toCharArray());

			sslContextBuilder.loadTrustMaterial(trustStore, null);

			sslContextBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray(), new PrivateKeyStrategy() {

				@Override
				public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
					return "spock";
				}
			});

			SettingsBasedSSLConfigurator.SSLConfig sslConfig = new SettingsBasedSSLConfigurator.SSLConfig(
					sslContextBuilder.build(), new String[] { "TLSv1.2", "TLSv1.1" }, null, null);

			KeySetRetriever keySetRetriever = new KeySetRetriever(sslMockIdpServer.getDiscoverUri(), sslConfig, false);

			keySetRetriever.get();

		}
	}
}
