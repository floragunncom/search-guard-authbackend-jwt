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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKeys;
import org.junit.Assert;
import org.junit.Test;

public class SelfRefreshingKeySetTest {

	@Test
	public void basicTest() {
		SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(new MockKeySetProvider());

		JsonWebKey key1 = selfRefreshingKeySet.getKeyByKid("kid_a");
		Assert.assertEquals(TestJwks.OCT_1_K, key1.getProperty("k"));
		Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());

		JsonWebKey key2 = selfRefreshingKeySet.getKeyByKid("kid_b");
		Assert.assertEquals(TestJwks.OCT_2_K, key2.getProperty("k"));
		Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());

		JsonWebKey keyX = selfRefreshingKeySet.getKeyByKid("kid_X");
		Assert.assertNull(keyX);
		Assert.assertEquals(2, selfRefreshingKeySet.getRefreshCount());

	}

	@Test(timeout = 10000)
	public void twoThreadedTest() throws Exception {
		BlockingMockKeySetProvider provider = new BlockingMockKeySetProvider();

		final SelfRefreshingKeySet selfRefreshingKeySet = new SelfRefreshingKeySet(provider);

		ExecutorService executorService = Executors.newCachedThreadPool();

		Future<JsonWebKey> f1 = executorService.submit(() -> selfRefreshingKeySet.getKeyByKid("kid_a"));

		provider.waitForCalled();

		Future<JsonWebKey> f2 = executorService.submit(() -> selfRefreshingKeySet.getKeyByKid("kid_b"));

		while (selfRefreshingKeySet.getQueuedGetCount() == 0) {
			Thread.sleep(10);
		}

		provider.unblock();

		Assert.assertEquals(TestJwks.OCT_1_K, f1.get().getProperty("k"));
		Assert.assertEquals(TestJwks.OCT_2_K, f2.get().getProperty("k"));

		Assert.assertEquals(1, selfRefreshingKeySet.getRefreshCount());
		Assert.assertEquals(1, selfRefreshingKeySet.getQueuedGetCount());

	}

	static class MockKeySetProvider implements KeySetProvider {

		@Override
		public JsonWebKeys get() throws AuthenticatorUnavailableException {
			return TestJwks.OCT_1_2_3;
		}

	}

	static class BlockingMockKeySetProvider extends MockKeySetProvider {
		private boolean blocked = true;
		private boolean called = false;

		@Override
		public synchronized JsonWebKeys get() throws AuthenticatorUnavailableException {

			called = true;
			notifyAll();

			waitForUnblock();

			return super.get();
		}

		public synchronized void unblock() {
			blocked = false;
			notifyAll();
		}

		public synchronized void waitForCalled() throws InterruptedException {
			while (!called) {
				wait();
			}
		}

		private synchronized void waitForUnblock() {
			while (blocked) {
				try {
					wait();
				} catch (InterruptedException e) {
				}

			}
		}
	}
}
