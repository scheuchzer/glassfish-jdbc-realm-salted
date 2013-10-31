/*
Copyright 2013 Thomas Scheuchzer, java-adventures.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package com.ja.glassfish.auth.realm.jdbc;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Rule;
import org.junit.Test;

import com.ja.glassfish.auth.realm.jdbc.app.DummyServlet;
import com.ja.junit.rule.glassfish.GlassfishController;

/**
 * Tests the JDBCRealm against an embedded Glassfish instance.
 * 
 * @author Thomas Scheuchzer, www.java-adventures.com
 *
 */
public class JDBCRealmIT {

	@Rule
	public GlassfishController glassfish = new GlassfishController();

	public JDBCRealmIT() throws Exception {
		glassfish
				.setHttpPort(8642)
				.setLoginConf(
						new File(getClass().getClassLoader()
								.getResource("login.conf").toURI()))
				.createUserAndRoleTables()
				.createAuthRealm("testRealm", JDBCRealm.class);
	}

	@Test
	public void testLoginInValidUser() throws Exception {
		glassfish.addUser("test", "abc123", "test");
		deployDummyApp();

		HttpURLConnection httpCon = glassfish.executeHttpRequest("test/dummy",
				"test", "abc123");

		assertThat(httpCon.getResponseCode(), is(200));
		byte[] content = new byte[httpCon.getContentLength()];
		((InputStream) httpCon.getContent()).read(content);
		assertThat(new String(content), is("OK"));
	}

	@Test
	public void testLoginNoUsersExist() throws Exception {
		deployDummyApp();

		HttpURLConnection httpCon = glassfish.executeHttpRequest("test/dummy",
				"test", "abc123");

		assertThat(httpCon.getResponseCode(), is(401));
		glassfish.addUser("test", "abc123", "test");
	}

	@Test
	public void testLoginWrongPassword() throws Exception {
		glassfish.addUser("test", "abc123", "test");
		deployDummyApp();

		HttpURLConnection httpCon = glassfish.executeHttpRequest("test/dummy",
				"test", "wrongPassword");

		assertThat(httpCon.getResponseCode(), is(401));
	}

	private void deployDummyApp() {
		glassfish.deploy(ShrinkWrap.create(WebArchive.class, "test.war")
				.addPackage(DummyServlet.class.getPackage())
				.addAsWebInfResource("web.xml")
				.addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml"));
	}

}
