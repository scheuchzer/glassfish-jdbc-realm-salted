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

import static com.ja.junit.rule.glassfish.ConfigObject.defaultUserAndGroupTables;
import static com.ja.junit.rule.glassfish.ConfigObject.deployment;
import static com.ja.junit.rule.glassfish.ConfigObject.jdbcAuthRealm;
import static com.ja.junit.rule.glassfish.ConfigObject.user;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.net.URISyntaxException;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Rule;
import org.junit.Test;

import com.ja.glassfish.auth.realm.jdbc.app.DummyServlet;
import com.ja.junit.rule.glassfish.GlassfishController;
import com.ja.junit.rule.glassfish.GlassfishPreStartConfigurator;
import com.ja.junit.rule.glassfish.Response;

/**
 * Tests the JDBCRealm against an embedded Glassfish instance.
 * 
 * @author Thomas Scheuchzer, www.java-adventures.com
 * 
 */
public class JDBCRealmIT {

	private final GlassfishPreStartConfigurator startCfg = new GlassfishPreStartConfigurator();

	@Rule
	public GlassfishController glassfish = new GlassfishController(startCfg)
			.create(defaultUserAndGroupTables())
			.create(jdbcAuthRealm("testRealm", "jdbcSaltRealm", JDBCRealm.class));

	public JDBCRealmIT() throws URISyntaxException {
		startCfg.setHttpPort(8642).setLoginConf(
				new File(getClass().getClassLoader().getResource("login.conf")
						.toURI()));
	}

	@Test
	public void testLoginValidUser() throws Exception {
		glassfish.create(user("test", "abc123", "test"));
		deployDummyApp();

		Response response = glassfish.executeHttpRequest("/test/dummy", "test",
				"abc123");

		assertThat(response.getStatus(), is(200));
		assertThat(response.getContentAsString(), is("OK"));
	}

	@Test
	public void testLoginWrongPassword() throws Exception {
		glassfish.create(user("test", "abc123", "test"));
		deployDummyApp();

		Response response = glassfish.executeHttpRequest("/test/dummy", "test",
				"wrongPassword");

		assertThat(response.getStatus(), is(401));
	}

	@Test
	public void testLoginNoUsersExist() throws Exception {
		deployDummyApp();

		Response response = glassfish.executeHttpRequest("/test/dummy", "test",
				"abc123");

		assertThat(response.getStatus(), is(401));
	}

	private void deployDummyApp() {
		deployDummyApp("test.war");
	}

	private void deployDummyApp(String warName) {
		glassfish.create(deployment(ShrinkWrap
				.create(WebArchive.class, warName)
				.addPackage(DummyServlet.class.getPackage())
				.addAsWebInfResource("web.xml")
				.addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")));
	}
}
