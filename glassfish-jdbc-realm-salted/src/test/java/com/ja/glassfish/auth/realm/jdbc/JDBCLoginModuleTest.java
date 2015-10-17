package com.ja.glassfish.auth.realm.jdbc;

import static com.ja.junit.rule.glassfish.ConfigObject.defaultUserAndGroupTables;
import static com.ja.junit.rule.glassfish.ConfigObject.jdbcAuthRealm;
import static com.ja.junit.rule.glassfish.ConfigObject.user;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.apache.http.auth.BasicUserPrincipal;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ja.junit.rule.glassfish.GlassfishController;
import com.ja.junit.rule.glassfish.GlassfishPreStartConfigurator;
import com.sun.enterprise.security.auth.login.common.LoginException;
import com.sun.enterprise.security.auth.login.common.PasswordCredential;

@RunWith(MockitoJUnitRunner.class)
public class JDBCLoginModuleTest {

	private final GlassfishPreStartConfigurator startCfg = new GlassfishPreStartConfigurator();
	@Mock
	private CallbackHandler callbackHandler;
	@Rule
	public GlassfishController glassfish = new GlassfishController(startCfg)
			.create(defaultUserAndGroupTables())
			.create(jdbcAuthRealm(
					"dummyJdbcRealm",
					"dummy",
					com.sun.enterprise.security.auth.realm.jdbc.JDBCRealm.class))
			.create(jdbcAuthRealm("jdbcRealm", "jdbc", JDBCRealm.class));
	@Rule
	public ExpectedException expectedException = ExpectedException.none();

	@Test
	public void testLoginWrongRealmForLoginModule() throws Exception {
		Principal principal = new BasicUserPrincipal("foo");
		PasswordCredential cred = new PasswordCredential("foo",
				"bar".toCharArray(), "dummyJdbcRealm");
		Subject subject = new Subject(true, new HashSet<>(
				Arrays.asList(principal)), new HashSet<>(), new HashSet<>(
				Arrays.asList(cred)));
		JDBCLoginModule module = new JDBCLoginModule();
		module.initialize(subject, callbackHandler, new HashMap<>(),
				new HashMap<>());

		expectedException.expect(LoginException.class);
		expectedException.expectMessage("JDBCLoginModule requires JDBCRealm");
		module.login();
	}

	@Test
	public void testLoginNullUser() throws Exception {
		expectedException.expect(LoginException.class);
		expectedException.expectMessage("Login failed for null user");
		doLogin("foo", null, "bar");
	}

	@Test
	public void testLoginEmptyUser() throws Exception {
		expectedException.expect(LoginException.class);
		expectedException.expectMessage("Login failed for null user");
		doLogin("foo", "", "bar");
	}

	@Test
	public void testLoginUserDoesNotExist() throws Exception {
		expectedException.expect(LoginException.class);
		expectedException.expectMessage("Failed jdbc login for foo");
		doLogin("foo", "foo", "bar");
	}

	@Test
	public void testLoginUserValid() throws Exception {
		glassfish.create(user("foo", "bar", "test"));
		doLogin("foo", "foo", "bar");
	}

	public boolean doLogin(String principalName, String userName,
			String password) throws Exception {
		Principal principal = new BasicUserPrincipal(principalName);
		PasswordCredential cred = new PasswordCredential(userName,
				password.toCharArray(), "jdbcRealm");
		Subject subject = new Subject(true, new HashSet<>(
				Arrays.asList(principal)), new HashSet<>(), new HashSet<>(
				Arrays.asList(cred)));
		JDBCLoginModule module = new JDBCLoginModule();
		module.initialize(subject, callbackHandler, new HashMap<>(),
				new HashMap<>());

		return module.login();
	}
}
