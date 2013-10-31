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

import java.util.Arrays;
import java.util.logging.Level;

import com.sun.enterprise.security.BasePasswordLoginModule;
import com.sun.enterprise.security.auth.login.common.LoginException;

/**
 * Login module that delegates to the {@link JDBCRealm}.
 * @author Thomas Scheuchzer, 
 */
public class JDBCLoginModule extends BasePasswordLoginModule {

	/**
	 * Perform JDBC authentication. Delegates to JDBCRealm.
	 * 
	 * @throws LoginException
	 *             If login fails (JAAS login() behavior).
	 */
	@Override
	protected void authenticateUser()
			throws javax.security.auth.login.LoginException {
		if (!(getCurrentRealm() instanceof JDBCRealm)) {
			String msg = sm.getString("jdbclm.badrealm");
			throw new LoginException(msg);
		}

		final JDBCRealm jdbcRealm = (JDBCRealm) getCurrentRealm();

		final String username = getUsername();
		if ((username == null) || (username.length() == 0)) {
			String msg = sm.getString("jdbclm.nulluser");
			throw new LoginException(msg);
		}

		String[] grpList = jdbcRealm.authenticate(username, getPasswordChar());

		if (grpList == null) { // JAAS behavior
			String msg = sm.getString("jdbclm.loginfail", username);
			throw new LoginException(msg);
		}

		if (_logger.isLoggable(Level.FINEST)) {
			_logger.finest("JDBC login succeeded for: " + username + " groups:"
					+ Arrays.toString(grpList));
		}

		commitUserAuthentication(grpList);

	}
}
