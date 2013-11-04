/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 1997-2013 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
/*
 * Portions Copyright 2013 Thomas Scheuchzer
 * - Original class: com.sun.enterprise.security.ee.auth.realm.jdbc.JDBCRealm
 * - Replaced digest code with PasswordHash class
 */

package com.ja.glassfish.auth.realm.jdbc;

import static com.ja.glassfish.auth.realm.jdbc.Params.CHARSET;
import static com.ja.glassfish.auth.realm.jdbc.Params.DATASOURCE_JNDI;
import static com.ja.glassfish.auth.realm.jdbc.Params.DB_PASSWORD;
import static com.ja.glassfish.auth.realm.jdbc.Params.DB_USER;
import static com.ja.glassfish.auth.realm.jdbc.Params.GROUP_NAME_COLUMN;
import static com.ja.glassfish.auth.realm.jdbc.Params.GROUP_TABLE;
import static com.ja.glassfish.auth.realm.jdbc.Params.GROUP_TABLE_USER_NAME_COLUMN;
import static com.ja.glassfish.auth.realm.jdbc.Params.PASSWORD_COLUMN;
import static com.ja.glassfish.auth.realm.jdbc.Params.USER_NAME_COLUMN;
import static com.ja.glassfish.auth.realm.jdbc.Params.USER_TABLE;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import org.glassfish.hk2.api.ActiveDescriptor;
import org.glassfish.hk2.utilities.BuilderHelper;
import org.jvnet.hk2.annotations.Service;

import com.sun.appserv.connectors.internal.api.ConnectorRuntime;
import com.sun.enterprise.security.BaseRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.realm.Realm;
import com.sun.enterprise.security.common.Util;
import com.sun.logging.LogDomains;

/**
 * Realm for supporting JDBC authentication secured with password hash and salt.
 * 
 * <P>
 * The JDBC realm needs the following properties in its configuration:
 * <ul>
 * <li>jaas-context : JAAS context name used to access LoginModule for
 * authentication (for example JDBCRealm).
 * <li>datasource-jndi : jndi name of datasource
 * <li>db-user : user name to access the datasource
 * <li>db-password : password to access the datasource. The password is of the
 * form {pbkdf2-iterations}:{salt}:{hash}
 * <li>user-table: table containing user name and password
 * <li>group-table: table containing user name and group name
 * <li>user-name-column: column corresponding to user name in user-table and
 * group-table
 * <li>password-column : column corresponding to password in user-table
 * <li>group-name-column : column corresponding to group in group-table
 * </ul>
 * Password hashing and salting options:
 * <ul>
 * <li>pbkdf2-algorithm : Default=PBKDF2WithHmacSHA1</li>
 * <li>pbkdf2-iterations : Default=20000</li>
 * <li>secure-random-algorithm : Default=SHA1PRNG</li>
 * <li>hash-byte-size : Default=24</li>
 * <li>salt-byte-size : Default=24</li>
 * </ul>
 * 
 */
@Service
public final class JDBCRealm extends IASRealm {
	protected static final Logger LOG = LogDomains.getLogger(Realm.class,
			LogDomains.SECURITY_LOGGER);

	public static final String AUTH_TYPE = "jdbc-with-salt";
	private Map<String, Vector<String>> groupCache = new HashMap<>();
	private String passwordQuery = null;
	private String groupQuery = null;
	private PasswordHash passwordHash = new PasswordHash();

	private ActiveDescriptor<ConnectorRuntime> cr;

	/**
	 * Initialize a realm with some properties. This can be used when
	 * instantiating realms from their descriptions. This method may only be
	 * called a single time.
	 * 
	 * @param props
	 *            Initialization parameters used by this realm.
	 * @exception BadRealmException
	 *                If the configuration parameters identify a corrupt realm.
	 * @exception NoSuchRealmException
	 *                If the configuration parameters specify a realm which
	 *                doesn't exist.
	 */
	@Override
	@SuppressWarnings("unchecked")
	public synchronized void init(Properties props) throws BadRealmException,
			NoSuchRealmException {
		super.init(props);
		passwordHash.configure(props);

		String jaasCtx = props.getProperty(BaseRealm.JAAS_CONTEXT_PARAM);
		String dbUser = props.getProperty(DB_USER);
		String dbPassword = props.getProperty(DB_PASSWORD);
		String dsJndi = props.getProperty(DATASOURCE_JNDI);
		String charset = props.getProperty(CHARSET);
		String userTable = props.getProperty(USER_TABLE);
		String userNameColumn = props.getProperty(USER_NAME_COLUMN);
		String passwordColumn = props.getProperty(PASSWORD_COLUMN);
		String groupTable = props.getProperty(GROUP_TABLE);
		String groupNameColumn = props.getProperty(GROUP_NAME_COLUMN);
		String groupTableUserNameColumn = props.getProperty(
				GROUP_TABLE_USER_NAME_COLUMN, userNameColumn);
		cr = (ActiveDescriptor<ConnectorRuntime>) Util.getDefaultHabitat()
				.getBestDescriptor(
						BuilderHelper
								.createContractFilter(ConnectorRuntime.class
										.getName()));
		checkPropertySet(jaasCtx, JAAS_CONTEXT_PARAM);
		checkPropertySet(dsJndi, DATASOURCE_JNDI);
		checkPropertySet(userTable, USER_TABLE);
		checkPropertySet(groupTable, GROUP_TABLE);
		checkPropertySet(userNameColumn, USER_NAME_COLUMN);
		checkPropertySet(passwordColumn, PASSWORD_COLUMN);
		checkPropertySet(groupNameColumn, GROUP_NAME_COLUMN);

		passwordQuery = String.format("SELECT %s FROM %s WHERE %s = ?", passwordColumn, userTable, userNameColumn);

		groupQuery = String.format("SELECT %s FROM %s WHERE %s = ?", groupNameColumn, groupTable, groupTableUserNameColumn);

		this.setProperty(BaseRealm.JAAS_CONTEXT_PARAM, jaasCtx);
		if (dbUser != null && dbPassword != null) {
			this.setProperty(DB_USER, dbUser);
			this.setProperty(DB_PASSWORD, dbPassword);
		}
		this.setProperty(DATASOURCE_JNDI, dsJndi);
		if (charset != null) {
			this.setProperty(CHARSET, charset);
		}

		if (LOG.isLoggable(Level.FINEST)) {
			LOG.finest(getClass().getSimpleName() + ": "
					+ BaseRealm.JAAS_CONTEXT_PARAM + "= " + jaasCtx + ", "
					+ DATASOURCE_JNDI + " = " + dsJndi + ", " + DB_USER + " = "
					+ dbUser + ", " + CHARSET + " = " + charset + ", "
					+ passwordHash);
		}

	}

	private void checkPropertySet(String paramValue, String paramName)
			throws BadRealmException {
		if (paramValue == null) {
			String msg = sm.getString("realm.missingprop", paramName,
					"JDBCRealm");
			throw new BadRealmException(msg);
		}
	}

	@Override
	public String getAuthType() {
		return AUTH_TYPE;
	}

	/**
	 * Returns the name of all the groups that this user belongs to. It loads
	 * the result from groupCache first. This is called from web path group
	 * verification, though it should not be.
	 * 
	 * @param username
	 *            Name of the user in this realm whose group listing is needed.
	 * @return Enumeration of group names (strings).
	 * @exception InvalidOperationException
	 *                thrown if the realm does not support this operation - e.g.
	 *                Certificate realm does not support this operation.
	 */
	@Override
	public Enumeration<String> getGroupNames(String username)
			throws InvalidOperationException, NoSuchUserException {
		Vector<String> vector = groupCache.get(username);
		if (vector == null) {
			String[] grps = findGroups(username);
			setGroupNames(username, grps);
			vector = groupCache.get(username);
		}
		return vector.elements();
	}

	private void setGroupNames(String username, String[] groups) {
		Vector<String> v = new Vector<>();
		for (String group : groups) {
			v.add(group);
		}

		synchronized (this) {
			groupCache.put(username, v);
		}
	}

	/**
	 * Invoke the native authentication call.
	 * 
	 * @param username
	 *            User to authenticate.
	 * @param password
	 *            Given password.
	 * @returns true of false, indicating authentication status.
	 * 
	 */
	public String[] authenticate(String username, char[] password) {
		String[] groups = null;
		if (isUserValid(username, password)) {
			groups = findGroups(username);
			groups = addAssignGroups(groups);
			setGroupNames(username, groups);
		}
		return groups;
	}

	private String getPasswordHash(String username) {
		try (Connection connection = getConnection();
				PreparedStatement statement = connection
						.prepareStatement(passwordQuery)) {
			statement.setString(1, username);
			try (ResultSet rs = statement.executeQuery()) {
				if (rs.next()) {
					return rs.getString(1);
				}
			}
		} catch (Exception ex) {
			LOG.log(Level.SEVERE, "jdbcrealm.invaliduser", username);
			LOG.log(Level.SEVERE, null, ex);
		}
		return null;
	}

	private boolean isUserValid(String user, char[] password) {
		boolean valid = false;

		try {
			String correctHash = getPasswordHash(user);
			valid = passwordHash.validatePassword(password, correctHash);
		} catch (Exception ex) {
			LOG.log(Level.SEVERE, "jdbcrealm.invaliduser", user);
			if (LOG.isLoggable(Level.FINE)) {
				LOG.log(Level.FINE, "Cannot validate user", ex);
			}
		}
		return valid;
	}

	private String[] findGroups(String user) {
		ResultSet rs = null;
		try (Connection connection = getConnection();
				PreparedStatement statement = connection
						.prepareStatement(groupQuery)) {
			statement.setString(1, user);
			rs = statement.executeQuery();
			return toArrayAndClose(rs, 1);
		} catch (Exception ex) {
			LOG.log(Level.SEVERE, "jdbcrealm.grouperror", user);
			LOG.log(Level.SEVERE, "Cannot load group", ex);
			return null;
		}
	}

	private String[] toArrayAndClose(ResultSet resultSet, int columnNr)
			throws SQLException {
		try (ResultSet rs = resultSet) {
			final List<String> result = new ArrayList<String>();
			while (rs.next()) {
				result.add(rs.getString(columnNr));
			}
			final String[] groupArray = new String[result.size()];
			return result.toArray(groupArray);
		}
	}

	/**
	 * Return a connection from the properties configured
	 * 
	 * @return a connection
	 */
	private Connection getConnection() throws LoginException {

		final String dsJndi = this.getProperty(DATASOURCE_JNDI);
		final String dbUser = this.getProperty(DB_USER);
		final String dbPassword = this.getProperty(DB_PASSWORD);
		try {
			ConnectorRuntime connectorRuntime = Util.getDefaultHabitat()
					.getServiceHandle(cr).getService();
			final DataSource dataSource = (DataSource) connectorRuntime
					.lookupNonTxResource(dsJndi, false);
			Connection connection = null;
			if (dbUser != null && dbPassword != null) {
				connection = dataSource.getConnection(dbUser, dbPassword);
			} else {
				connection = dataSource.getConnection();
			}
			return connection;
		} catch (Exception ex) {
			String msg = sm.getString("jdbcrealm.cantconnect", dsJndi, dbUser);
			LoginException loginEx = new LoginException(msg);
			loginEx.initCause(ex);
			throw loginEx;
		}
	}
}