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
package com.ja.junit.rule.glassfish;

import static org.junit.Assert.fail;

import java.io.File;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Stack;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.glassfish.embeddable.CommandResult;
import org.glassfish.embeddable.CommandResult.ExitStatus;
import org.glassfish.embeddable.CommandRunner;
import org.glassfish.embeddable.Deployer;
import org.glassfish.embeddable.GlassFish;
import org.glassfish.embeddable.GlassFishException;
import org.glassfish.embeddable.GlassFishProperties;
import org.glassfish.embeddable.GlassFishRuntime;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ja.security.PasswordHash;
import com.sun.enterprise.security.auth.realm.Realm;

/**
 * A JUnit Rule that controlls an embedded Glassfish instance.
 * 
 * @author Thomas Scheuchzer, www.java-adventures.com
 *
 */
public class GlassfishController extends ExternalResource {
	private Logger log = LoggerFactory.getLogger(GlassfishController.class);
	private static GlassFishRuntime gfr;
	private static GlassFish gf;
	private Deployer deployer;
	private CommandRunner commandRunner;
	private TemporaryFolder tmpFolder = new TemporaryFolder();
	private Stack<CleanupCommand> cleanupStack = new Stack<>();
	private List<StartupCommand> startupCommands = new ArrayList<>();
	private File loginConf;
	private GlassFishProperties props = new GlassFishProperties();

	public GlassfishController() {
	}

	@Override
	protected void before() throws Throwable {
		tmpFolder.create();
		start();
	}

	public void start() {
		setupLoginConfig();
		try {
			if (gfr == null) {
				gfr = GlassFishRuntime.bootstrap();
				gf = gfr.newGlassFish(props);
				gf.start();
			}
			deployer = gf.getService(Deployer.class, null);
			commandRunner = gf.getCommandRunner();

			for (StartupCommand command : startupCommands) {
				try {
					command.execute();
				} catch (Exception e) {
					log.error("Startup failed. ", e);
					fail();
				}
			}
		} catch (GlassFishException e) {
			throw new RuntimeException("Startup failed", e);
		}
	}

	private void setupLoginConfig() {
		if (loginConf == null) {
			return;
		}
		log.info("Login-Config={}", loginConf.getAbsolutePath());
		final String loginConfProperty = "java.security.auth.login.config";
		final String loginConfBackup = System.getProperty(loginConfProperty);
		System.setProperty(loginConfProperty, loginConf.getAbsolutePath());
		cleanupStack.add(new CleanupCommand() {

			@Override
			public void execute() {
				System.setProperty(loginConfProperty, loginConfBackup);

			}
		});
	}

	public void stop() {
		try {
			gf.stop();
			gf.dispose();
			gfr.shutdown();
		} catch (Exception e) {
			throw new RuntimeException("Shutdown failed", e);
		}
		log.info("GF has been shutdown");
	}

	@Override
	protected void after() {
		cleanup();
		// stop();
		tmpFolder.delete();
	}

	public void cleanup() {
		log.info("Executing {} cleanup commands.", cleanupStack.size());
		while (!cleanupStack.isEmpty()) {
			try {
				cleanupStack.pop().execute();
			} catch (Exception e) {
				log.info("CleanupCommand failed");
			}
		}
	}

	public void deploy(final Archive<?> archive) {
		try {
			ZipExporter exporter = archive.as(ZipExporter.class);
			File file = tmpFolder.newFile(archive.getName());
			exporter.exportTo(file, true);
			final String appName = deployer.deploy(file);
			log.info("Application {} deployed as {}", archive.getName(),
					appName);
			register(new CleanupCommand() {

				@Override
				public void execute() {
					undeploy(appName);

				}
			});
		} catch (Exception e) {
			throw new RuntimeException("Deployment failed", e);
		}
	}

	public void undeploy(final String appName) {
		log.info("Undeploy {}", appName);
		try {
			deployer.undeploy(appName);
		} catch (GlassFishException e) {
			throw new RuntimeException("Undeploy failed");
		}
	}

	public void createConnectorConnectionPool(final String raname,
			final Class<?> connectionDefinition, final String poolName,
			final Properties connectionConfigProperties) {
		log.info("Create connection pool");
		commandRunner.run("create-connector-connection-pool", "--raname="
				+ raname,
				"--connectiondefinition=" + connectionDefinition.getName(),
				poolName);
		if (connectionConfigProperties != null) {
			for (Map.Entry<Object, Object> entry : connectionConfigProperties
					.entrySet()) {
				createConnectorConnectionPoolProperty(poolName,
						(String) entry.getKey(), (String) entry.getValue());
			}
		}
		register(new CleanupCommand() {

			@Override
			public void execute() {
				deleteConnectorConnectionPool(poolName);

			}
		});
	}

	private void register(CleanupCommand cleanupCommand) {
		cleanupStack.push(cleanupCommand);
	}

	public void createConnectorConnectionPoolProperty(String poolName,
			String key, String value) {
		log.info("Create connection pool property");
		String cmd = String.format(
				"domain.resources.connector-connection-pool.%s.property.%s=%s",
				poolName, key, value);
		commandRunner.run("set", cmd);

	}

	public void createConnectorResource(final String poolName,
			final String jndiName) {
		log.info("Create connection resource");
		commandRunner.run("create-connector-resource",
				"--poolname=" + poolName, jndiName);
		register(new CleanupCommand() {

			@Override
			public void execute() {
				deleteConnectorResource(jndiName);

			}
		});
	}

	public void deleteConnectorResource(String jndiName) {
		log.info("delete connetor resource");
		commandRunner.run("delete-connector-resource", jndiName);
	}

	public void deleteConnectorConnectionPool(String poolName) {
		log.info("delete connector connection pool");
		commandRunner.run("delete-connector-connection-pool", poolName);
	}

	@SuppressWarnings("unchecked")
	public <T> T lookup(String jndiName) {
		try {
			return (T) new InitialContext().lookup(jndiName);
		} catch (NamingException e) {
			throw new RuntimeException("Lookup failed", e);
		}
	}

	public GlassfishController setLoginConf(File loginConf) {
		this.loginConf = loginConf;
		return this;
	}

	public GlassfishController setHttpPort(int port) {
		props.setPort("http-listener", port);
		return this;
	}

	abstract public static class CleanupCommand {
		abstract public void execute() throws Exception;
	}

	abstract public static class StartupCommand {
		abstract public void execute() throws Exception;
	}

	public GlassfishController createUserAndRoleTables() {
		startupCommands.add(new StartupCommand() {

			@Override
			public void execute() throws Exception {

				DataSource dataSource = (DataSource) new InitialContext()
						.lookup("jdbc/__default");
				String createUserTable = "CREATE TABLE users (username varchar(255) NOT NULL, password varchar(255) DEFAULT NULL,PRIMARY KEY (username))";
				String createGroupTable = "CREATE TABLE groups (username varchar(255) DEFAULT NULL,groupname varchar(255) DEFAULT NULL)";
				try (Connection con = dataSource.getConnection()) {
					log.info("Create users table={}", createUserTable);
					con.prepareStatement(createUserTable).execute();
					log.info("Create group tabls={}", createGroupTable);
					con.prepareStatement(createGroupTable).execute();
					con.commit();
				}
			}
		});
		cleanupStack.add(new CleanupCommand() {

			@Override
			public void execute() throws Exception {
				DataSource dataSource = (DataSource) new InitialContext()
						.lookup("jdbc/__default");
				try (Connection con = dataSource.getConnection()) {
					Statement s = con.createStatement();
					s.execute("SELECT * from users");
					log.info("Resetting users and groups tables.");
					s.execute("DROP TABLE groups");
					s.execute("DROP TABLE users");
					con.commit();
				} catch (Exception e) {
					// ignore
				}
			}
		});
		return this;
	}

	public GlassfishController createAuthRealm(final String realmName,
			final Class<? extends Realm> realmClass) throws GlassFishException {
		startupCommands.add(new StartupCommand() {

			@Override
			public void execute() throws Exception {

				log.info("Create auth realm");
				CommandResult result = commandRunner.run(
						"create-auth-realm",
						"--classname",
						realmClass.getName(),
						"--property",
						"jaas-context=jdbcSaltRealm:datasource-jndi=jdbc/__default:user-table=users:group-table=groups:user-name-column=username:password-column=password:group-name-column=groupname",
						realmName);
				log.info("result={}", result.getExitStatus());
				if (ExitStatus.FAILURE.equals(result.getExitStatus())) {
					log.error("command failed", result.getFailureCause());
					fail();
				}
				listAuthRealms();
			}
		});

		cleanupStack.add(new CleanupCommand() {

			@Override
			public void execute() throws Exception {
				log.info("delete auth realm");
				CommandResult result = commandRunner.run("delete-auth-realm",
						realmName);
				log.info("result={}", result.getExitStatus());
				if (ExitStatus.FAILURE.equals(result.getExitStatus())) {
					log.error("command failed", result.getFailureCause());
					fail();
				}

			}
		});
		return this;
	}

	public void addUser(final String username, final String password,
			final String... roles) {
		try {
			DataSource dataSource = (DataSource) new InitialContext()
					.lookup("jdbc/__default");
			try (Connection con = dataSource.getConnection()) {
				String hash = new PasswordHash().createHash("abc123");
				PreparedStatement ps = con
						.prepareStatement("insert into users values(?, ?)");
				ps.setString(1, username);
				ps.setString(2, hash);
				ps.execute();

				for (String role : roles) {
					ps = con.prepareStatement("insert into groups values(?, ?)");
					ps.setString(1, username);
					ps.setString(2, role);
					ps.execute();
				}
				con.commit();
			}
			log.info("User {} created", username);
		} catch (Exception e) {
			log.error("Add user failed", e);
			fail();
		}
		cleanupStack.add(new CleanupCommand() {

			@Override
			public void execute() throws Exception {
				log.info("removing user {}", username);
				DataSource dataSource = (DataSource) new InitialContext()
						.lookup("jdbc/__default");
				try (Connection con = dataSource.getConnection()) {
					PreparedStatement ps = con
							.prepareStatement("delete from users where username=?");
					ps.setString(1, username);
					ps.execute();
					ps = con.prepareStatement("delete from groups where username=?");
					ps.setString(1, username);
					ps.execute();
				}
			}
		});
	}

	public void listAuthRealms() throws GlassFishException {
		log.info("list auth realm");
		CommandResult result = commandRunner.run("list-auth-realms");
		log.info("auth-realms={}", result.getOutput());
	}

	public HttpURLConnection executeHttpRequest(String path) {
		return executeHttpRequest(path, null, null);
	}

	public HttpURLConnection executeHttpRequest(final String path,
			final String username, final String password) {
		if (username != null) {
			log.info("Setting up username and password");
			Authenticator.setDefault(new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(username, password
							.toCharArray());
				}
			});
		}
		String url = String.format("http://localhost:%s/%s",
				props.getPort("http-listener"), path);
		log.info("Calling url={}", url);
		HttpURLConnection con = null;
		try {
			con = (HttpURLConnection) new URL(url).openConnection();
			log.info("Response={}", con.getResponseMessage());
		} catch (Exception e) {
			log.error("HTTP request failed.", e);
			fail();
		} finally {
			Authenticator.setDefault(null);
		}
		return con;
	}
}
