package com.trilead.ssh2;

import org.junit.rules.ExternalResource;
import org.slf4j.Logger;

public class SshLogger extends ExternalResource {
	private final Logger logger;

	private DebugLogger oldLogger;
	private boolean oldEnabled;

	SshLogger(Logger logger) {
		this.logger = logger;
	}

	@Override
	protected void before() throws Throwable {
		oldEnabled = com.trilead.ssh2.log.Logger.enabled;
		oldLogger = com.trilead.ssh2.log.Logger.logger;

		com.trilead.ssh2.log.Logger.enabled = true;
		com.trilead.ssh2.log.Logger.logger = (level, className, message) -> logger.info("[SSHLIB] " + message);
	}

	@Override
	protected void after() {
		com.trilead.ssh2.log.Logger.enabled = oldEnabled;
		com.trilead.ssh2.log.Logger.logger = oldLogger;
	}
}
