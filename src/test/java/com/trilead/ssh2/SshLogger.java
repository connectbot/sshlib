package com.trilead.ssh2;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;

public class SshLogger implements BeforeEachCallback, AfterEachCallback {
	private final Logger logger;

	private DebugLogger oldLogger;
	private boolean oldEnabled;

	SshLogger(Logger logger) {
		this.logger = logger;
	}

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		oldEnabled = com.trilead.ssh2.log.Logger.enabled;
		oldLogger = com.trilead.ssh2.log.Logger.logger;

		com.trilead.ssh2.log.Logger.enabled = true;
		com.trilead.ssh2.log.Logger.logger = (level, className, message) -> logger.info("[SSHLIB] " + message);
	}

	@Override
	public void afterEach(ExtensionContext context) throws Exception {
		com.trilead.ssh2.log.Logger.enabled = oldEnabled;
		com.trilead.ssh2.log.Logger.logger = oldLogger;
	}
}
