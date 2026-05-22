/*
 * Copyright 2019 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.dokka) apply false
    alias(libs.plugins.spotless)
    alias(libs.plugins.release)
    alias(libs.plugins.publish) apply false
    alias(libs.plugins.kover)
    alias(libs.plugins.cyclonedx)
    alias(libs.plugins.sonarqube)
}

allprojects {
    group = "org.connectbot.sshlib"

    repositories {
        google()
        mavenCentral()
    }
}

dependencies {
    kover(project(":protocol"))
    kover(project(":sshlib"))
}

sonar {
    properties {
        property("sonar.projectName", "ConnectBot SSH Library")
        property("sonar.projectKey", "connectbot_cbssh")
        property("sonar.organization", "connectbot")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.coverage.jacoco.xmlReportPaths", "build/reports/kover/report.xml")
        property("sonar.coverage.exclusions", "testapp/**")
        property("sonar.exclusions", "**/build/generated/**")
        property("sonar.issue.ignore.multicriteria", "cognitiveComplexityConnection,cognitiveComplexitySftp,cognitiveComplexityTransport")
        property("sonar.issue.ignore.multicriteria.cognitiveComplexityConnection.ruleKey", "kotlin:S3776")
        property(
            "sonar.issue.ignore.multicriteria.cognitiveComplexityConnection.resourceKey",
            "**/src/main/kotlin/org/connectbot/sshlib/client/SshConnection.kt",
        )
        property("sonar.issue.ignore.multicriteria.cognitiveComplexitySftp.ruleKey", "kotlin:S3776")
        property(
            "sonar.issue.ignore.multicriteria.cognitiveComplexitySftp.resourceKey",
            "**/src/main/kotlin/org/connectbot/sshlib/client/sftp/SftpDispatcher.kt",
        )
        property("sonar.issue.ignore.multicriteria.cognitiveComplexityTransport.ruleKey", "kotlin:S3776")
        property(
            "sonar.issue.ignore.multicriteria.cognitiveComplexityTransport.resourceKey",
            "**/src/main/kotlin/org/connectbot/sshlib/transport/KtorTcpTransport.kt",
        )
    }
}

spotless {
    ratchetFrom = "origin/main"

    kotlin {
        target("**/src/**/*.kt")
        ktlint("1.8.0")
        licenseHeaderFile("spotless/license-header.txt")
    }

    kotlinGradle {
        target("**/*.gradle.kts")
        ktlint("1.8.0")
    }

    yaml {
        target(".github/**/*.yml", ".github/**/*.yaml")
        trimTrailingWhitespace()
        endWithNewline()
    }

    format("xml") {
        target("**/*.xml")
        targetExclude("**/.idea/**/*.xml", "**/bin/**/*.xml", "**/build/**/*.xml", "**/.worktrees/**/*.xml")
        trimTrailingWhitespace()
        endWithNewline()
    }

    format("toml") {
        target("**/*.toml")
        trimTrailingWhitespace()
        endWithNewline()
    }

    format("misc") {
        target(listOf("**/*.md", "**/.gitignore", "**/.gitattributes", "**/.editorconfig"))
        trimTrailingWhitespace()
        endWithNewline()
    }
}
