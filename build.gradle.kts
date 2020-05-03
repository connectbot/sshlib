import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

// Top-level build file where you can add configuration options common to all sub-projects/modules.

plugins {
    `java-library`
    jacoco
    id("com.diffplug.gradle.spotless") version "3.26.1"
    id("com.github.ben-manes.versions") version "0.27.0"
    id("com.jfrog.artifactory") version "4.12.0"
    id("com.jfrog.bintray") version "1.8.4"
    id("net.researchgate.release") version "2.8.1"
}

buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        // NOTE: Do not place your application dependencies here; they belong
        // in the individual module build.gradle files
    }
}

repositories {
    jcenter()
}

apply(from = "$rootDir/publish.gradle")
apply(from = "$rootDir/config/quality.gradle.kts")

dependencies {
    implementation("com.jcraft:jzlib:1.1.3")
    implementation("org.connectbot:simplesocks:1.0.1")
    implementation("com.google.crypto.tink:tink:1.4.0-rc1")
    implementation("org.connectbot.jbcrypt:jbcrypt:1.0.0")

    testImplementation("junit:junit:4.12")
    testImplementation("commons-io:commons-io:2.6")
    testImplementation("commons-codec:commons-codec:1.13")
    testImplementation("org.testcontainers:testcontainers:1.12.4")
    testImplementation("ch.qos.logback:logback-classic:1.2.3")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<JacocoReport> {
    reports {
        xml.isEnabled = true
    }
}

spotless {
    java {
        target(fileTree(".") {
            include("**/*.java")
            exclude("**/build", "**/out")
        })
        removeUnusedImports()
        trimTrailingWhitespace()

        indentWithTabs()
        replaceRegex("class-level javadoc indentation fix", "^\\*", " *")
        replaceRegex("method-level javadoc indentation fix", "\t\\*", "\t *")
    }

    kotlinGradle {
        target(fileTree(".") {
            include("**/*.gradle.kts")
            exclude("**/build", "**/out")
        })
        ktlint()
    }

    format("xml") {
        target(fileTree(".") {
            include("config/**/*.xml", "sshlib/**/*.xml")
            exclude("**/build", "**/out")
        })

        eclipseWtp(EclipseWtpFormatterStep.XML).configFile("spotless.xml.prefs")
    }

    format("misc") {
        target("**/.gitignore")
        indentWithTabs()
        trimTrailingWhitespace()
        endWithNewline()
    }
}

tasks.named<DependencyUpdatesTask>("dependencyUpdates") {
    resolutionStrategy {
        componentSelection {
            all {
                val rejected = listOf("alpha", "beta", "rc", "cr", "m", "preview", "b", "ea")
                    .map { qualifier -> Regex("(?i).*[.-]$qualifier[.\\d-+]*") }
                    .any { it.matches(candidate.version) }
                if (rejected) {
                    reject("Release candidate")
                }
            }
        }
    }
    // optional parameters
    checkForGradleUpdate = true
    outputFormatter = "json"
    outputDir = "build/dependencyUpdates"
    reportfileName = "report"
}
