import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import net.researchgate.release.GitAdapter.GitConfig
import net.researchgate.release.ReleaseExtension

// Top-level build file where you can add configuration options common to all sub-projects/modules.

plugins {
    id("com.github.johnrengelman.shadow") version "7.1.2"
    `java-library`
    `maven-publish`
    signing
    jacoco
    id("com.diffplug.spotless") version "6.1.2"
    id("com.github.ben-manes.versions") version "0.41.0"
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
    id("net.researchgate.release") version "2.8.1"
}

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        // NOTE: Do not place your application dependencies here; they belong
        // in the individual module build.gradle files
    }
}

repositories {
    mavenCentral()
}

group = "org.connectbot"

val gitHubUrl = "https://github.com/connectbot/sshlib"

apply(from = "$rootDir/config/quality.gradle.kts")

dependencies {
    implementation("com.jcraft:jzlib:1.1.3")
    implementation("org.connectbot:simplesocks:1.0.1")
    implementation("com.google.crypto.tink:tink:1.6.1")
    implementation("org.connectbot:jbcrypt:1.0.2")

    testImplementation("junit:junit:4.13.2")
    testImplementation("commons-io:commons-io:2.11.0")
    testImplementation("commons-codec:commons-codec:1.15")
    testImplementation("org.testcontainers:testcontainers:1.16.2")
    testImplementation("org.jetbrains:annotations:23.0.0")
    testImplementation("ch.qos.logback:logback-classic:1.2.10")
    testImplementation("org.hamcrest:hamcrest:2.2")
    testImplementation("org.mockito:mockito-core:4.2.0")
}

java {
    withJavadocJar()
    withSourcesJar()
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
    }
}

tasks.withType<ShadowJar> {
    classifier = null
    minimize()
}

tasks.withType<JacocoReport> {
    reports {
        xml.isEnabled = true
    }
}

fun ReleaseExtension.git(configure: GitConfig.() -> Unit) = (getProperty("git") as GitConfig).configure()
release {
    git {
        requireBranch = "main"
    }
}

spotless {
    java {
        target(
            fileTree(".") {
                include("**/*.java")
                exclude("**/build", "**/out")
            }
        )
        removeUnusedImports()
        trimTrailingWhitespace()

        indentWithTabs()
        replaceRegex("class-level javadoc indentation fix", "^\\*", " *")
        replaceRegex("method-level javadoc indentation fix", "\t\\*", "\t *")
    }

    kotlinGradle {
        target(
            fileTree(".") {
                include("**/*.gradle.kts")
                exclude("**/build", "**/out")
            }
        )
        ktlint()
    }

    format("xml") {
        target(
            fileTree(".") {
                include("config/**/*.xml", "sshlib/**/*.xml")
                exclude("**/build", "**/out")
            }
        )

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

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifact(tasks["shadowJar"])
            artifact(tasks["javadocJar"])
            artifact(tasks["sourcesJar"])

            pom {
                name.set("sshlib")
                description.set("The SSH library used by the ConnectBot app")
                url.set(gitHubUrl)
                licenses {
                    license {
                        name.set("BSD 3-Clause License")
                        url.set("https://opensource.org/licenses/BSD-3-Clause")
                    }
                }
                developers {
                    developer {
                        name.set("Kenny Root")
                        email.set("kenny@the-b.org")
                    }
                }
                scm {
                    connection.set("$gitHubUrl.git")
                    developerConnection.set("$gitHubUrl.git")
                    url.set(gitHubUrl)
                }
            }
        }
    }
}

signing {
    setRequired({
        gradle.taskGraph.hasTask("publish")
    })
    sign(publishing.publications["mavenJava"])
}

nexusPublishing {
    repositories {
        sonatype()
    }
}
