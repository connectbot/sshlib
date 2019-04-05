import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

// Top-level build file where you can add configuration options common to all sub-projects/modules.

plugins {
    id("com.github.ben-manes.versions") version "0.21.0"
    id("com.diffplug.gradle.spotless") version "3.21.1"
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

allprojects {
    repositories {
        jcenter()
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
