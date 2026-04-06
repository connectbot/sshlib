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

import com.vanniktech.maven.publish.DeploymentValidation
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.spotless)
    alias(libs.plugins.publish)
    alias(libs.plugins.dokka)
    alias(libs.plugins.metalava)
    alias(libs.plugins.kover)
    `java-library`
}

dependencies {
    // Public API dependencies
    api(libs.kotlinx.coroutines.core)

    // Internal dependencies
    implementation(project(":protocol"))
    implementation(kotlin("stdlib"))
    implementation(libs.kstatemachine)
    implementation(libs.ktor.network)
    implementation(libs.slf4j.api)
    implementation(libs.tink)
    implementation(libs.kyber)
    implementation(libs.jbcrypt)

    // Unit tests
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.mockk)

    // Integration test dependencies
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.testcontainers)
    testImplementation(libs.logback.classic)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.test {
    useJUnitPlatform()
}

java {
    withSourcesJar()
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

spotless {
    kotlinGradle {
        target(
            fileTree(".") {
                include("**/*.gradle.kts")
                exclude("**/build", "**/out")
            },
        )
        ktlint()
    }

    kotlin {
        ktlint("1.8.0")
            .editorConfigOverride(
                mapOf(
                    "ij_kotlin_imports_layout" to "*,java.**,javax.**,kotlin.**,^",
                    "ij_kotlin_allow_trailing_comma" to "true",
                    "ktlint_code_style" to "android_studio",
                    "ktlint_function_naming_ignore_when_annotated_with" to "Composable",
                    "ktlint_standard_property-naming" to "disabled",
                    "ktlint_standard_backing-property-naming" to "disabled",
                    "ktlint_standard_filename" to "disabled",
                    "ktlint_standard_discouraged-comment-location" to "disabled",
                    "ktlint_standard_max-line-length" to "disabled",
                    "ktlint_standard_kdoc" to "disabled",
                ),
            )
    }

    format("xml") {
        target(
            fileTree(".") {
                include("config/**/*.xml", "lib/**/*.xml", "test-app/**/*.xml")
                exclude("**/build", "**/out")
            },
        )
    }

    format("misc") {
        target("**/.gitignore")
        trimTrailingWhitespace()
        endWithNewline()
    }
}

val gitHubUrl = "https://github.com/kruton/ssh-proto"

dokka {
    moduleName.set("ConnectBot SSH Library")

    dokkaSourceSets.configureEach {
        includes.from("README.md")
        sourceLink {
            localDirectory.set(file("./"))
            remoteUrl.set(uri("$gitHubUrl/blob/main"))
            remoteLineSuffix.set("#L")
        }
    }

    pluginsConfiguration {
        html.footerMessage.set("Copyright Kenny Root")
    }
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true, validateDeployment = DeploymentValidation.PUBLISHED)
    signAllPublications()

    pom {
        name.set("sshlib")
        description.set("ConnectBot's SSH library written with Kotlin suspend functions.")
        inceptionYear.set("2025")
        url.set(gitHubUrl)
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("kruton")
                name.set("Kenny Root")
                url.set("https://github.com/kruton/")
            }
        }
        scm {
            connection.set("scm:git:$gitHubUrl.git")
            developerConnection.set("$gitHubUrl.git")
            url.set(gitHubUrl)
        }
    }
}
