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
    alias(libs.plugins.publish)
    alias(libs.plugins.dokka)
    alias(libs.plugins.metalava)
    alias(libs.plugins.kover)
    alias(libs.plugins.cyclonedx)
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
    testImplementation(libs.equalsverifier)
    testImplementation(libs.mockk)

    // Integration test dependencies
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.testcontainers)
    testImplementation(libs.logback.classic)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

val testJdkVersion = providers.gradleProperty("jdkVersion").map(String::toInt).orElse(17)

tasks.test {
    useJUnitPlatform()
    javaLauncher.set(
        javaToolchains.launcherFor {
            languageVersion.set(JavaLanguageVersion.of(testJdkVersion.get()))
        },
    )
}

val tlaModelDirectory = layout.projectDirectory.dir("src/test/resources/tla")
val tlaStateDirectory = layout.buildDirectory.dir("tla/states")

tasks.register<JavaExec>("generateSshStateMachineTla") {
    group = "verification"
    description = "Regenerates the TLA+ lifecycle model from SshClientStateMachine"
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("org.connectbot.sshlib.protocol.SshStateMachineTlaGenerator")
    args(tlaModelDirectory.file("SshClientStateMachineGenerated.tla").asFile.absolutePath)
}

tasks.register<JavaExec>("generateSftpStateMachineTla") {
    group = "verification"
    description = "Regenerates the TLA+ lifecycle model from SftpStateMachine"
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("org.connectbot.sshlib.protocol.SftpStateMachineTlaGenerator")
    args(tlaModelDirectory.file("SftpClientStateMachineGenerated.tla").asFile.absolutePath)
}

val tla2toolsJar = providers.gradleProperty("tla2toolsJar")
    .orElse(providers.environmentVariable("TLA2TOOLS_JAR"))

tasks.register<JavaExec>("checkSshStateMachineTla") {
    group = "verification"
    description = "Checks the generated SSH lifecycle model with TLC"
    mainClass.set("tlc2.TLC")
    workingDir(tlaModelDirectory)
    args(
        "-workers",
        "1",
        "-metadir",
        tlaStateDirectory.get().asFile.absolutePath,
        "-config",
        "SshClientStateMachine.cfg",
        "SshClientStateMachine.tla",
    )
    jvmArgs("-XX:+UseParallelGC")
    doFirst {
        val jarPath = tla2toolsJar.orNull
            ?: throw GradleException(
                "Set -Ptla2toolsJar=/path/to/tla2tools.jar or TLA2TOOLS_JAR to run TLC",
            )
        classpath = files(jarPath)
    }
}

tasks.register<JavaExec>("checkSftpStateMachineTla") {
    group = "verification"
    description = "Checks the generated SFTP lifecycle model with TLC"
    mainClass.set("tlc2.TLC")
    workingDir(tlaModelDirectory)
    args(
        "-workers",
        "1",
        "-metadir",
        tlaStateDirectory.get().asFile.absolutePath,
        "-config",
        "SftpClientStateMachine.cfg",
        "SftpClientStateMachine.tla",
    )
    jvmArgs("-XX:+UseParallelGC")
    doFirst {
        val jarPath = tla2toolsJar.orNull
            ?: throw GradleException(
                "Set -Ptla2toolsJar=/path/to/tla2tools.jar or TLA2TOOLS_JAR to run TLC",
            )
        classpath = files(jarPath)
    }
}

tasks.register("generateTla") {
    group = "verification"
    description = "Regenerates all TLA+ formal models (SSH and SFTP)"
    dependsOn("generateSshStateMachineTla", "generateSftpStateMachineTla")
}

tasks.register("checkTla") {
    group = "verification"
    description = "Checks all TLA+ formal models (SSH and SFTP) with TLC"
    dependsOn("checkSshStateMachineTla", "checkSftpStateMachineTla")
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

val gitHubUrl = "https://github.com/connectbot/cbssh"

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

tasks.cyclonedxDirectBom {
    includeConfigs.set(listOf("runtimeClasspath"))
    includeLicenseText.set(true)
    jsonOutput.set(layout.buildDirectory.file("reports/cyclonedx-direct/${project.name}-bom.json"))
}

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            artifact(tasks.cyclonedxDirectBom.flatMap { it.jsonOutput }) {
                classifier = "cyclonedx"
                extension = "json"
            }
        }
    }
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true, validateDeployment = DeploymentValidation.PUBLISHED)
    signAllPublications()

    pom {
        name.set("sshlib")
        description.set("ConnectBot SSH Client Library")
        inceptionYear.set("2019")
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
