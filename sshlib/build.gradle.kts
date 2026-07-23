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
import java.io.ByteArrayOutputStream

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
val tla2toolsJar = providers.gradleProperty("tla2toolsJar")
    .orElse(providers.environmentVariable("TLA2TOOLS_JAR"))

listOf(
    "Ssh" to ("SshClientStateMachine" to "SshStateMachineTlaGenerator"),
    "Sftp" to ("SftpClientStateMachine" to "SftpStateMachineTlaGenerator"),
).forEach { (type, config) ->
    val (modelName, generatorClass) = config
    tasks.register<JavaExec>("generate${type}StateMachineTla") {
        group = "verification"
        description = "Regenerates the TLA+ lifecycle model from $modelName"
        dependsOn(tasks.testClasses)
        classpath = sourceSets.test.get().runtimeClasspath
        mainClass.set("org.connectbot.sshlib.protocol.$generatorClass")
        args(tlaModelDirectory.file("${modelName}Generated.tla").asFile.absolutePath)
    }
}

fun TaskContainer.registerTlcCheck(
    name: String,
    description: String,
    configFile: String,
    tlaFile: String,
    stateSubdir: String? = null,
    configure: (JavaExec.() -> Unit)? = null,
): TaskProvider<JavaExec> = register<JavaExec>(name) {
    group = "verification"
    this.description = description
    mainClass.set("tlc2.TLC")
    workingDir(tlaModelDirectory)

    val metaDir = if (stateSubdir != null) {
        tlaStateDirectory.get().dir(stateSubdir).asFile.absolutePath
    } else {
        tlaStateDirectory.get().asFile.absolutePath
    }

    args(
        "-workers",
        "1",
        "-metadir",
        metaDir,
        "-config",
        configFile,
        tlaFile,
    )
    jvmArgs("-XX:+UseParallelGC")

    doFirst {
        val jarPath = tla2toolsJar.orNull
            ?: throw GradleException(
                "Set -Ptla2toolsJar=/path/to/tla2tools.jar or TLA2TOOLS_JAR to run TLC",
            )
        classpath = files(jarPath)
    }

    configure?.invoke(this)
}

fun TaskContainer.registerTlcCounterexampleCheck(
    name: String,
    description: String,
    configFile: String,
    tlaFile: String,
    stateSubdir: String,
    expectedViolation: String,
    failureMessage: String,
    successMessage: String,
): TaskProvider<JavaExec> {
    val outputStream = ByteArrayOutputStream()
    return registerTlcCheck(
        name = name,
        description = description,
        configFile = configFile,
        tlaFile = tlaFile,
        stateSubdir = stateSubdir,
    ) {
        standardOutput = outputStream
        errorOutput = outputStream
        isIgnoreExitValue = true
        doFirst {
            outputStream.reset()
        }
        doLast {
            val output = outputStream.toString(Charsets.UTF_8)
            logger.lifecycle(output)
            val exitValue = executionResult.get().exitValue
            if (exitValue == 0 || expectedViolation !in output) {
                throw GradleException("$failureMessage; exit=$exitValue")
            }
            logger.lifecycle(successMessage)
        }
    }
}

tasks.registerTlcCheck(
    name = "checkSshStateMachineTla",
    description = "Checks the generated SSH lifecycle model with TLC",
    configFile = "SshClientStateMachine.cfg",
    tlaFile = "SshClientStateMachine.tla",
)

listOf(
    "OnPath" to "SshClientStateMachineOnPath.cfg",
    "HostilePeer" to "SshClientStateMachineHostilePeer.cfg",
).forEach { (profile, configFile) ->
    tasks.registerTlcCheck(
        name = "checkSshStateMachine${profile}Tla",
        description = "Checks the generated SSH lifecycle model with the $profile hostile environment",
        configFile = configFile,
        tlaFile = "SshClientStateMachine.tla",
        stateSubdir = "ssh-${profile.lowercase()}",
    )
}

tasks.registerTlcCounterexampleCheck(
    name = "checkSshStateMachineUnsafeProofTla",
    description = "Requires TLC to find a hostile KEX counterexample when proof verification is disabled",
    configFile = "SshClientStateMachineUnsafeProof.cfg",
    tlaFile = "SshClientStateMachine.tla",
    stateSubdir = "ssh-unsafe-proof",
    expectedViolation = "Invariant HostileKexReplyRequiresPossessionProof is violated",
    failureMessage = "Expected TLC to find the disabled-proof counterexample",
    successMessage = "Expected disabled-proof counterexample found; treating it as success.",
)

tasks.registerTlcCheck(
    name = "checkSftpStateMachineTla",
    description = "Checks the generated SFTP lifecycle model with TLC",
    configFile = "SftpClientStateMachine.cfg",
    tlaFile = "SftpClientStateMachine.tla",
)

val checkSshTerrapinStrictTla = tasks.registerTlcCheck(
    name = "checkSshTerrapinStrictTla",
    description = "Proves that strict KEX prevents the modeled Terrapin prefix truncation attack",
    configFile = "SshTerrapinStrict.cfg",
    tlaFile = "SshTerrapin.tla",
    stateSubdir = "terrapin-strict",
)

val checkSshTerrapinNonStrictTla = tasks.registerTlcCounterexampleCheck(
    name = "checkSshTerrapinNonStrictTla",
    description = "Requires TLC to find the modeled Terrapin counterexample without failing the build",
    configFile = "SshTerrapinNonStrict.cfg",
    tlaFile = "SshTerrapin.tla",
    stateSubdir = "terrapin-non-strict",
    expectedViolation = "Invariant NoTerrapin is violated",
    failureMessage = "Expected TLC to find the non-strict Terrapin counterexample",
    successMessage = "Expected non-strict Terrapin counterexample found; treating it as success.",
)

tasks.register("checkSshTerrapinTla") {
    group = "verification"
    description = "Checks strict Terrapin resistance and the expected non-strict counterexample"
    dependsOn(checkSshTerrapinStrictTla, checkSshTerrapinNonStrictTla)
}

tasks.register("generateTla") {
    group = "verification"
    description = "Regenerates all TLA+ formal models (SSH and SFTP)"
    dependsOn("generateSshStateMachineTla", "generateSftpStateMachineTla")
}

tasks.register("checkTla") {
    group = "verification"
    description = "Checks all TLA+ formal models (SSH and SFTP) with TLC"
    dependsOn(
        "checkSshStateMachineTla",
        "checkSshStateMachineOnPathTla",
        "checkSshStateMachineHostilePeerTla",
        "checkSshStateMachineUnsafeProofTla",
        "checkSftpStateMachineTla",
        "checkSshTerrapinTla",
    )
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
