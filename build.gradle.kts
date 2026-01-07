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
    java
    kotlin("jvm") version "2.3.0"
}

val kaitaiInputDir = file("src/main/resources/kaitai")
val kaitaiOutputDir = file("build/generated/kaitai")
val kaitaiCompilerZip = file("prebuilts/kaitai-struct-compiler-0.11.zip")
val kaitaiCompilerDir = file("build/kaitai-compiler")

tasks.register<Copy>("unzipKaitaiCompiler") {
    from(zipTree(kaitaiCompilerZip))
    into(kaitaiCompilerDir)
}

tasks.register<Exec>("kaitai") {
    dependsOn("unzipKaitaiCompiler")

    inputs.dir(kaitaiInputDir)
    outputs.dir(kaitaiOutputDir)

    doFirst {
        kaitaiOutputDir.mkdirs()
    }

    commandLine(
        "${kaitaiCompilerDir}/kaitai-struct-compiler-0.11/bin/kaitai-struct-compiler",
        "--read-write",
        "--target", "java",
        "--outdir", kaitaiOutputDir.absolutePath,
        "--java-package", "org.connectbot.sshlib.struct",
        *fileTree(kaitaiInputDir).filter { it.extension == "ksy" }.map { it.absolutePath }.toTypedArray()
    )
}

tasks.named("compileJava") {
    dependsOn("kaitai")
}

tasks.named("compileKotlin") {
    dependsOn("kaitai")
}

sourceSets {
    main {
        java {
            srcDir(kaitaiOutputDir)
        }
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Kaitai Struct runtime
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("kaitai-struct-runtime-*.jar"))))

    // KStateMachine for state machine implementation (JVM/Android artifact)
    implementation("io.github.nsk90:kstatemachine-jvm:0.35.0")

    // Kotlin standard library
    implementation(kotlin("stdlib"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")

    // Ktor for networking (lightweight TCP transport)
    implementation("io.ktor:ktor-network:3.3.3")

    // SLF4J API for logging
    implementation("org.slf4j:slf4j-api:2.0.17")

    // Testing dependencies
    testImplementation("org.junit.jupiter:junit-jupiter-api:6.0.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params:6.0.1")
    testImplementation("junit:junit:4.13.2")  // For CaptureTest (JUnit 4)
    testImplementation("org.testcontainers:testcontainers-junit-jupiter:2.0.3")
    testImplementation("org.testcontainers:testcontainers:2.0.3")
    testImplementation("ch.qos.logback:logback-classic:1.5.24")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:6.0.1")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:6.0.2")
}

tasks.test {
    useJUnitPlatform()
}
