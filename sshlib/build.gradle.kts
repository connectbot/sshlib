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
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

val kaitaiInputDir = file("src/main/resources/kaitai")
val kaitaiOutputDir = file("build/generated/kaitai")
val kaitaiCompiler by configurations.creating

abstract class KaitaiTask : JavaExec() {
    @get:InputFiles
    abstract val ksyFiles: ConfigurableFileCollection

    @get:Input
    abstract val outputDirPath: Property<String>

    @get:Input
    abstract val javaPackage: Property<String>

    @TaskAction
    override fun exec() {
        File(outputDirPath.get()).mkdirs()
        args = listOf(
            "--read-write",
            "--target", "java",
            "--outdir", outputDirPath.get(),
            "--java-package", javaPackage.get()
        ) + ksyFiles.files.map { it.absolutePath }
        super.exec()
    }
}

tasks.register<KaitaiTask>("kaitai") {
    ksyFiles.from(fileTree(kaitaiInputDir) { include("*.ksy") })
    classpath = kaitaiCompiler
    mainClass.set("io.kaitai.struct.JavaMain")
    outputDirPath.set(kaitaiOutputDir.absolutePath)
    javaPackage.set("org.connectbot.sshlib.struct")

    outputs.dir(kaitaiOutputDir)
}

tasks.matching { it.name.startsWith("metalava") }.configureEach {
    dependsOn("kaitai")
}

sourceSets {
    main {
        java {
            srcDir(tasks.named("kaitai"))
        }
    }
}

dependencies {
    // Public API dependencies
    api(libs.kaitai.runtime)
    api(libs.kotlinx.coroutines.core)

    // Kaitai compiler
    kaitaiCompiler(libs.kaitai.compiler)

    // Internal dependencies
    implementation(kotlin("stdlib"))
    implementation(libs.kstatemachine)
    implementation(libs.ktor.network)
    implementation(libs.slf4j.api)
    implementation(libs.tink)
    implementation(libs.kyber)

    // Unit tests
    testImplementation(libs.junit)
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly(libs.junit.vintage.engine)
}

tasks.test {
    useJUnitPlatform()
}
