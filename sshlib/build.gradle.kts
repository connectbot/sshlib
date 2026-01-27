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
    kotlin("jvm")
    `java-library`
}

val kaitaiInputDir = file("src/main/resources/kaitai")
val kaitaiOutputDir = file("build/generated/kaitai")
val kaitaiCompilerZip = rootProject.file("prebuilts/kaitai-struct-compiler-0.11.zip")
val kaitaiCompilerDir = file("build/kaitai-compiler")

tasks.register<Copy>("unzipKaitaiCompiler") {
    from(zipTree(kaitaiCompilerZip))
    into(kaitaiCompilerDir)
}

abstract class KaitaiTask : Exec() {
    @get:InputFiles
    abstract val ksyFiles: ConfigurableFileCollection

    @get:Input
    abstract val compilerPath: Property<String>

    @get:Input
    abstract val outputDirPath: Property<String>

    @get:Input
    abstract val javaPackage: Property<String>

    @TaskAction
    override fun exec() {
        File(outputDirPath.get()).mkdirs()
        commandLine(
            listOf(
                compilerPath.get(),
                "--read-write",
                "--target", "java",
                "--outdir", outputDirPath.get(),
                "--java-package", javaPackage.get()
            ) + ksyFiles.files.map { it.absolutePath }
        )
        super.exec()
    }
}

tasks.register<KaitaiTask>("kaitai") {
    dependsOn("unzipKaitaiCompiler")

    ksyFiles.from(fileTree(kaitaiInputDir) { include("*.ksy") })
    compilerPath.set(kaitaiCompilerDir.resolve("kaitai-struct-compiler-0.11/bin/kaitai-struct-compiler").absolutePath)
    outputDirPath.set(kaitaiOutputDir.absolutePath)
    javaPackage.set("org.connectbot.sshlib.struct")

    outputs.dir(kaitaiOutputDir)
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

dependencies {
    // Public API dependencies
    api(fileTree(rootProject.file("libs")) { include("kaitai-struct-runtime-*.jar") })
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")

    // Internal dependencies
    implementation(kotlin("stdlib"))
    implementation("io.github.nsk90:kstatemachine-jvm:0.36.0")
    implementation("io.ktor:ktor-network:3.4.0")
    implementation("org.slf4j:slf4j-api:2.0.17")

    // Unit tests
    testImplementation("junit:junit:4.13.2")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:6.0.2")
}

tasks.test {
    useJUnitPlatform()
}
