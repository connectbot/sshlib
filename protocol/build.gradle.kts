/*
 * Copyright 2025 Kenny Root
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
    javaPackage.set("org.connectbot.sshlib.protocol")

    outputs.dir(kaitaiOutputDir)
}

sourceSets {
    main {
        java {
            srcDir(tasks.named("kaitai"))
        }
    }
}

dependencies {
    api(libs.kaitai.runtime)
    implementation(kotlin("stdlib"))
    kaitaiCompiler(libs.kaitai.compiler)
}

java {
    withSourcesJar()
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

val gitHubUrl = "https://github.com/kruton/ssh-proto"

dokka {
    moduleName.set("ConnectBot SSH Protocol Messages")

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

    coordinates(groupId = "org.connectbot", artifactId = "protocol")

    pom {
        name.set("protocol")
        description.set("ConnectBot's SSH protocol messages in Kaitai Struct.")
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
