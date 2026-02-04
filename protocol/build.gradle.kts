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
