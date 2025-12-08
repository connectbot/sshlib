apply(plugin = "checkstyle")

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

configure<CheckstyleExtension> {
    toolVersion = libs.findVersion("checkstyle").get().toString()
}

tasks.named<Task>("check") {
    dependsOn("checkstyle")
}

tasks.register<Checkstyle>("checkstyle") {
    source = fileTree("src/main/java")
    exclude("**/gen/**")

    classpath = files()
}
