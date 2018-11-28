apply(plugin = "checkstyle")

configure<CheckstyleExtension> {
    toolVersion = "8.14"
    configDir = rootProject.file("config/quality/checkstyle")
}

tasks.named<Task>("check") {
    dependsOn("checkstyle")
}

tasks.register<Checkstyle>("checkstyle") {
    source = fileTree("src/main/java")
    exclude("**/gen/**")

    classpath = files()
}
