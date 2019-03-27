plugins {
    java
}

apply(from = "${rootDir}/config/quality.gradle.kts")

dependencies {
    testCompile(project(":sshlib"))
    testCompile("junit:junit:4.12")
    testCompile("commons-io:commons-io:2.6")
    testCompile("commons-codec:commons-codec:1.11")
    testCompile("org.testcontainers:testcontainers:1.10.2")
    testCompile("ch.qos.logback:logback-classic:1.2.3")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}
