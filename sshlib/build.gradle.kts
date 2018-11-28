plugins {
    `java-library`
    id("com.jfrog.artifactory") version "4.7.5"
    id("com.jfrog.bintray") version "1.8.4"
    id("net.researchgate.release") version "2.7.0"
}

apply(from = "${rootDir}/publish.gradle")
apply(from = "${rootDir}/config/quality.gradle.kts")

dependencies {
    compile("com.jcraft:jzlib:1.1.3")
    compile("org.connectbot:simplesocks:1.0.1")
    compile("net.i2p.crypto:eddsa:0.2.0")
    compile("net.vrallev.ecc:ecc-25519-java:1.0.3")
    compile("org.connectbot.jbcrypt:jbcrypt:1.0.0")

    testCompile("junit:junit:4.12")
    testCompile("commons-io:commons-io:2.6")
    testCompile("commons-codec:commons-codec:1.11")
    testCompile("org.testcontainers:testcontainers:1.9.1")
    testCompile("ch.qos.logback:logback-classic:1.2.3")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}
