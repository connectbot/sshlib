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
    alias(libs.plugins.metalava)
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

    // Unit tests
    testImplementation(libs.junit)
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly(libs.junit.vintage.engine)
}

tasks.test {
    useJUnitPlatform()
}