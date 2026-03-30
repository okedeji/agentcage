plugins {
    kotlin("jvm") version "1.9.22"
    kotlin("plugin.serialization") version "1.9.22"
    application
}

group = "com.agentcage"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    implementation("org.postgresql:postgresql:42.7.1")

    testImplementation(kotlin("test"))
}

application {
    mainClass.set("com.agentcage.audit.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
