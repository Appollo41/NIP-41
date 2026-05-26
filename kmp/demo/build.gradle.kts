plugins {
    kotlin("jvm")
    application
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(project(":nip41"))

    // Demo uses these directly (Json formatter, Secp256k1.pubkeyCreate for negative test).
    // Library declares them as `implementation` to keep encapsulation, so demo re-declares.
    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.23.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.23.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    testImplementation(kotlin("test"))
}

application {
    mainClass.set("com.appollo41.nip41.demo.DemoKt")
}

tasks.register<JavaExec>("bench") {
    group = "application"
    description = "Run the chain-derivation benchmark"
    mainClass.set("com.appollo41.nip41.demo.BenchKt")
    classpath = sourceSets["main"].runtimeClasspath
}

tasks.register<JavaExec>("example") {
    group = "application"
    description = "Run the code-as-documentation usage example (no prints)"
    mainClass.set("com.appollo41.nip41.demo.ExampleKt")
    classpath = sourceSets["main"].runtimeClasspath
}
