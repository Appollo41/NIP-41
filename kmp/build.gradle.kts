plugins {
    kotlin("multiplatform") version "2.3.21" apply false
    kotlin("jvm") version "2.3.21" apply false
    kotlin("plugin.serialization") version "2.3.21" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.dokka") version "2.0.0" apply false
}

allprojects {
    group = "com.appollo41"
    version = "0.1.0-SNAPSHOT"
}
