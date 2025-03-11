plugins {
    id(libs.plugins.android.library.get().pluginId)
    id(libs.plugins.kotlin.android.get().pluginId)
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.amnezia.vpn.protocol.xray"
}

dependencies {
    compileOnly(project(":utils"))
    compileOnly(project(":protocolApi"))
    implementation(project(":xray:libXray"))
    implementation(libs.kotlinx.coroutines)
    implementation("com.hierynomus:sshj:0.37.0")
    // Android's built-in "BC" is stripped (no X25519); sshj needs a full provider at runtime.
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("org.slf4j:slf4j-nop:2.0.16")
}
