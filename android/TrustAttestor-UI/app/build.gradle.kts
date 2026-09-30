plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    // Keep the original R/binding package so shared UI files stay byte-identical.
    namespace = "com.lingqing.trustattestor"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.lingqing.trustattestor.uipreview"
        minSdk = 27
        targetSdk = 35
        versionCode = 1
        versionName = "UI Preview 1.0"
    }

    sourceSets.getByName("main") {
        java.srcDir("src/preview/java")
        res.srcDir("src/preview/res")
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildTypes {
        release {
            // Preview release exercises production's DEBUG=false presentation.
            // It uses only the local development key and cannot replace TA.
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.fragment:fragment-ktx:1.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.recyclerview:recyclerview:1.4.0")
    implementation("androidx.viewpager2:viewpager2:1.1.0")
}
