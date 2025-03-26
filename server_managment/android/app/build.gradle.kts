import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    id("dev.flutter.flutter-gradle-plugin")
}

val keystoreProperties = Properties()
val keystorePropertiesFile = rootProject.file("key.properties")
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(keystorePropertiesFile.inputStream())
} else {
    throw GradleException("Plik key.properties nie istnieje. Utwórz go w folderze android/")
}

android {
    compileSdk = 35
    namespace = "com.example.server_managment"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    defaultConfig {
        applicationId = "com.example.server_managment"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("release") {
            keyAlias = keystoreProperties.getProperty("keyAlias") ?: throw GradleException("Brak keyAlias w key.properties")
            keyPassword = keystoreProperties.getProperty("keyPassword") ?: throw GradleException("Brak keyPassword w key.properties")
            storeFile = keystoreProperties.getProperty("storeFile")?.let { file(it) } ?: throw GradleException("Brak storeFile w key.properties")
            storePassword = keystoreProperties.getProperty("storePassword") ?: throw GradleException("Brak storePassword w key.properties")
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true // Zsynchronizowane z isMinifyEnabled
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.9.20")
}

flutter {
    source = "../.."
}