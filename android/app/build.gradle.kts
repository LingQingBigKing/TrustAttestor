import android.databinding.tool.ext.capitalizeUS
import com.android.build.api.dsl.ApkSigningConfig
import net.fornwall.jelf.ElfFile
import net.fornwall.jelf.ElfSegment
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Properties
import java.util.zip.CRC32

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.lsposed.lsplugin.apksign")
}

val androidSourceCompatibility: JavaVersion by rootProject.extra
val androidTargetCompatibility: JavaVersion by rootProject.extra
val ndkVer: String? by project
val effectiveNdkVersion = ndkVer ?: "27.2.12479018"
val cloudAttestationUrl = providers.gradleProperty("trustAttestorCloudUrl").orNull.orEmpty()
val cloudVerdictPublicKey = providers.gradleProperty("trustAttestorCloudVerdictPublicKey").orNull.orEmpty()
fun buildConfigString(value: String): String = "\"" + value
    .replace("\\", "\\\\")
    .replace("\"", "\\\"") + "\""

rootProject.file("keystore.properties").let { f ->
    if (f.isFile) {
        Properties().apply {
            f.inputStream().use { load(it) }
        }.forEach { k, v -> project.ext[k.toString()] = v }
    }
}

apksign {
    storeFileProperty = "androidStoreFile"
    storePasswordProperty = "androidStorePassword"
    keyAliasProperty = "androidKeyAlias"
    keyPasswordProperty = "androidKeyPassword"
}

val defaultCFlags = arrayOf(
    "-Wall", "-Wextra",
    "-Wno-unused", "-Wno-unused-parameter",
    "-Wno-builtin-macro-redefined",
    "-Wno-unused-command-line-argument",
    "-fno-rtti", "-fno-exceptions",
    "-fno-stack-protector", "-fomit-frame-pointer",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=0",
    "-D__FILE__=__FILE_NAME__",
)

val releaseFlags = arrayOf(
    "-O3", "-flto",
    "-fvisibility=hidden", "-fvisibility-inlines-hidden",
    "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
    // memmove will not be linked without this
    "-fno-builtin",
)

val commonLinkerKeepFlags = arrayOf(
    "-Wl,--undefined=checksum"
)

fun String.execute(currentWorkingDir: File = file("./")): String {
    val byteOut = ByteArrayOutputStream()
    project.exec {
        workingDir = currentWorkingDir
        commandLine = split("\\s".toRegex())
        standardOutput = byteOut
    }
    return String(byteOut.toByteArray()).trim()
}

val gitCommitHash = "git rev-parse --verify --short HEAD".execute()

android {
    namespace = "com.lingqing.trustattestor"
    compileSdk = 35
    ndkVersion = effectiveNdkVersion
    buildToolsVersion = "35.0.0"

    fun getSignerSha256(signConfig: ApkSigningConfig): String {
        val ks = KeyStore.getInstance("JKS")
        return FileInputStream(signConfig.storeFile!!).use {
            println("use keystore file ${signConfig.storeFile}")
            ks.load(it, signConfig.storePassword?.toCharArray())
            val certificate = requireNotNull(ks.getCertificate(signConfig.keyAlias)) {
                "missing signing certificate for alias ${signConfig.keyAlias}"
            }
            MessageDigest.getInstance("SHA-256")
                .digest(certificate.encoded)
                .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        }
    }

    signingConfigs {
        all {
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = false
            enableV4Signing = false
        }
    }

    defaultConfig {
        applicationId = "com.lingqing.trustattestor"
        minSdk = 27
        targetSdk = 35
        versionCode = 15
        versionName = "v1.5"
        buildConfigField(
            "String",
            "CLOUD_ATTESTATION_URL",
            buildConfigString(cloudAttestationUrl)
        )
        buildConfigField(
            "String",
            "CLOUD_VERDICT_PUBLIC_KEY",
            buildConfigString(cloudVerdictPublicKey)
        )
        setProperty("archivesBaseName", "TrustAttestor-v${defaultConfig.versionCode}-$gitCommitHash")
        proguardFiles("proguard-rules.pro")

        externalNativeBuild.cmake {
            abiFilters("arm64-v8a")
            arguments += "-DANDROID_STL=none"
            cFlags("-std=c2x", *defaultCFlags)
            cppFlags("-std=c++2b", *defaultCFlags)
        }

        compileOptions {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }

    buildFeatures {
        buildConfig = true
        prefab = true
        viewBinding = true
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        debug {
            externalNativeBuild.cmake {
                cFlags += commonLinkerKeepFlags
                cppFlags += commonLinkerKeepFlags
            }
        }
        release {
            isMinifyEnabled = true
            externalNativeBuild.cmake {
                cFlags += releaseFlags + commonLinkerKeepFlags
                cppFlags += releaseFlags + commonLinkerKeepFlags
            }
        }

        forEach { type ->
            type.externalNativeBuild.cmake {
                val signerSha256 = getSignerSha256(type.signingConfig!!)
                val name = type.name
                val dexFile = if (name == "release") {
                    rootProject.file(
                        "dex/build/intermediates/dex/release/minifyReleaseWithR8/classes.dex"
                    )
                } else {
                    rootProject.file("dex/build/outputs/embedded-dex/$name/classes.dex")
                }
                val dexPath = dexFile.absolutePath
                println("signerSha256=$signerSha256 type=$name dexPath=$dexPath")
                arguments += "-DAPP_SIGNER_SHA256=$signerSha256"
                arguments += "-DDEX_PATH=${dexFile.absolutePath.replace("\\", "/")}"
            }
        }
    }

    externalNativeBuild.cmake {
        path("src/main/cpp/CMakeLists.txt")
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation("org.lsposed.libcxx:libcxx:27.0.12077973")

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

afterEvaluate {
    android.applicationVariants.forEach { variant ->
        val variantLowered = variant.name
        val variantCapped = variant.name.capitalizeUS()
        val buildTypeCapped = variant.buildType.name.capitalizeUS()
        val cmakeTaskName = if (variantCapped.contains("Debug"))
            "buildCMakeDebug[arm64-v8a]"
        else "buildCMakeRelWithDebInfo[arm64-v8a]"
        val embeddedDexTask = if (variant.buildType.name == "release") {
            ":dex:minifyReleaseWithR8"
        } else {
            ":dex:buildEmbedded${buildTypeCapped}Dex"
        }
        tasks.getByName(cmakeTaskName).dependsOn(embeddedDexTask)
        val patchTask = task("patchBinary${variantCapped}") {
            val unstrippedSo = layout.buildDirectory.file(
                "intermediates/merged_native_libs/$variantLowered/merge${variantCapped}NativeLibs/out/lib/arm64-v8a/libTrustAttestor.so"
            ).get().asFile
            val strippedSo = layout.buildDirectory.file(
                "intermediates/stripped_native_libs/$variantLowered/strip${variantCapped}DebugSymbols/out/lib/arm64-v8a/libTrustAttestor.so"
            ).get().asFile

            inputs.file(unstrippedSo)
            inputs.file(strippedSo)
            outputs.file(strippedSo)

            dependsOn("strip${variantCapped}DebugSymbols")
            doLast {
                var textSz = 0
                var symOff = 0L

                ElfFile.from(unstrippedSo.readBytes()).let { elfFile ->
                        val sym = elfFile.getELFSymbol("checksum")

                        val symAddr = sym.st_value

                        for (i in 0 until elfFile.e_phnum) {
                            val phdr = elfFile.getProgramHeader(i)
                            if (phdr.p_type != ElfSegment.PT_LOAD) continue
                            val fileOff = phdr.p_offset
                            val memOff = phdr.p_vaddr
                            val fileSz = phdr.p_filesz

                            if (symAddr >= memOff && symAddr < memOff + fileSz) {
                                symOff = symAddr - memOff + fileOff
                            }
                            if (memOff == 0L) { // __executable_start
                                textSz = fileSz.toInt() // == memSz == _etext
                            }
                        }
                }

                if (symOff == 0L) error("failed to find symoff")
                println("symOff=$symOff")
                println("textSz=$textSz")

                if (variant.buildType.name == "release") {
                    val osName = System.getProperty("os.name").lowercase()
                    val hostTag = when {
                        osName.contains("win") -> "windows-x86_64"
                        osName.contains("mac") -> "darwin-x86_64"
                        else -> "linux-x86_64"
                    }
                    val executableName = if (osName.contains("win")) {
                        "llvm-objcopy.exe"
                    } else {
                        "llvm-objcopy"
                    }
                    val llvmObjcopy = androidComponents.sdkComponents.sdkDirectory.get().asFile
                        .resolve("ndk/$effectiveNdkVersion/toolchains/llvm/prebuilt/$hostTag/bin/$executableName")
                    check(llvmObjcopy.isFile) { "llvm-objcopy not found: $llvmObjcopy" }

                    project.exec {
                        commandLine(
                            llvmObjcopy.absolutePath,
                            "--strip-unneeded",
                            "--remove-section=.comment",
                            unstrippedSo.absolutePath,
                            strippedSo.absolutePath
                        )
                    }

                    val releaseBytes = strippedSo.readBytes()
                    check(releaseBytes.size >= 64 &&
                          releaseBytes[0] == 0x7f.toByte() &&
                          releaseBytes[1] == 'E'.code.toByte() &&
                          releaseBytes[2] == 'L'.code.toByte() &&
                          releaseBytes[3] == 'F'.code.toByte() &&
                          releaseBytes[4] == 2.toByte() &&
                          releaseBytes[5] == 1.toByte()) {
                        "release native library is not a little-endian ELF64 image"
                    }
                    val elfHeader = ByteBuffer.wrap(releaseBytes).order(ByteOrder.LITTLE_ENDIAN)
                    val sectionHeaderOffset = elfHeader.getLong(0x28)
                    val sectionHeaderEntrySize = elfHeader.getShort(0x3a).toInt() and 0xffff
                    val sectionHeaderCount = elfHeader.getShort(0x3c).toInt() and 0xffff
                    val sectionNameIndex = elfHeader.getShort(0x3e).toInt() and 0xffff
                    check(sectionHeaderOffset > 0 &&
                          sectionHeaderEntrySize >= 64 &&
                          sectionHeaderCount > 0 &&
                          sectionNameIndex in 1 until sectionHeaderCount &&
                          sectionHeaderOffset + sectionHeaderEntrySize.toLong() * sectionHeaderCount <= releaseBytes.size) {
                        "release ELF section headers are unavailable after metadata cleanup"
                    }
                    val sectionNameHeader = Math.toIntExact(
                        sectionHeaderOffset + sectionHeaderEntrySize.toLong() * sectionNameIndex
                    )
                    val sectionNameOffset = elfHeader.getLong(sectionNameHeader + 0x18)
                    val sectionNameSize = elfHeader.getLong(sectionNameHeader + 0x20)
                    check(sectionNameOffset >= 0 && sectionNameSize > 0 &&
                          sectionNameOffset + sectionNameSize <= releaseBytes.size) {
                        "release ELF section name table is invalid"
                    }
                    RandomAccessFile(strippedSo, "rw").use { file ->
                        file.seek(sectionNameOffset)
                        var remaining = sectionNameSize
                        val zeros = ByteArray(4096)
                        while (remaining > 0) {
                            val count = minOf(remaining, zeros.size.toLong()).toInt()
                            file.write(zeros, 0, count)
                            remaining -= count
                        }
                    }
                    println(
                        "release ELF compiler metadata removed and section names anonymized, " +
                            "size=${strippedSo.length()}"
                    )
                }

                check(textSz > 0 && textSz.toLong() <= strippedSo.length()) {
                    "invalid executable text size after ELF stripping"
                }
                check(symOff + 4 <= strippedSo.length()) {
                    "checksum location was removed by ELF stripping"
                }

                RandomAccessFile(strippedSo, "rw").use {
                    val arr = ByteArray(textSz)
                    it.seek(0)
                    it.read(arr, 0, textSz)
                    val crc32 = CRC32()
                    crc32.update(arr)
                    val checksum = crc32.value
                    println("checksum = $checksum")
                    val buf = ByteBuffer.allocate(4)
                    buf.order(ByteOrder.LITTLE_ENDIAN)
                    buf.putInt(checksum.toInt().xor(0x04c696e6751696e67.toInt()))
                    it.seek(symOff)
                    it.write(buf.array(), 0, 4)
                }

                if (variant.buildType.name == "release") {
                    val releaseBytes = strippedSo.readBytes()
                    val elfHeader = ByteBuffer.wrap(releaseBytes, 0, 64)
                        .order(ByteOrder.LITTLE_ENDIAN)
                    val sectionHeaderOffset = elfHeader.getLong(0x28)
                    val sectionHeaderEntrySize = elfHeader.getShort(0x3a).toInt() and 0xffff
                    val sectionHeaderCount = elfHeader.getShort(0x3c).toInt() and 0xffff
                    val sectionNameIndex = elfHeader.getShort(0x3e).toInt() and 0xffff
                    check(sectionHeaderOffset > 0 &&
                          sectionHeaderEntrySize >= 64 &&
                          sectionHeaderCount > 0 &&
                          sectionNameIndex in 1 until sectionHeaderCount) {
                        "release ELF compatibility section headers were removed"
                    }

                    val sectionNameHeader = Math.toIntExact(
                        sectionHeaderOffset + sectionHeaderEntrySize.toLong() * sectionNameIndex
                    )
                    val sectionNameOffset = ByteBuffer.wrap(releaseBytes)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .getLong(sectionNameHeader + 0x18)
                    val sectionNameSize = ByteBuffer.wrap(releaseBytes)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .getLong(sectionNameHeader + 0x20)
                    check(sectionNameOffset >= 0 && sectionNameSize > 0 &&
                          sectionNameOffset + sectionNameSize <= releaseBytes.size &&
                          releaseBytes.copyOfRange(
                              Math.toIntExact(sectionNameOffset),
                              Math.toIntExact(sectionNameOffset + sectionNameSize)
                          ).all { it == 0.toByte() }) {
                        "release ELF section names remain after anonymization"
                    }

                    val payload = String(releaseBytes, Charsets.ISO_8859_1)
                    val forbiddenMetadata = listOf("clang version", "Linker: LLD")
                    forbiddenMetadata.forEach { marker ->
                        check(!payload.contains(marker)) {
                            "release ELF metadata remains after stripping: $marker"
                        }
                    }
                }
            }
        }
        tasks.getByName("package$variantCapped").dependsOn(patchTask)
        tasks.getByName("build${variantCapped}PreBundle").dependsOn(patchTask)
        tasks.getByName("extract${variantCapped}NativeSymbolTables").dependsOn(patchTask)
    }

    val debugUnitTest = tasks.named<Test>("testDebugUnitTest")
    val hostRegressionMains = linkedMapOf(
        "runThroneHuntWatchSnapshotHostTest" to
            "com.lingqing.trustattestor.ThroneHuntWatchSnapshotTest",
        "runThroneHuntCompatibilityHostTest" to
            "com.lingqing.trustattestor.ThroneHuntCompatibilityTest",
        "runFindingTextCatalogEvidenceHostTest" to
            "com.lingqing.trustattestor.FindingTextCatalogEvidenceTest",
        "runScanAssessmentWarningHostTest" to
            "com.lingqing.trustattestor.ScanAssessmentWarningTest",
        "runHardwareProbePresentationHostTest" to
            "com.lingqing.trustattestor.ui.HardwareProbePresentationTest",
        "runHardwareTextLocalizationHostTest" to
            "com.lingqing.trustattestor.HardwareTextLocalizationTest",
        "runIsolatedAttestationCapabilityPolicyHostTest" to
            "com.lingqing.trustattestor.IsolatedAttestationCapabilityPolicyTest",
        "runIsolatedAttestationEvidenceHostTest" to
            "com.lingqing.trustattestor.IsolatedAttestationEvidenceTest",
    )
    val hostRegressionTasks = hostRegressionMains.map { (taskName, mainClassName) ->
        tasks.register<JavaExec>(taskName) {
            group = "verification"
            description = "Runs $mainClassName as a dependency-free host regression test."
            dependsOn("compileDebugUnitTestSources")
            classpath = files(
                debugUnitTest.map { it.testClassesDirs },
                debugUnitTest.map { it.classpath },
            )
            mainClass.set(mainClassName)
        }
    }
    val appHostRegressionTest = tasks.register("appHostRegressionTest") {
        group = "verification"
        description = "Runs the app host-side regression suite."
        dependsOn(hostRegressionTasks)
    }
    tasks.named("check").configure {
        dependsOn(appHostRegressionTest)
    }
}
