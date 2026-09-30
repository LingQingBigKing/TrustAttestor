import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import org.gradle.jvm.tasks.Jar

plugins {
    id("com.android.application")
}

fun javaStringLiteral(s: String): String {
    val out = StringBuilder(s.length + 32)
    out.append('"')
    for (ch in s) {
        when (ch) {
            '\\' -> out.append("\\\\")
            '"' -> out.append("\\\"")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            '\b' -> out.append("\\b")
            '\u000C' -> out.append("\\f")
            else -> {
                if (ch.code < 0x20) {
                    out.append(String.format("\\u%04x", ch.code))
                } else {
                    out.append(ch)
                }
            }
        }
    }
    out.append('"')
    return out.toString()
}

fun splitByUtf8Bytes(text: String, maxBytes: Int): List<String> {
    val parts = ArrayList<String>()
    val current = StringBuilder()
    var currentBytes = 0
    var i = 0

    while (i < text.length) {
        val cp = text.codePointAt(i)
        val chars = String(Character.toChars(cp))
        val bytes = chars.toByteArray(StandardCharsets.UTF_8).size

        if (current.isNotEmpty() && currentBytes + bytes > maxBytes) {
            parts.add(current.toString())
            current.setLength(0)
            currentBytes = 0
        }

        current.append(chars)
        currentBytes += bytes
        i += Character.charCount(cp)
    }

    if (current.isNotEmpty()) {
        parts.add(current.toString())
    }

    return parts
}

val generateRevocationListJava by tasks.registering {
    val inputFile = layout.projectDirectory.file("revocation_list.json")
    val outputDir = layout.buildDirectory.dir("generated/source/revocationList/java")

    inputs.file(inputFile)
    outputs.dir(outputDir)

    doLast {
        val json = inputFile.asFile.readText(Charsets.UTF_8)

        // 单个 Java 字符串常量上限约 65535 字节。
        // 这里用 16000 字节保守切片，避免 UTF-8 / 编译器 / 转义边界问题。
        val parts = splitByUtf8Bytes(json, 16_000)

        val packageDir = outputDir.get().asFile
            .resolve("io/github/vvb2060/keyattestation/attestation")

        packageDir.mkdirs()

        val outFile = packageDir.resolve("RevocationListData.java")

        outFile.writeText(
            buildString {
                appendLine("package io.github.vvb2060.keyattestation.attestation;")
                appendLine()
                appendLine("final class RevocationListData {")
                appendLine("    private RevocationListData() {}")
                appendLine()
                appendLine("    static final int ORIGINAL_LENGTH = ${json.length};")
                appendLine("    static final int PART_COUNT = ${parts.size};")
                appendLine()
                appendLine("    private static final String[] PARTS = new String[] {")
                parts.forEachIndexed { index, part ->
                    append("        ")
                    append(javaStringLiteral(part))
                    if (index != parts.lastIndex) append(',')
                    appendLine()
                }
                appendLine("    };")
                appendLine()
                appendLine("    static String get() {")
                appendLine("        StringBuilder sb = new StringBuilder(ORIGINAL_LENGTH);")
                appendLine("        for (String part : PARTS) {")
                appendLine("            sb.append(part);")
                appendLine("        }")
                appendLine("        return sb.toString();")
                appendLine("    }")
                appendLine("}")
            },
            Charsets.UTF_8
        )

        println("Generated RevocationListData.java, parts=${parts.size}, originalLength=${json.length}")
    }
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(generateRevocationListJava)
}

android {
    namespace = "com.lingqing.trustattestor"
    compileSdk = 35
    sourceSets["main"].java.srcDir(layout.buildDirectory.dir("generated/source/revocationList/java"))

    defaultConfig {
        minSdk = 27
        multiDexEnabled = false
        proguardFiles("proguard-rules.pro")
    }

    packaging {
        resources {
            excludes += "**"
        }
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles("proguard-release.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("com.google.guava:guava:33.3.1-android")
    implementation("co.nstant.in:cbor:0.9")
    implementation("com.android.tools.build:apksig:8.7.2")

    compileOnly(project(":stub"))
}

// Build the embedded payload with the standard Android R8 toolchain.
val androidSdkDirectory = androidComponents.sdkComponents.sdkDirectory
val androidPlatformJar = androidSdkDirectory.map { it.file("platforms/android-35/android.jar") }
val d8Jar = androidSdkDirectory.map { it.file("build-tools/35.0.1/lib/d8.jar") }

fun File.isClassPathEntry(): Boolean = isDirectory || extension.equals("jar", ignoreCase = true)

afterEvaluate {
    val variantName = "debug"
    val variantCapped = "Debug"
    val compileTaskName = "compileDebugJavaWithJavac"
    val projectClasses = layout.buildDirectory.dir(
        "intermediates/javac/${variantName}/${compileTaskName}/classes"
    )
    val projectClassesJar = layout.buildDirectory.file(
        "intermediates/embedded-dex/${variantName}/program.jar"
    )
    val embeddedDex = layout.buildDirectory.file(
        "outputs/embedded-dex/${variantName}/classes.dex"
    )
    val runtimeClasspath = configurations.getByName("${variantName}RuntimeClasspath")
    val stubJar = rootProject.layout.projectDirectory.file(
        "stub/build/intermediates/compile_library_classes_jar/${variantName}/" +
            "bundleLibCompileToJar${variantCapped}/classes.jar"
    )
    val packageProjectClasses = tasks.register<Jar>("packageEmbedded${variantCapped}Classes") {
        group = "build"
        description = "Packages compiled classes for the embedded R8 payload."
        dependsOn(compileTaskName)
        from(projectClasses)
        archiveFileName.set("program.jar")
        destinationDirectory.set(layout.buildDirectory.dir("intermediates/embedded-dex/${variantName}"))
    }
    val buildEmbeddedDex = tasks.register("buildEmbedded${variantCapped}Dex") {
        group = "build"
        description = "Builds the single Debug DEX embedded into libTrustAttestor.so."
        dependsOn(packageProjectClasses, ":stub:bundleLibCompileToJar${variantCapped}")
        inputs.dir(projectClasses)
        inputs.file(projectClassesJar)
        inputs.file(d8Jar)
        inputs.file(androidPlatformJar)
        inputs.file(stubJar)
        inputs.files(runtimeClasspath)
        inputs.file(layout.projectDirectory.file("proguard-rules.pro"))
        outputs.file(embeddedDex)
        doLast {
            val r8 = d8Jar.get().asFile
            val androidJar = androidPlatformJar.get().asFile
            val classesJar = projectClassesJar.get().asFile
            check(r8.isFile) { "Android R8/D8 JAR not found: ${r8}" }
            check(androidJar.isFile) { "Android platform JAR not found: ${androidJar}" }
            check(classesJar.isFile) { "Packaged classes not found: ${classesJar}" }
            check(stubJar.asFile.isFile) { "Stub JAR not found: ${stubJar}" }

            val outputDirectory = layout.buildDirectory.dir(
                "intermediates/embedded-dex/${variantName}/r8"
            ).get().asFile
            delete(outputDirectory)
            check(outputDirectory.mkdirs()) {
                "Cannot create R8 output directory: ${outputDirectory}"
            }

            val runtimeEntries = runtimeClasspath.files
                .filter { it.isClassPathEntry() }
                .sortedBy { it.absolutePath }
            check(runtimeEntries.isNotEmpty()) {
                "Runtime classpath is empty for ${variantName}"
            }

            val r8Arguments = mutableListOf(
                "-cp", r8.absolutePath,
                "com.android.tools.r8.R8",
                "--debug",
                "--min-api", "27",
                "--no-data-resources",
                "--lib", androidJar.absolutePath,
                "--lib", stubJar.asFile.absolutePath,
                "--output", outputDirectory.absolutePath,
                "--pg-conf", layout.projectDirectory.file("proguard-rules.pro").asFile.absolutePath,
                classesJar.absolutePath,
            )
            r8Arguments += runtimeEntries.map(File::getAbsolutePath)

            val javaExecutable = file(System.getProperty("java.home"))
                .resolve("bin/" + if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java")
            exec {
                executable = javaExecutable.absolutePath
                args = r8Arguments
            }

            val generatedDexFiles = outputDirectory.listFiles { file ->
                file.isFile && file.name.matches(Regex("classes(?:\\d+)?\\.dex"))
            }?.sortedBy { it.name }.orEmpty()
            check(generatedDexFiles.map(File::getName) == listOf("classes.dex")) {
                "Embedded payload must remain single-DEX, found: ${generatedDexFiles.map(File::getName)}"
            }
            val generatedDex = generatedDexFiles.single()
            val header = generatedDex.inputStream().use { it.readNBytes(8) }
            check(header.size == 8 && header.copyOfRange(0, 4)
                .contentEquals("dex\n".toByteArray())) {
                "R8 output is not a DEX file: ${generatedDex}"
            }

            val output = embeddedDex.get().asFile
            output.parentFile.mkdirs()
            Files.copy(generatedDex.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING)
            println("Embedded Debug DEX: $output (${output.length()} bytes)")
        }
    }

    tasks.named("assemble${variantCapped}").configure {
        dependsOn(buildEmbeddedDex)
    }

    val debugUnitTest = tasks.named<Test>("testDebugUnitTest")
    val hostRegressionMains = linkedMapOf(
        "runAttestationVerdictEvidenceHostTest" to
            "com.lingqing.trustattestor.AttestationVerdictEvidenceTest",
        "runAttestationStateEvidenceHostTest" to
            "com.lingqing.trustattestor.AttestationStateEvidenceTest",
        "runCertificateRecordEvidenceHostTest" to
            "com.lingqing.trustattestor.CertificateRecordEvidenceTest",
        "runDevicePropertiesProbeDecisionHostTest" to
            "com.lingqing.trustattestor.DevicePropertiesProbeDecisionTest",
        "runExtendedProbeEvidenceHostTest" to
            "com.lingqing.trustattestor.ExtendedProbeEvidenceTest",
        "runKeystoreStatePlaneEvidenceHostTest" to
            "com.lingqing.trustattestor.KeystoreStatePlaneEvidenceTest",
        "runKeystoreTimingClockHostTest" to
            "com.lingqing.trustattestor.KeystoreTimingClockTest",
        "runKeystoreTimingProbeDecisionHostTest" to
            "com.lingqing.trustattestor.KeystoreTimingProbeDecisionTest",
        "runKeystoreTimingStatisticsHostTest" to
            "com.lingqing.trustattestor.KeystoreTimingStatisticsTest",
        "runOmkAttestKeyProbeSpecHostTest" to
            "com.lingqing.trustattestor.OmkAttestKeyProbeSpecTest",
        "runOmkRiskyProbeEvidenceHostTest" to
            "com.lingqing.trustattestor.OmkRiskyProbeEvidenceTest",
        "runOmkTimingEvidenceHostTest" to
            "com.lingqing.trustattestor.OmkTimingEvidenceTest",
        "runSilentProbeEvidenceHostTest" to
            "com.lingqing.trustattestor.SilentProbeEvidenceTest",
        "runStructuralProbeEvidenceHostTest" to
            "com.lingqing.trustattestor.StructuralProbeEvidenceTest",
        "runAttestationTrustPolicyHostTest" to
            "io.github.vvb2060.keyattestation.attestation.AttestationTrustPolicyTest",
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
            workingDir(rootProject.projectDir)
            mainClass.set(mainClassName)
        }
    }
    val dexHostRegressionTest = tasks.register("dexHostRegressionTest") {
        group = "verification"
        description = "Runs the dex host-side regression suite."
        dependsOn(hostRegressionTasks)
    }
    tasks.named("check").configure {
        dependsOn(dexHostRegressionTest)
    }
}
