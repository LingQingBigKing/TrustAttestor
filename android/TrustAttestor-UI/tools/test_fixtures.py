"""Run actual fixture/model Kotlin code on JDK 17; no device or network required.

First build the app so Gradle has cached the Kotlin compiler dependencies.
"""
import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gradle-home', default=os.environ.get('GRADLE_USER_HOME', str(Path.home() / '.gradle')))
    parser.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    cache = Path(args.gradle_home) / 'caches/modules-2/files-2.1'

    def jar(group, artifact, version):
        candidates = list((cache / group / artifact / version).glob('*/*.jar'))
        if len(candidates) != 1:
            raise RuntimeError(f'Expected one cached {artifact}:{version} JAR; build the app first.')
        return str(candidates[0])

    stdlib = jar('org.jetbrains.kotlin', 'kotlin-stdlib', '2.0.21')
    annotations_candidates = sorted((cache / 'org.jetbrains/annotations').glob('*/*/*.jar'))
    if not annotations_candidates:
        raise RuntimeError('Missing annotations dependency; build the app first.')
    annotations = str(annotations_candidates[-1])
    compiler = [jar('org.jetbrains.kotlin', artifact, '2.0.21') for artifact in (
        'kotlin-compiler-embeddable', 'kotlin-script-runtime', 'kotlin-daemon-embeddable')]
    compiler += [stdlib, annotations,
                 jar('org.jetbrains.kotlin', 'kotlin-reflect', '1.6.10'),
                 jar('org.jetbrains.intellij.deps', 'trove4j', '1.0.20200330'),
                 jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.6.4')]
    java = str(Path(args.java_home) / 'bin/java') if args.java_home else 'java'
    package = root / 'app/src/preview/java/com/lingqing/trustattestor'
    output = root / 'build/fixture-tests'
    output.mkdir(parents=True, exist_ok=True)
    models = (package / 'FindingModels.kt').read_text(encoding='utf-8')
    models = 'package com.lingqing.trustattestor\n\n' + models[
        models.index('enum class FindingStatus'):models.index('object NativeFindingCodec')]
    (output / 'FindingData.kt').write_text(models, encoding='utf-8')
    controller = (package / 'MainViewModel.kt').read_text(encoding='utf-8')
    constants = controller[controller.index('    companion object'):]
    (output / 'LayerConstants.kt').write_text(
        'package com.lingqing.trustattestor\nclass MainViewModel {\n' + constants, encoding='utf-8')
    sources = [output / 'FindingData.kt', output / 'LayerConstants.kt', package / 'UiModels.kt',
               package / 'preview/PreviewFixtures.kt', root / 'tools/PreviewFixturesTest.kt']
    classes = output / 'classes'
    subprocess.run([java, '-cp', os.pathsep.join(compiler), 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                    '-no-stdlib', '-no-reflect', '-jvm-target', '17', '-classpath',
                    os.pathsep.join([stdlib, annotations]), '-d', str(classes),
                    *map(str, sources)], check=True)
    subprocess.run([java, '-ea', '-cp', os.pathsep.join([str(classes), stdlib]), 'PreviewFixturesTestKt'], check=True)


if __name__ == '__main__':
    main()
