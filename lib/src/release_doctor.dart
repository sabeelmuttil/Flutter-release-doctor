import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/app_identity_check.dart';
import 'package:flutter_release_doctor/src/deep_link_push_check.dart';
import 'package:flutter_release_doctor/src/environment_flavor_check.dart';
import 'package:flutter_release_doctor/src/finding.dart';
import 'package:flutter_release_doctor/src/platform_compatibility_check.dart';
import 'package:flutter_release_doctor/src/signing_check.dart';

export 'package:flutter_release_doctor/src/finding.dart';

class DoctorReport {
  const DoctorReport(this.project, this.findings);

  final Directory project;
  final List<Finding> findings;

  bool get hasErrors =>
      findings.any((finding) => finding.level == FindingLevel.error);

  int get score {
    var result = 100;
    for (final finding in findings) {
      if (finding.level == FindingLevel.error) result -= 15;
      if (finding.level == FindingLevel.warning) result -= 5;
    }
    return result.clamp(0, 100);
  }

  String toConsole() {
    final buffer = StringBuffer('Flutter Release Doctor — ${project.path}\n');
    buffer.writeln('Release score: $score/100\n');
    for (final finding in findings) {
      final icon = switch (finding.level) {
        FindingLevel.error => 'ERROR',
        FindingLevel.warning => 'WARN ',
        FindingLevel.passed => 'PASS ',
      };
      buffer.writeln('[$icon] ${finding.title}: ${finding.detail}');
      if (finding.fix != null) buffer.writeln('       Fix: ${finding.fix}');
    }
    return buffer.toString().trimRight();
  }

  String toMarkdown() {
    final buffer = StringBuffer('# Flutter Release Doctor report\n\n');
    buffer.writeln('**Project:** `${project.path}`  ');
    buffer.writeln('**Release score:** $score/100\n');
    for (final level in FindingLevel.values) {
      final items = findings.where((finding) => finding.level == level);
      if (items.isEmpty) continue;
      buffer.writeln('## ${level.name.toUpperCase()}\n');
      for (final finding in items) {
        buffer.writeln('- **${finding.title}** — ${finding.detail}');
        if (finding.fix != null) buffer.writeln('  - Fix: ${finding.fix}');
      }
      buffer.writeln();
    }
    return buffer.toString();
  }
}

class ReleaseDoctor {
  Future<DoctorReport> check(Directory project) async {
    final findings = <Finding>[];
    final pubspec = File(_path(project, 'pubspec.yaml'));
    if (!await pubspec.exists()) {
      return DoctorReport(project, [
        const Finding(
          FindingLevel.error,
          'Flutter project',
          'pubspec.yaml was not found.',
          fix: 'Run this command from a Flutter project root.',
        ),
      ]);
    }

    final pubspecText = await pubspec.readAsString();
    findings.add(
      const Finding(
        FindingLevel.passed,
        'Flutter project',
        'pubspec.yaml found.',
      ),
    );
    _checkVersion(pubspecText, findings);
    await _checkFirebase(project, findings);
    await _checkAndroid(project, findings);
    await _checkIos(project, findings);
    await _checkSecurity(project, findings);
    await AppIdentityCheck().run(project, findings);
    await EnvironmentFlavorCheck().run(project, findings);
    await SigningCheck().run(project, findings);
    await PlatformCompatibilityCheck().run(project, findings);
    await DeepLinkPushCheck().run(project, findings);
    return DoctorReport(project, findings);
  }

  void _checkVersion(String pubspec, List<Finding> findings) {
    final match = RegExp(
      r'^version:\s*([^\s#]+)',
      multiLine: true,
    ).firstMatch(pubspec);
    if (match == null) {
      findings.add(
        const Finding(
          FindingLevel.error,
          'App version',
          'No version found in pubspec.yaml.',
          fix: 'Add version: 1.0.0+1 to pubspec.yaml.',
        ),
      );
      return;
    }
    final value = match.group(1)!;
    if (!RegExp(r'^\d+\.\d+\.\d+\+\d+$').hasMatch(value)) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'App version',
          '`$value` is not in recommended x.y.z+build format.',
          fix: 'Use a version such as 1.0.0+1.',
        ),
      );
      return;
    }
    findings.add(
      Finding(FindingLevel.passed, 'App version', '`$value` is valid.'),
    );
  }

  Future<void> _checkFirebase(Directory project, List<Finding> findings) async {
    final android = File(_path(project, 'android/app/google-services.json'));
    final ios = File(_path(project, 'ios/Runner/GoogleService-Info.plist'));
    final androidExists = await android.exists();
    final iosExists = await ios.exists();
    if (!androidExists && !iosExists) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Firebase configuration',
          'No Android or iOS Firebase config found.',
          fix: 'Ignore this only when Firebase is intentionally not used.',
        ),
      );
      return;
    }
    findings.add(
      Finding(
        FindingLevel.passed,
        'Firebase configuration',
        'Found ${androidExists ? 'Android' : ''}${androidExists && iosExists ? ' and ' : ''}${iosExists ? 'iOS' : ''} config file(s).',
      ),
    );
    if (androidExists) {
      try {
        jsonDecode(await android.readAsString());
        findings.add(
          const Finding(
            FindingLevel.passed,
            'Android Firebase JSON',
            'google-services.json is valid JSON.',
          ),
        );
      } catch (_) {
        findings.add(
          const Finding(
            FindingLevel.error,
            'Android Firebase JSON',
            'google-services.json is not valid JSON.',
            fix: 'Download a fresh file from Firebase Console.',
          ),
        );
      }
    }
  }

  Future<void> _checkAndroid(Directory project, List<Finding> findings) async {
    final manifest = File(
      _path(project, 'android/app/src/main/AndroidManifest.xml'),
    );
    if (!await manifest.exists()) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android manifest',
          'AndroidManifest.xml was not found.',
        ),
      );
      return;
    }
    final text = await manifest.readAsString();
    final permissions = RegExp(r'<uses-permission[^>]*android:name="([^"]+)"')
        .allMatches(text)
        .map((m) => m.group(1)!)
        .toList();
    final risky = permissions
        .where(
          (p) =>
              p.contains('CAMERA') ||
              p.contains('RECORD_AUDIO') ||
              p.contains('ACCESS_FINE_LOCATION') ||
              p.contains('READ_CONTACTS'),
        )
        .toList();
    if (risky.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'Android permissions',
          'No high-sensitivity permissions detected.',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android permissions',
          'Sensitive permissions: ${risky.join(', ')}.',
          fix:
              'Confirm every permission is essential and declared accurately in Play Data Safety.',
        ),
      );
    }
  }

  Future<void> _checkIos(Directory project, List<Finding> findings) async {
    final plist = File(_path(project, 'ios/Runner/Info.plist'));
    if (!await plist.exists()) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS Info.plist',
          'Info.plist was not found.',
        ),
      );
      return;
    }
    final text = await plist.readAsString();
    const privacyKeys = [
      'NSCameraUsageDescription',
      'NSMicrophoneUsageDescription',
      'NSLocationWhenInUseUsageDescription',
      'NSPhotoLibraryUsageDescription',
    ];
    final present = privacyKeys.where(text.contains).toList();
    findings.add(
      Finding(
        FindingLevel.passed,
        'iOS privacy descriptions',
        present.isEmpty
            ? 'No sensitive permission descriptions found.'
            : 'Found: ${present.join(', ')}.',
      ),
    );
  }

  Future<void> _checkSecurity(Directory project, List<Finding> findings) async {
    final candidates = <File>[];
    await for (final entity in project.list(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File) continue;
      final path = entity.path;
      if (path.contains(
            '${Platform.pathSeparator}.git${Platform.pathSeparator}',
          ) ||
          path.contains(
            '${Platform.pathSeparator}build${Platform.pathSeparator}',
          )) {
        continue;
      }
      if (path.endsWith('.dart') ||
          path.endsWith('.env') ||
          path.endsWith('.yaml') ||
          path.endsWith('.json')) {
        candidates.add(entity);
      }
    }
    var insecureHttp = false;
    var obviousSecret = false;
    for (final file in candidates) {
      final text = await file.readAsString();
      insecureHttp = insecureHttp ||
          RegExp('http:' r'//(?!localhost|10\.0\.2\.2)').hasMatch(text);
      obviousSecret = obviousSecret ||
          RegExp(
            r'''(?:api[_-]?key|secret|password)\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}''',
            caseSensitive: false,
          ).hasMatch(text);
    }
    if (insecureHttp) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Insecure HTTP',
          'A non-local HTTP endpoint was detected.',
          fix: 'Use HTTPS for production endpoints.',
        ),
      );
    }
    if (obviousSecret) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Possible hard-coded secret',
          'A long API key, secret, or password-like value was detected.',
          fix:
              'Review it; rotate real secrets and move them to secure server-side configuration.',
        ),
      );
    }
    if (!insecureHttp && !obviousSecret) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'Basic security scan',
          'No insecure HTTP endpoint or obvious hard-coded secret detected.',
        ),
      );
    }
  }

  String _path(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}
