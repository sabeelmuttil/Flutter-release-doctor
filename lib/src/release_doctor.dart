import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/app_identity_check.dart';
import 'package:flutter_release_doctor/src/cicd_check.dart';
import 'package:flutter_release_doctor/src/deep_link_push_check.dart';
import 'package:flutter_release_doctor/src/doctor_config.dart';
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

  bool get hasWarnings =>
      findings.any((finding) => finding.level == FindingLevel.warning);

  int get score {
    var result = 100;
    for (final finding in findings) {
      switch (finding.level) {
        case FindingLevel.error:
          result -= 15;
        case FindingLevel.warning:
          result -= 5;
        case FindingLevel.info:
        case FindingLevel.passed:
          break;
      }
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
        FindingLevel.info => 'INFO ',
        FindingLevel.passed => 'PASS ',
      };
      buffer.writeln(
        '[$icon] [${finding.id}] ${finding.title}: ${finding.detail}',
      );
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
        buffer.writeln(
          '- **${finding.title}** (`${finding.id}`) — ${finding.detail}',
        );
        if (finding.fix != null) buffer.writeln('  - Fix: ${finding.fix}');
      }
      buffer.writeln();
    }
    return buffer.toString();
  }

  static const jsonSchemaVersion = 1;

  Map<String, dynamic> toJson() {
    final counts = <String, int>{
      for (final level in FindingLevel.values) level.name: 0,
    };
    for (final finding in findings) {
      counts[finding.level.name] = (counts[finding.level.name] ?? 0) + 1;
    }
    return {
      'schemaVersion': jsonSchemaVersion,
      'projectPath': project.path,
      'score': score,
      'summary': {
        'error': counts['error'] ?? 0,
        'warning': counts['warning'] ?? 0,
        'info': counts['info'] ?? 0,
        'passed': counts['passed'] ?? 0,
      },
      'findings': findings.map((f) => f.toJson()).toList(),
    };
  }

  String toJsonString({bool pretty = true}) {
    final encoder =
        pretty ? const JsonEncoder.withIndent('  ') : const JsonEncoder();
    return encoder.convert(toJson());
  }
}

class ReleaseDoctor {
  Future<DoctorReport> check(Directory project) async {
    final configResult = await DoctorConfigLoader().load(project);
    final findings = <Finding>[...configResult.findings];
    final approvedHosts = configResult.config.approvedHosts;

    final pubspec = File(_path(project, 'pubspec.yaml'));
    if (!await pubspec.exists()) {
      findings.add(
        const Finding(
          FindingLevel.error,
          'Flutter project',
          'pubspec.yaml was not found.',
          id: 'flutter-project-missing',
          fix: 'Run this command from a Flutter project root.',
        ),
      );
      final applied = DoctorConfigLoader().apply(configResult.config, findings);
      return DoctorReport(project, applied);
    }

    final pubspecText = await pubspec.readAsString();
    findings.add(
      const Finding(
        FindingLevel.passed,
        'Flutter project',
        'pubspec.yaml found.',
        id: 'flutter-project-found',
      ),
    );
    _checkVersion(pubspecText, findings);
    await _checkFirebase(project, findings);
    await _checkAndroid(project, findings);
    await _checkIos(project, findings);
    await _checkSecurity(project, findings, approvedHosts);
    await AppIdentityCheck().run(project, findings);
    await EnvironmentFlavorCheck(approvedHosts: approvedHosts)
        .run(project, findings);
    await SigningCheck().run(project, findings);
    await PlatformCompatibilityCheck().run(project, findings);
    await DeepLinkPushCheck().run(project, findings);
    await CicdCheck().run(project, findings);

    final applied = DoctorConfigLoader().apply(configResult.config, findings);
    return DoctorReport(project, applied);
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
          id: 'app-version',
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
          id: 'app-version',
          fix: 'Use a version such as 1.0.0+1.',
        ),
      );
      return;
    }
    findings.add(
      Finding(
        FindingLevel.passed,
        'App version',
        '`$value` is valid.',
        id: 'app-version',
      ),
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
          id: 'firebase-configuration',
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
        id: 'firebase-configuration',
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
            id: 'android-firebase-json',
          ),
        );
      } catch (_) {
        findings.add(
          const Finding(
            FindingLevel.error,
            'Android Firebase JSON',
            'google-services.json is not valid JSON.',
            id: 'android-firebase-json',
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
          id: 'android-manifest',
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
          id: 'android-sensitive-permissions',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android permissions',
          'Sensitive permissions: ${risky.join(', ')}.',
          id: 'android-sensitive-permissions',
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
          id: 'ios-info-plist',
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
        id: 'ios-privacy-descriptions',
      ),
    );
  }

  Future<void> _checkSecurity(
    Directory project,
    List<Finding> findings,
    Set<String> approvedHosts,
  ) async {
    final approved = approvedHosts.map((h) => h.toLowerCase()).toSet();
    final httpPattern = RegExp(
      "http://[^\\s'\"<>]+",
      caseSensitive: false,
    );
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
      for (final match in httpPattern.allMatches(text)) {
        final url = match.group(0)!;
        final lower = url.toLowerCase();
        if (lower.contains('localhost') || lower.contains('10.0.2.2')) {
          continue;
        }
        final host = _hostOfUrl(url);
        if (host != null && approved.contains(host)) continue;
        insecureHttp = true;
        break;
      }
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
          id: 'insecure-http',
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
          id: 'hard-coded-secret',
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
          id: 'basic-security-scan',
        ),
      );
    }
  }

  String? _hostOfUrl(String url) {
    final match =
        RegExp(r'https?://([^/?:#]+)', caseSensitive: false).firstMatch(url);
    return match?.group(1)?.toLowerCase();
  }

  String _path(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}
