import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/app_identity_check.dart';
import 'package:flutter_release_doctor/src/cicd_check.dart';
import 'package:flutter_release_doctor/src/deep_link_push_check.dart';
import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/environment_flavor_check.dart';
import 'package:flutter_release_doctor/src/evidence.dart';
import 'package:flutter_release_doctor/src/finding.dart';
import 'package:flutter_release_doctor/src/platform_compatibility_check.dart';
import 'package:flutter_release_doctor/src/signing_check.dart';
import 'package:flutter_release_doctor/src/store_compliance_check.dart';
import 'package:flutter_release_doctor/src/store_profile_policy.dart';
import 'package:flutter_release_doctor/src/transaction_safety_check.dart';

export 'package:flutter_release_doctor/src/finding.dart';

class DoctorReport {
  const DoctorReport(this.project, this.findings);

  final Directory project;
  final List<Finding> findings;

  static const storeRiskDisclaimer = StoreComplianceCheck.disclaimer;

  bool get hasErrors =>
      findings.any((finding) => finding.level == FindingLevel.error);

  /// Score-affecting warnings only (excludes MANUAL REVIEW).
  bool get hasWarnings =>
      findings.any((finding) => finding.affectsFailOnWarning);

  int get score {
    var result = 100;
    for (final finding in findings) {
      if (!finding.affectsScore) continue;
      switch (finding.level) {
        case FindingLevel.error:
          result -= 15;
        case FindingLevel.warning:
          result -= 5;
        case FindingLevel.manualReview:
        case FindingLevel.info:
        case FindingLevel.passed:
          break;
      }
    }
    return result.clamp(0, 100);
  }

  String toConsole() {
    final buffer = StringBuffer('Flutter Release Doctor — ${project.path}\n');
    buffer.writeln('Release score: $score/100');
    buffer.writeln('Disclaimer: $storeRiskDisclaimer\n');
    for (final finding in findings) {
      buffer.writeln(
        '[${finding.levelLabel}] [${finding.id}] ${finding.title}: ${finding.detail}',
      );
      buffer.writeln(
        '       confidence=${finding.confidence.name} source=${_sourceLabel(finding.source)}',
      );
      if (finding.guideline != null) {
        buffer.writeln('       Guideline: ${finding.guideline}');
      }
      if (finding.evidenceSummary != null) {
        buffer.writeln('       Evidence: ${finding.evidenceSummary}');
      }
      final evidence = finding.evidenceLabel;
      if (evidence != null) {
        buffer.writeln('       At: $evidence');
      }
      if (finding.fix != null) buffer.writeln('       Fix: ${finding.fix}');
    }
    return buffer.toString().trimRight();
  }

  String toMarkdown() {
    final buffer = StringBuffer('# Flutter Release Doctor report\n\n');
    buffer.writeln('**Project:** `${project.path}`  ');
    buffer.writeln('**Release score:** $score/100  ');
    buffer.writeln('**Disclaimer:** $storeRiskDisclaimer\n');
    for (final level in FindingLevel.values) {
      final items = findings.where((finding) => finding.level == level);
      if (items.isEmpty) continue;
      buffer.writeln('## ${level.reportSectionTitle}\n');
      for (final finding in items) {
        buffer.writeln(
          '- **${finding.title}** (`${finding.id}`) — ${finding.detail}',
        );
        buffer.writeln(
          '  - Confidence: `${finding.confidence.name}` · Source: `${_sourceLabel(finding.source)}`',
        );
        if (finding.guideline != null) {
          buffer.writeln('  - Guideline: ${finding.guideline}');
        }
        if (finding.evidenceSummary != null) {
          buffer.writeln('  - Evidence: ${finding.evidenceSummary}');
        }
        final evidence = finding.evidenceLabel;
        if (evidence != null) buffer.writeln('  - At: `$evidence`');
        if (finding.fix != null) buffer.writeln('  - Fix: ${finding.fix}');
      }
      buffer.writeln();
    }
    return buffer.toString();
  }

  static const jsonSchemaVersion = 1;

  Map<String, dynamic> toJson() {
    final counts = <String, int>{
      for (final level in FindingLevel.values)
        (level == FindingLevel.manualReview ? 'manual_review' : level.name): 0,
    };
    for (final finding in findings) {
      final key = finding.level == FindingLevel.manualReview
          ? 'manual_review'
          : finding.level.name;
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return {
      'schemaVersion': jsonSchemaVersion,
      'projectPath': project.path,
      'score': score,
      'disclaimer': storeRiskDisclaimer,
      'summary': {
        'error': counts['error'] ?? 0,
        'warning': counts['warning'] ?? 0,
        'manual_review': counts['manual_review'] ?? 0,
        'info': counts['info'] ?? 0,
        'passed': counts['passed'] ?? 0,
      },
      'findings': findings.map((f) => f.toJson()).toList(),
    };
  }

  static String _sourceLabel(FindingSource source) => switch (source) {
        FindingSource.staticAnalysis => 'static-analysis',
        FindingSource.projectConfig => 'project-config',
        FindingSource.manualReview => 'manual-review',
      };

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
    await DeepLinkPushCheck(
      usesUniversalLinks: configResult.config.storeProfile.usesUniversalLinks,
      usesAndroidAppLinks: configResult.config.storeProfile.usesAndroidAppLinks,
    ).run(project, findings);
    await CicdCheck(
      ciRequired: configResult.config.storeProfile.ciRequired,
    ).run(project, findings);
    await TransactionSafetyCheck(
      transactionType: configResult.config.transactionType,
      paymentFlows: configResult.config.paymentFlows,
    ).run(project, findings);
    await StoreComplianceCheck(
      storeCompliance: configResult.config.storeCompliance,
      transactionType: configResult.config.transactionType,
      storeProfile: configResult.config.storeProfile,
    ).run(project, findings);

    final profiled = StoreProfilePolicy().apply(configResult.config, findings);
    final applied = DoctorConfigLoader().apply(configResult.config, profiled);
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
    // Keep detection for real secrets; Firebase client-config contexts are
    // filtered separately (not a broad apiKey exception).
    final secretPattern = RegExp(
      r'''(?:api[_-]?key|secret|password|private[_-]?key)\s*[=:]\s*["']?[A-Za-z0-9_/+=\-]{20,}'''
      r'''|"type"\s*:\s*"service_account"'''
      r'''|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----''',
      caseSensitive: false,
    );
    final candidates = <File>[];
    await for (final entity in project.list(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File) continue;
      final path = entity.path;
      final normalized = path.replaceAll('\\', '/');
      final relative = Evidence.relativePath(project, entity);
      if (_shouldSkipSecurityScanPath(relative, normalized)) {
        continue;
      }
      if (path.endsWith('.dart') ||
          path.endsWith('.env') ||
          path.endsWith('.yaml') ||
          path.endsWith('.yml') ||
          path.endsWith('.json') ||
          path.endsWith('.plist') ||
          path.endsWith('.xml')) {
        candidates.add(entity);
      }
    }

    String? httpFile;
    int? httpLine;
    String? secretFile;
    int? secretLine;
    String? secretClass;
    String? firebaseClientFile;
    int? firebaseClientLine;

    for (final file in candidates) {
      final text = await file.readAsString();
      final relative = Evidence.relativePath(project, file);

      if (firebaseClientFile == null &&
          _isKnownFirebaseClientConfigFile(relative, text)) {
        firebaseClientFile = relative;
        firebaseClientLine = _firebaseClientEvidenceLine(relative, text);
      }

      if (httpFile == null) {
        for (final match in httpPattern.allMatches(text)) {
          final url = match.group(0)!;
          final lower = url.toLowerCase();
          if (lower.contains('localhost') || lower.contains('10.0.2.2')) {
            continue;
          }
          if (_isXmlOrPlistMetadataHttp(
            relative,
            text,
            match.start,
            url,
          )) {
            continue;
          }
          final host = _hostOfUrl(url);
          if (host != null && approved.contains(host)) continue;
          httpFile = relative;
          httpLine = Evidence.lineOfOffset(text, match.start);
          break;
        }
      }
      if (secretFile == null) {
        for (final match in secretPattern.allMatches(text)) {
          if (_isFirebaseClientConfigSecret(relative, text, match)) {
            continue;
          }
          secretFile = relative;
          secretLine = Evidence.lineOfOffset(text, match.start);
          secretClass = Evidence.classifySecretMatch(match.group(0)!);
          break;
        }
      }
      if (httpFile != null &&
          secretFile != null &&
          firebaseClientFile != null) {
        break;
      }
    }

    if (httpFile != null) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Insecure HTTP',
          'A non-local HTTP endpoint was detected.',
          id: 'insecure-http',
          file: httpFile,
          line: httpLine,
          confidence: FindingConfidence.high,
          source: FindingSource.staticAnalysis,
          fix: 'Use HTTPS for production endpoints.',
        ),
      );
    }
    if (secretFile != null) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Possible hard-coded secret',
          'A credential-like assignment was detected. The value is redacted.',
          id: 'hard-coded-secret',
          file: secretFile,
          line: secretLine,
          classification: secretClass,
          confidence: FindingConfidence.high,
          source: FindingSource.staticAnalysis,
          fix:
              'Review it; rotate real secrets and move them to secure server-side configuration.',
        ),
      );
    }
    if (firebaseClientFile != null) {
      findings.add(
        Finding(
          FindingLevel.info,
          'Firebase client configuration',
          'Firebase client configuration was detected. Review Google Cloud API restrictions separately.',
          id: 'firebase-client-config-detected',
          file: firebaseClientFile,
          line: firebaseClientLine,
          classification: 'firebase-client-config',
        ),
      );
    }
    if (httpFile == null && secretFile == null) {
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

  /// Generated / metadata trees that must not be scanned for insecure HTTP.
  bool _shouldSkipSecurityScanPath(String relativePath, String normalizedAbs) {
    final relative = relativePath.replaceAll('\\', '/');
    if (relative == '.git' ||
        relative.startsWith('.git/') ||
        normalizedAbs.contains('/.git/')) {
      return true;
    }
    if (relative == 'build' ||
        relative.startsWith('build/') ||
        normalizedAbs.contains('/build/')) {
      return true;
    }
    if (relative == '.dart_tool' ||
        relative.startsWith('.dart_tool/') ||
        normalizedAbs.contains('/.dart_tool/')) {
      return true;
    }
    if (relative.startsWith('ios/Pods/') ||
        relative == 'ios/Pods' ||
        normalizedAbs.contains('/ios/Pods/')) {
      return true;
    }
    // ios/**/*.xcworkspace/**
    if (RegExp(r'(^|/)ios/.+\.xcworkspace(/|$)').hasMatch(relative) ||
        RegExp(r'/ios/.+\.xcworkspace(/|$)').hasMatch(normalizedAbs)) {
      return true;
    }
    return false;
  }

  /// Ignore HTTP URLs that only appear as XML/plist metadata (DTD, xmlns, etc.).
  bool _isXmlOrPlistMetadataHttp(
    String relativePath,
    String text,
    int offset,
    String url,
  ) {
    final lowerPath = relativePath.toLowerCase();
    final isXmlLike =
        lowerPath.endsWith('.plist') || lowerPath.endsWith('.xml');
    if (!isXmlLike) return false;

    final lowerUrl = url.toLowerCase();
    if (lowerUrl.contains('www.apple.com/dtds/') ||
        lowerUrl.contains('apple.com/dtds/') ||
        lowerUrl.contains('schemas.android.com/') ||
        lowerUrl.contains('www.w3.org/') ||
        lowerUrl.contains('xmlns') ||
        lowerUrl.contains('schemas.xmlsoap.org/')) {
      return true;
    }

    final lineStart = offset == 0 ? 0 : text.lastIndexOf('\n', offset - 1) + 1;
    final lineEnd = text.indexOf('\n', offset);
    final line = text
        .substring(lineStart, lineEnd < 0 ? text.length : lineEnd)
        .trimLeft();
    final lineLower = line.toLowerCase();

    if (lineLower.startsWith('<?xml')) return true;
    if (lineLower.startsWith('<!doctype')) return true;
    if (RegExp(r'\bxmlns(?::[\w.-]+)?\s*=', caseSensitive: false)
        .hasMatch(line)) {
      return true;
    }
    if (lineLower.contains('public "-//apple//dtd')) return true;

    return false;
  }

  /// Known FlutterFire / Firebase *client* config files only — not a global
  /// apiKey exception.
  bool _isKnownFirebaseClientConfigFile(String relativePath, String text) {
    final base = relativePath.split('/').last;
    if (base == 'google-services.json' || base == 'GoogleService-Info.plist') {
      return true;
    }
    if (base == 'firebase_options.dart' && text.contains('FirebaseOptions(')) {
      return true;
    }
    return false;
  }

  int? _firebaseClientEvidenceLine(String relativePath, String text) {
    final base = relativePath.split('/').last;
    if (base == 'firebase_options.dart') {
      final match = RegExp(r'FirebaseOptions\s*\(').firstMatch(text);
      if (match != null) return Evidence.lineOfOffset(text, match.start);
    }
    if (base == 'google-services.json') {
      final match = RegExp(r'"project_info"|"client"', caseSensitive: false)
          .firstMatch(text);
      if (match != null) return Evidence.lineOfOffset(text, match.start);
    }
    if (base == 'GoogleService-Info.plist') {
      final match =
          RegExp(r'GOOGLE_APP_ID|GCM_SENDER_ID|API_KEY').firstMatch(text);
      if (match != null) return Evidence.lineOfOffset(text, match.start);
    }
    return 1;
  }

  /// Exclude only Firebase client-config contexts from hard-coded-secret.
  bool _isFirebaseClientConfigSecret(
    String relativePath,
    String text,
    RegExpMatch match,
  ) {
    final base = relativePath.split('/').last;
    if (base == 'google-services.json' || base == 'GoogleService-Info.plist') {
      return true;
    }
    if (base != 'firebase_options.dart') return false;

    final matched = match.group(0)!.toLowerCase();
    final looksLikeApiKey = matched.contains('apikey') ||
        matched.contains('api_key') ||
        matched.contains('api-key');
    if (!looksLikeApiKey) return false;
    return _isInsideFirebaseOptionsCall(text, match.start);
  }

  bool _isInsideFirebaseOptionsCall(String text, int offset) {
    final before = text.substring(0, offset);
    final start = before.lastIndexOf('FirebaseOptions(');
    if (start < 0) return false;

    var depth = 0;
    for (var i = start + 'FirebaseOptions'.length; i < offset; i++) {
      final c = text.codeUnitAt(i);
      if (c == 0x28) {
        // (
        depth++;
      } else if (c == 0x29) {
        // )
        depth--;
        if (depth == 0) return false;
      }
    }
    return depth > 0;
  }

  String? _hostOfUrl(String url) {
    final match =
        RegExp(r'https?://([^/?:#]+)', caseSensitive: false).firstMatch(url);
    return match?.group(1)?.toLowerCase();
  }

  String _path(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}
