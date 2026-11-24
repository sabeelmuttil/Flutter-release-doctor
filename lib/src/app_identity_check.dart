import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';

/// Compares each platform's app ID against that platform's Firebase config.
class AppIdentityCheck {
  Future<void> run(Directory project, List<Finding> findings) async {
    await _checkAndroid(project, findings);
    await _checkIos(project, findings);
  }

  Future<void> _checkAndroid(Directory project, List<Finding> findings) async {
    final androidDir = Directory(_join(project, 'android'));
    if (!await androidDir.exists()) return;

    final appIdResult = await _resolveAndroidAppId(project);
    final firebaseFile =
        File(_join(project, 'android/app/google-services.json'));
    final firebaseExists = await firebaseFile.exists();

    if (!firebaseExists) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android Firebase config',
          'android/ exists but android/app/google-services.json is missing.',
          fix:
              'Add google-services.json for this Android app/environment, or ignore if Firebase is unused.',
        ),
      );
    }

    if (appIdResult.unresolvedReason != null) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android app ID',
          appIdResult.unresolvedReason!,
        ),
      );
    }

    if (!firebaseExists) return;

    final firebasePackages = await _readAndroidFirebasePackages(firebaseFile);
    if (firebasePackages.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android Firebase package',
          'Could not resolve package_name from android/app/google-services.json.',
          fix:
              'Confirm the file contains client_info.android_client_info.package_name.',
        ),
      );
      return;
    }

    final appId = appIdResult.value;
    if (appId == null) return;

    if (firebasePackages.contains(appId)) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Android app identity',
          'Application ID `$appId` matches Firebase package `$appId`.',
        ),
      );
    } else {
      final firebaseLabel = firebasePackages.join(', ');
      findings.add(
        Finding(
          FindingLevel.error,
          'Android app identity',
          'Application ID `$appId` does not match Firebase package `$firebaseLabel`.',
          fix:
              'Download google-services.json for the correct Android app/environment from Firebase Console.',
        ),
      );
    }
  }

  Future<void> _checkIos(Directory project, List<Finding> findings) async {
    final iosDir = Directory(_join(project, 'ios'));
    if (!await iosDir.exists()) return;

    final bundleResult = await _resolveIosBundleId(project);
    final firebaseFile =
        File(_join(project, 'ios/Runner/GoogleService-Info.plist'));
    final firebaseExists = await firebaseFile.exists();

    if (!firebaseExists) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS Firebase config',
          'ios/ exists but ios/Runner/GoogleService-Info.plist is missing.',
          fix:
              'Add GoogleService-Info.plist for this iOS app/environment, or ignore if Firebase is unused.',
        ),
      );
    }

    if (bundleResult.unresolvedReason != null) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'iOS bundle ID',
          bundleResult.unresolvedReason!,
        ),
      );
    }

    if (!firebaseExists) return;

    final firebaseBundle = await _readIosFirebaseBundleId(firebaseFile);
    if (firebaseBundle == null) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS Firebase bundle ID',
          'Could not resolve BUNDLE_ID from ios/Runner/GoogleService-Info.plist.',
          fix: 'Confirm the plist contains a BUNDLE_ID string value.',
        ),
      );
      return;
    }

    final bundleId = bundleResult.value;
    if (bundleId == null) return;

    if (bundleId == firebaseBundle) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'iOS app identity',
          'Bundle ID `$bundleId` matches Firebase BUNDLE_ID `$firebaseBundle`.',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.error,
          'iOS app identity',
          'Bundle ID `$bundleId` does not match Firebase BUNDLE_ID `$firebaseBundle`.',
          fix:
              'Download GoogleService-Info.plist for the correct iOS app/environment from Firebase Console.',
        ),
      );
    }
  }

  Future<_ResolvedId> _resolveAndroidAppId(Directory project) async {
    final groovy = File(_join(project, 'android/app/build.gradle'));
    final kts = File(_join(project, 'android/app/build.gradle.kts'));
    File? gradle;
    if (await groovy.exists()) {
      gradle = groovy;
    } else if (await kts.exists()) {
      gradle = kts;
    }

    if (gradle != null) {
      final text = await gradle.readAsString();
      final fileName = gradle.uri.pathSegments.last;
      final quoted = _firstQuotedGradleAssignment(text, 'applicationId');
      if (quoted != null) {
        if (_looksLikeVariable(quoted)) {
          return _ResolvedId.unresolved(
            'Could not resolve Android applicationId from $fileName: value uses a variable or unsupported structure (`$quoted`).',
          );
        }
        return _ResolvedId.resolved(quoted);
      }
      final bare = _firstBareGradleAssignment(text, 'applicationId');
      if (bare != null) {
        return _ResolvedId.unresolved(
          'Could not resolve Android applicationId from $fileName: value uses a variable or unsupported structure (`$bare`).',
        );
      }
    }

    final manifest = File(
      _join(project, 'android/app/src/main/AndroidManifest.xml'),
    );
    if (await manifest.exists()) {
      final text = await manifest.readAsString();
      final packageMatch =
          RegExp(r'''package\s*=\s*["']([^"']+)["']''').firstMatch(text);
      if (packageMatch != null) {
        final packageName = packageMatch.group(1)!;
        if (_looksLikeVariable(packageName)) {
          return const _ResolvedId.unresolved(
            'Could not resolve Android package name from AndroidManifest.xml: value uses a variable or unsupported structure.',
          );
        }
        return _ResolvedId.resolved(packageName);
      }
    }

    if (gradle != null) {
      return _ResolvedId.unresolved(
        'Could not resolve Android applicationId from ${gradle.uri.pathSegments.last}: applicationId was not found or uses an unsupported structure.',
      );
    }

    return const _ResolvedId.unresolved(
      'Could not resolve Android application ID: neither android/app/build.gradle(.kts) applicationId nor AndroidManifest package was found.',
    );
  }

  Future<_ResolvedId> _resolveIosBundleId(Directory project) async {
    final plist = File(_join(project, 'ios/Runner/Info.plist'));
    if (!await plist.exists()) {
      return const _ResolvedId.unresolved(
        'Could not resolve iOS bundle ID: ios/Runner/Info.plist was not found.',
      );
    }

    final plistText = await plist.readAsString();
    final raw = _plistStringValue(plistText, 'CFBundleIdentifier');
    if (raw == null) {
      return const _ResolvedId.unresolved(
        'Could not resolve iOS bundle ID: CFBundleIdentifier was not found in Info.plist.',
      );
    }

    if (raw == r'$(PRODUCT_BUNDLE_IDENTIFIER)') {
      return _resolveProductBundleIdentifier(project);
    }

    if (_looksLikeVariable(raw)) {
      return _ResolvedId.unresolved(
        'Could not resolve iOS bundle ID from Info.plist: value uses a variable or unsupported structure (`$raw`).',
      );
    }

    return _ResolvedId.resolved(raw);
  }

  Future<_ResolvedId> _resolveProductBundleIdentifier(
    Directory project,
  ) async {
    final pbxproj =
        File(_join(project, 'ios/Runner.xcodeproj/project.pbxproj'));
    if (!await pbxproj.exists()) {
      return const _ResolvedId.unresolved(
        'Could not resolve PRODUCT_BUNDLE_IDENTIFIER: ios/Runner.xcodeproj/project.pbxproj was not found.',
      );
    }

    final text = await pbxproj.readAsString();
    final matches = RegExp(
      r'PRODUCT_BUNDLE_IDENTIFIER\s*=\s*([^;]+);',
    ).allMatches(text);

    final values = <String>{};
    for (final match in matches) {
      final value = match.group(1)!.trim().replaceAll('"', '');
      if (value.endsWith('Tests') || value.endsWith('UITests')) continue;
      if (_looksLikeVariable(value)) continue;
      values.add(value);
    }

    if (values.isEmpty) {
      return const _ResolvedId.unresolved(
        'Could not resolve PRODUCT_BUNDLE_IDENTIFIER from project.pbxproj: value uses a variable or unsupported structure.',
      );
    }

    if (values.length > 1) {
      return _ResolvedId.unresolved(
        'Could not resolve PRODUCT_BUNDLE_IDENTIFIER from project.pbxproj: multiple distinct values found (${values.join(', ')}).',
      );
    }

    return _ResolvedId.resolved(values.single);
  }

  Future<Set<String>> _readAndroidFirebasePackages(File file) async {
    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map) return {};
      final clients = decoded['client'];
      if (clients is! List) return {};
      final packages = <String>{};
      for (final client in clients) {
        if (client is! Map) continue;
        final clientInfo = client['client_info'];
        if (clientInfo is! Map) continue;
        final androidInfo = clientInfo['android_client_info'];
        if (androidInfo is! Map) continue;
        final packageName = androidInfo['package_name'];
        if (packageName is String && packageName.isNotEmpty) {
          packages.add(packageName);
        }
      }
      return packages;
    } catch (_) {
      return {};
    }
  }

  Future<String?> _readIosFirebaseBundleId(File file) async {
    try {
      final text = await file.readAsString();
      return _plistStringValue(text, 'BUNDLE_ID');
    } catch (_) {
      return null;
    }
  }

  String? _plistStringValue(String plist, String key) {
    final match = RegExp(
      '<key>$key</key>\\s*<string>([^<]*)</string>',
      multiLine: true,
    ).firstMatch(plist);
    final value = match?.group(1)?.trim();
    if (value == null || value.isEmpty) return null;
    return value;
  }

  String? _firstQuotedGradleAssignment(String text, String key) {
    final patterns = [
      RegExp('$key\\s+"([^"]+)"'),
      RegExp("$key\\s+'([^']+)'"),
      RegExp('$key\\s*=\\s*"([^"]+)"'),
      RegExp("$key\\s*=\\s*'([^']+)'"),
    ];
    for (final pattern in patterns) {
      final match = pattern.firstMatch(text);
      if (match != null) return match.group(1);
    }
    return null;
  }

  String? _firstBareGradleAssignment(String text, String key) {
    final bare = RegExp('$key\\s*=\\s*([^\\s\\n/#]+)').firstMatch(text);
    return bare?.group(1);
  }

  bool _looksLikeVariable(String value) {
    final trimmed = value.trim();
    return trimmed.contains(r'$(') ||
        trimmed.contains(r'${') ||
        trimmed.startsWith('\$');
  }

  String _join(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}

class _ResolvedId {
  const _ResolvedId.resolved(this.value) : unresolvedReason = null;
  const _ResolvedId.unresolved(this.unresolvedReason) : value = null;

  final String? value;
  final String? unresolvedReason;
}
