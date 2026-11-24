import 'dart:io';

import 'package:flutter_release_doctor/src/evidence.dart';
import 'package:flutter_release_doctor/src/finding.dart';

/// Deep link (App Links / Universal Links / URL schemes) and push readiness.
///
/// Never makes network calls and never reports tokens, keys, APNs IDs, or
/// Firebase secrets.
class DeepLinkPushCheck {
  Future<void> run(Directory project, List<Finding> findings) async {
    await _checkAndroidDeepLinks(project, findings);
    await _checkIosDeepLinks(project, findings);
    await _checkPush(project, findings);
  }

  Future<void> _checkAndroidDeepLinks(
    Directory project,
    List<Finding> findings,
  ) async {
    final androidDir = Directory(_join(project, 'android'));
    if (!await androidDir.exists()) return;

    final manifest = File(
      _join(project, 'android/app/src/main/AndroidManifest.xml'),
    );
    if (!await manifest.exists()) return;

    final text = await manifest.readAsString();
    final relative = Evidence.relativePath(project, manifest);
    final filters = _androidViewBrowsableFilters(text);
    if (filters.isEmpty) return;

    var httpsPass = false;
    var customSchemePass = false;
    final customSchemes = <String>{};

    for (final filter in filters) {
      // HTTPS App Links only when a data tag explicitly sets scheme="https".
      final httpsEntries =
          filter.data.where((d) => d.scheme?.toLowerCase() == 'https').toList();
      if (httpsEntries.isNotEmpty) {
        final concreteHosts = httpsEntries
            .map((d) => d.host)
            .whereType<String>()
            .where((h) => h.isNotEmpty && !_isPlaceholder(h))
            .toList();
        final line = Evidence.lineOfOffset(text, filter.start);
        if (concreteHosts.isEmpty) {
          findings.add(
            Finding(
              FindingLevel.warning,
              'Android App Links host',
              'An HTTPS app-link intent filter has no host or uses an unresolved placeholder.',
              id: 'android-app-links-host',
              file: relative,
              line: line,
              fix:
                  'Set a concrete android:host on the HTTPS VIEW/BROWSABLE intent filter.',
            ),
          );
        } else if (!filter.autoVerify) {
          findings.add(
            Finding(
              FindingLevel.warning,
              'Android App Links autoVerify',
              'An HTTPS deep-link intent filter is present but android:autoVerify="true" is missing.',
              id: 'android-app-links-autoverify',
              file: relative,
              line: line,
              fix:
                  'Add android:autoVerify="true" for Android App Links verification.',
            ),
          );
        } else {
          httpsPass = true;
        }
      }

      for (final data in filter.data) {
        final scheme = data.scheme;
        if (scheme == null || scheme.isEmpty) continue;
        final lower = scheme.toLowerCase();
        if (lower == 'http' || lower == 'https') continue;
        final line = Evidence.lineOfOffset(text, filter.start);
        if (_isPlaceholder(scheme) || _looksLikeVariableScheme(scheme)) {
          findings.add(
            Finding(
              FindingLevel.warning,
              'Android custom URL scheme',
              'A custom URL scheme intent filter uses an unresolved placeholder.',
              id: 'android-custom-url-scheme',
              file: relative,
              line: line,
              classification: 'unresolved-scheme',
              fix: 'Replace placeholder schemes with a concrete scheme name.',
            ),
          );
          continue;
        }
        customSchemes.add(scheme);
        customSchemePass = true;
      }
    }

    if (httpsPass) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Android App Links',
          'HTTPS app-link intent filter found with android:autoVerify="true" and a host.',
          id: 'android-app-links',
          file: relative,
        ),
      );
    }

    if (customSchemePass && customSchemes.isNotEmpty) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Android custom URL scheme',
          'Custom URL scheme deep link configured: ${customSchemes.join(', ')}.',
          id: 'android-custom-url-scheme',
          file: relative,
        ),
      );
    }
  }

  Future<void> _checkIosDeepLinks(
    Directory project,
    List<Finding> findings,
  ) async {
    final iosDir = Directory(_join(project, 'ios'));
    if (!await iosDir.exists()) return;

    final infoPlistFile = File(_join(project, 'ios/Runner/Info.plist'));
    final schemes = await _iosUrlSchemes(project);
    final entitlementsText = await _readEntitlements(project);
    final associated = _associatedDomains(entitlementsText);

    if (schemes.isNotEmpty) {
      final empty = schemes.where((s) => s.trim().isEmpty).isNotEmpty;
      final nonEmpty = schemes.where((s) => s.trim().isNotEmpty).toList();
      final unresolved = nonEmpty
          .where(_looksLikeVariableScheme)
          .map(_redactScheme)
          .toSet()
          .toList();
      final concrete =
          nonEmpty.where((s) => !_looksLikeVariableScheme(s)).toList();
      final duplicates = <String>{};
      final seen = <String>{};
      for (final scheme in concrete) {
        final key = scheme.toLowerCase();
        if (!seen.add(key)) duplicates.add(scheme);
      }

      String? plistRel;
      int? plistLine;
      if (await infoPlistFile.exists()) {
        plistRel = Evidence.relativePath(project, infoPlistFile);
        final text = await infoPlistFile.readAsString();
        final idx = text.indexOf('CFBundleURLSchemes');
        if (idx >= 0) plistLine = Evidence.lineOfOffset(text, idx);
      }

      if (empty || duplicates.isNotEmpty || unresolved.isNotEmpty) {
        final parts = <String>[
          if (empty) 'one or more URL schemes are empty',
          if (duplicates.isNotEmpty)
            'duplicated scheme(s): ${duplicates.join(', ')}',
          if (unresolved.isNotEmpty)
            'unresolved variable scheme(s): ${unresolved.join(', ')}',
        ];
        findings.add(
          Finding(
            FindingLevel.warning,
            'iOS custom URL scheme',
            'CFBundleURLTypes issue: ${parts.join('; ')}.',
            id: 'ios-custom-url-scheme',
            file: plistRel,
            line: plistLine,
            classification: unresolved.isNotEmpty ? 'unresolved-scheme' : null,
            fix:
                'Use unique, non-empty, fully resolved URL schemes in Info.plist CFBundleURLTypes.',
          ),
        );
      } else {
        findings.add(
          Finding(
            FindingLevel.passed,
            'iOS custom URL scheme',
            'Custom URL scheme(s) configured: ${concrete.join(', ')}.',
            id: 'ios-custom-url-scheme',
            file: plistRel,
            line: plistLine,
          ),
        );
      }
    }

    final applinks = associated
        .where((d) => d.toLowerCase().startsWith('applinks:'))
        .toList();
    if (applinks.isNotEmpty) {
      final unresolved = applinks.any((d) => _isPlaceholder(d));
      if (unresolved) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'iOS associated domains',
            'Associated domains include applinks entries that look unresolved or use placeholders.',
            id: 'ios-associated-domains',
            fix:
                'Set concrete applinks: domains in Runner entitlements (domain values only; no secrets).',
          ),
        );
      } else {
        final domains = applinks
            .map((d) => d.substring(d.indexOf(':') + 1))
            .where((d) => d.isNotEmpty)
            .toList();
        findings.add(
          Finding(
            FindingLevel.passed,
            'iOS associated domains',
            'Associated domains include applinks: ${domains.join(', ')}.',
            id: 'ios-associated-domains',
          ),
        );
      }
    } else if (_hasConcreteUniversalLinkEvidence(entitlementsText)) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS associated domains',
          'Universal Links evidence was found, but no concrete applinks: domain is configured.',
          id: 'ios-associated-domains',
          fix:
              'Add com.apple.developer.associated-domains with at least one applinks: entry in Runner entitlements.',
        ),
      );
    }
  }

  Future<void> _checkPush(Directory project, List<Finding> findings) async {
    final messaging = await _detectFirebaseMessaging(project);
    if (!messaging) return;

    final hasAndroid = await Directory(_join(project, 'android')).exists();
    final hasIos = await Directory(_join(project, 'ios')).exists();

    var androidOk = !hasAndroid;
    var iosOk = !hasIos;

    if (hasAndroid) {
      final modernTarget = await _androidTargetLooksModern(project);
      final manifest = File(
        _join(project, 'android/app/src/main/AndroidManifest.xml'),
      );
      final declared = await manifest.exists() &&
          (await manifest.readAsString())
              .contains('android.permission.POST_NOTIFICATIONS');

      if (modernTarget && !declared) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'Android push notifications',
            'Firebase Messaging is detected but android.permission.POST_NOTIFICATIONS is absent for a modern Android target.',
            id: 'android-push-notifications',
            fix:
                'Declare POST_NOTIFICATIONS when using FCM on Android 13+ targets.',
          ),
        );
      } else if (declared || !modernTarget) {
        androidOk = true;
        findings.add(
          Finding(
            FindingLevel.passed,
            'Android push notifications',
            declared
                ? 'Firebase Messaging detected and POST_NOTIFICATIONS is declared.'
                : 'Firebase Messaging detected; POST_NOTIFICATIONS not required for the resolved older targetSdk.',
            id: 'android-push-notifications',
          ),
        );
      } else {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'Android push notifications',
            'Firebase Messaging is detected but notification permission setup could not be fully verified.',
            id: 'android-push-notifications',
          ),
        );
      }
    }

    if (hasIos) {
      final entitlements = await _readEntitlements(project);
      final hasAps =
          entitlements != null && entitlements.contains('aps-environment');
      if (!hasAps) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'iOS push notifications',
            'Firebase Messaging is detected but aps-environment is missing from Runner entitlements.',
            id: 'ios-push-notifications',
            fix:
                'Enable Push Notifications and ensure Runner.entitlements defines aps-environment.',
          ),
        );
      } else {
        iosOk = true;
        findings.add(
          const Finding(
            FindingLevel.passed,
            'iOS push notifications',
            'Firebase Messaging detected and aps-environment is present in Runner entitlements.',
            id: 'ios-push-notifications',
          ),
        );
      }
    }

    if (androidOk && iosOk && (hasAndroid || hasIos)) {
      // Per-platform PASS findings already added when setup is complete.
    }
  }

  List<_IntentFilter> _androidViewBrowsableFilters(String manifest) {
    final filters = <_IntentFilter>[];
    final filterRegex = RegExp(
      r'<intent-filter\b([^>]*)>([\s\S]*?)</intent-filter>',
      caseSensitive: false,
    );
    for (final match in filterRegex.allMatches(manifest)) {
      final attrs = match.group(1) ?? '';
      final body = match.group(2) ?? '';
      final actions = RegExp(
        r'''<action\b[^>]*android:name\s*=\s*["']([^"']+)["']''',
        caseSensitive: false,
      ).allMatches(body).map((m) => m.group(1)!).toSet();
      final categories = RegExp(
        r'''<category\b[^>]*android:name\s*=\s*["']([^"']+)["']''',
        caseSensitive: false,
      ).allMatches(body).map((m) => m.group(1)!).toSet();

      final hasView = actions.any((a) => a.endsWith('.action.VIEW'));
      final hasBrowsable =
          categories.any((c) => c.endsWith('.category.BROWSABLE'));
      final hasDefault = categories.any((c) => c.endsWith('.category.DEFAULT'));
      if (!hasView || !hasBrowsable || !hasDefault) continue;

      final autoVerify = RegExp(
        r'''android:autoVerify\s*=\s*["']true["']''',
        caseSensitive: false,
      ).hasMatch(attrs);

      final data = <_DataTag>[];
      for (final dataMatch in RegExp(
        r'<data\b([^>]*)/?>',
        caseSensitive: false,
      ).allMatches(body)) {
        final dataAttrs = dataMatch.group(1) ?? '';
        data.add(
          _DataTag(
            scheme: _androidAttr(dataAttrs, 'scheme'),
            host: _androidAttr(dataAttrs, 'host'),
          ),
        );
      }
      filters.add(
        _IntentFilter(
          autoVerify: autoVerify,
          data: data,
          start: match.start,
        ),
      );
    }
    return filters;
  }

  String? _androidAttr(String attrs, String name) {
    return RegExp(
      '''android:$name\\s*=\\s*["']([^"']*)["']''',
      caseSensitive: false,
    ).firstMatch(attrs)?.group(1);
  }

  Future<List<String>> _iosUrlSchemes(Directory project) async {
    final plist = File(_join(project, 'ios/Runner/Info.plist'));
    if (!await plist.exists()) return const [];
    final text = await plist.readAsString();
    if (!text.contains('CFBundleURLTypes')) return const [];

    final schemes = <String>[];
    // Match CFBundleURLSchemes arrays directly (nested inside CFBundleURLTypes).
    for (final match in RegExp(
      r'<key>CFBundleURLSchemes</key>\s*<array>([\s\S]*?)</array>',
      caseSensitive: false,
    ).allMatches(text)) {
      final arrayBody = match.group(1)!;
      final strings = RegExp(
        r'<string>([^<]*)</string>',
      ).allMatches(arrayBody).map((m) => m.group(1) ?? '').toList();
      if (strings.isEmpty) {
        schemes.add('');
      } else {
        schemes.addAll(strings);
      }
    }
    return schemes;
  }

  Future<String?> _readEntitlements(Directory project) async {
    final candidates = [
      File(_join(project, 'ios/Runner/Runner.entitlements')),
      File(_join(project, 'ios/Runner/RunnerDebug.entitlements')),
      File(_join(project, 'ios/Runner/RunnerRelease.entitlements')),
    ];
    final chunks = <String>[];
    for (final file in candidates) {
      if (await file.exists()) chunks.add(await file.readAsString());
    }

    final pbxproj =
        File(_join(project, 'ios/Runner.xcodeproj/project.pbxproj'));
    if (await pbxproj.exists()) {
      final text = await pbxproj.readAsString();
      for (final match in RegExp(
        r'CODE_SIGN_ENTITLEMENTS\s*=\s*([^;]+);',
      ).allMatches(text)) {
        final relative = match.group(1)!.trim().replaceAll('"', '');
        if (relative.isEmpty || _isPlaceholder(relative)) continue;
        final path = relative.startsWith('ios/') ? relative : 'ios/$relative';
        final file = File(_join(project, path));
        if (await file.exists()) chunks.add(await file.readAsString());
      }
    }

    if (chunks.isEmpty) return null;
    return chunks.join('\n');
  }

  List<String> _associatedDomains(String? entitlements) {
    if (entitlements == null) return const [];
    final match = RegExp(
      r'<key>com\.apple\.developer\.associated-domains</key>\s*<array>([\s\S]*?)</array>',
      caseSensitive: false,
    ).firstMatch(entitlements);
    if (match == null) return const [];
    return RegExp(r'<string>([^<]*)</string>')
        .allMatches(match.group(1)!)
        .map((m) => m.group(1)!.trim())
        .where((s) => s.isNotEmpty)
        .toList();
  }

  /// Concrete Universal Links evidence only — not arbitrary URL schemes.
  bool _hasConcreteUniversalLinkEvidence(String? entitlements) {
    if (entitlements == null) return false;
    if (entitlements.contains('com.apple.developer.associated-domains')) {
      return true;
    }
    if (RegExp(r'applinks:', caseSensitive: false).hasMatch(entitlements)) {
      return true;
    }
    return false;
  }

  bool _looksLikeVariableScheme(String scheme) {
    return scheme.contains(r'$(') ||
        scheme.contains(r'${') ||
        _isPlaceholder(scheme);
  }

  /// Avoid echoing unresolved variable bodies that may include sensitive keys.
  String _redactScheme(String scheme) {
    if (scheme.contains('REVERSED_CLIENT_ID') ||
        scheme.contains('CLIENT_ID') ||
        scheme.contains('API_KEY')) {
      return '[unresolved-variable-scheme]';
    }
    if (_looksLikeVariableScheme(scheme)) {
      // Keep structural hint without expanding values.
      return scheme.replaceAll(RegExp(r'\$\([^)]+\)'), r'$(…)');
    }
    return scheme;
  }

  Future<bool> _detectFirebaseMessaging(Directory project) async {
    final pubspec = File(_join(project, 'pubspec.yaml'));
    if (await pubspec.exists()) {
      final text = (await pubspec.readAsString()).toLowerCase();
      if (text.contains('firebase_messaging')) return true;
    }

    for (final relative in [
      'android/app/build.gradle',
      'android/app/build.gradle.kts',
      'android/build.gradle',
      'android/build.gradle.kts',
    ]) {
      final file = File(_join(project, relative));
      if (!await file.exists()) continue;
      final text = await file.readAsString();
      if (RegExp(
        r'firebase[_-]messaging|com\.google\.firebase:firebase-messaging',
        caseSensitive: false,
      ).hasMatch(text)) {
        return true;
      }
    }

    final iosRunner = Directory(_join(project, 'ios/Runner'));
    if (await iosRunner.exists()) {
      await for (final entity
          in iosRunner.list(followLinks: false, recursive: false)) {
        if (entity is! File) continue;
        final name = entity.uri.pathSegments.last.toLowerCase();
        if (name.endsWith('.entitlements') || name.endsWith('.plist')) {
          final text = await entity.readAsString();
          if (text.contains('FIREBASE_MESSAGING') ||
              text.contains('firebase_messaging')) {
            return true;
          }
        }
      }
    }

    final podfile = File(_join(project, 'ios/Podfile'));
    if (await podfile.exists()) {
      final text = await podfile.readAsString();
      if (RegExp(
        r'FirebaseMessaging|firebase_messaging',
        caseSensitive: false,
      ).hasMatch(text)) {
        return true;
      }
    }

    return false;
  }

  Future<bool> _androidTargetLooksModern(Directory project) async {
    for (final relative in [
      'android/app/build.gradle',
      'android/app/build.gradle.kts',
    ]) {
      final file = File(_join(project, relative));
      if (!await file.exists()) continue;
      final text = await file.readAsString();
      final match = RegExp(
        r'''(?:targetSdk|targetSdkVersion)\s*=?\s*(\d+)''',
      ).firstMatch(text);
      if (match != null) {
        return int.parse(match.group(1)!) >= 33;
      }
      // Unresolved flutter.targetSdkVersion → assume modern Flutter defaults.
      if (RegExp(
        r'targetSdk(?:Version)?\s*=?\s*flutter\.targetSdkVersion',
      ).hasMatch(text)) {
        return true;
      }
    }
    // No target found but Android project exists with FCM → treat as modern.
    return true;
  }

  bool _isPlaceholder(String value) {
    final trimmed = value.trim();
    return trimmed.contains(r'${') ||
        trimmed.contains(r'$(') ||
        trimmed.contains('YOUR_') ||
        trimmed == '*' ||
        trimmed.isEmpty;
  }

  String _join(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}

class _IntentFilter {
  const _IntentFilter({
    required this.autoVerify,
    required this.data,
    required this.start,
  });

  final bool autoVerify;
  final List<_DataTag> data;
  final int start;
}

class _DataTag {
  const _DataTag({this.scheme, this.host});

  final String? scheme;
  final String? host;
}
