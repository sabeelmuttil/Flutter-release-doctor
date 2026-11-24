import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';

/// Android/iOS platform compatibility and store-readiness checks.
class PlatformCompatibilityCheck {
  /// API levels below this are treated as clearly obsolete for store apps.
  /// This is intentionally far below current Play requirements and is not a
  /// "latest SDK" recommendation.
  static const _clearlyOldTargetSdk = 21;

  static const _privacyUsageKeys = <String>[
    'NSCameraUsageDescription',
    'NSMicrophoneUsageDescription',
    'NSPhotoLibraryUsageDescription',
    'NSPhotoLibraryAddUsageDescription',
    'NSLocationWhenInUseUsageDescription',
    'NSLocationAlwaysAndWhenInUseUsageDescription',
    'NSLocationAlwaysUsageDescription',
    'NSContactsUsageDescription',
    'NSBluetoothAlwaysUsageDescription',
    'NSBluetoothPeripheralUsageDescription',
    'NSUserTrackingUsageDescription',
    'NSFaceIDUsageDescription',
    'NSMotionUsageDescription',
    'NSHealthShareUsageDescription',
    'NSHealthUpdateUsageDescription',
  ];

  Future<void> run(Directory project, List<Finding> findings) async {
    await _checkAndroid(project, findings);
    await _checkIos(project, findings);
  }

  Future<void> _checkAndroid(
    Directory project,
    List<Finding> findings,
  ) async {
    final androidDir = Directory(_join(project, 'android'));
    if (!await androidDir.exists()) return;

    final gradle = await _androidAppGradle(project);
    if (gradle == null) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android SDK levels',
          'Android folder exists but app Gradle file was not found; minSdk/targetSdk/compileSdk cannot be resolved.',
          id: 'android-sdk-levels',
        ),
      );
      return;
    }

    final text = await gradle.readAsString();
    final symbols = await _loadAndroidSdkSymbols(project, text);

    final minSdk = _resolveSdkValue(
      text,
      const ['minSdk', 'minSdkVersion'],
      symbols,
    );
    final targetSdk = _resolveSdkValue(
      text,
      const ['targetSdk', 'targetSdkVersion'],
      symbols,
    );
    final compileSdk = _resolveSdkValue(
      text,
      const ['compileSdk', 'compileSdkVersion'],
      symbols,
    );

    final unresolved = <String>[
      if (minSdk == null) 'minSdk',
      if (targetSdk == null) 'targetSdk',
      if (compileSdk == null) 'compileSdk',
    ];

    if (unresolved.isNotEmpty) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android SDK levels',
          'Could not resolve ${unresolved.join(', ')} from ${gradle.uri.pathSegments.last}'
              '${_resolvedSummary(minSdk, targetSdk, compileSdk)}.',
          id: 'android-sdk-levels',
          fix:
              'Set numeric minSdk, targetSdk, and compileSdk (or resolvable flutter.* / ext values) in the app Gradle file.',
        ),
      );
    } else if (minSdk! <= targetSdk! && targetSdk <= compileSdk!) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Android SDK levels',
          'Resolved minSdk=$minSdk, targetSdk=$targetSdk, compileSdk=$compileSdk with valid ordering.',
          id: 'android-sdk-levels',
        ),
      );
    } else {
      findings.add(
        Finding(
          FindingLevel.error,
          'Android SDK levels',
          'Invalid SDK ordering: minSdk=$minSdk, targetSdk=$targetSdk, compileSdk=$compileSdk (expected minSdk ≤ targetSdk ≤ compileSdk).',
          id: 'android-sdk-levels',
          fix:
              'Raise targetSdk/compileSdk or lower minSdk so minSdk ≤ targetSdk ≤ compileSdk.',
        ),
      );
    }

    if (targetSdk == null) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android targetSdk',
          'targetSdk is missing and could not be resolved.',
          id: 'android-target-sdk',
          fix: 'Set targetSdk explicitly for store builds.',
        ),
      );
    } else if (targetSdk < _clearlyOldTargetSdk) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android targetSdk',
          'Discovered targetSdk=$targetSdk, which is clearly old for a modern store release.',
          id: 'android-target-sdk',
          fix:
              'Review and update targetSdk for current Play store expectations (Release Doctor does not prescribe a specific latest value).',
        ),
      );
    }

    await _checkCleartext(project, findings);
    await _checkPostNotifications(project, text, findings);
  }

  Future<void> _checkCleartext(
    Directory project,
    List<Finding> findings,
  ) async {
    final manifest = File(
      _join(project, 'android/app/src/main/AndroidManifest.xml'),
    );
    if (!await manifest.exists()) return;
    final text = await manifest.readAsString();
    if (RegExp(
      r'''android:usesCleartextTraffic\s*=\s*["']true["']''',
      caseSensitive: false,
    ).hasMatch(text)) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android cleartext traffic',
          'AndroidManifest sets android:usesCleartextTraffic="true".',
          id: 'android-cleartext-traffic',
          fix:
              'Disable cleartext traffic for release builds unless HTTP is intentionally required.',
        ),
      );
    }
  }

  Future<void> _checkPostNotifications(
    Directory project,
    String gradleText,
    List<Finding> findings,
  ) async {
    final notificationsLikely = await _hasNotificationFirebaseSignal(
      project,
      gradleText,
    );
    if (!notificationsLikely) return;

    final manifest = File(
      _join(project, 'android/app/src/main/AndroidManifest.xml'),
    );
    if (!await manifest.exists()) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android POST_NOTIFICATIONS',
          'Notification-related Firebase dependency/config appears present, but AndroidManifest.xml was not found to verify POST_NOTIFICATIONS.',
          id: 'android-post-notifications',
        ),
      );
      return;
    }

    final text = await manifest.readAsString();
    final declared = text.contains('android.permission.POST_NOTIFICATIONS');
    if (!declared) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android POST_NOTIFICATIONS',
          'Notification-related Firebase dependency/config is present, but android.permission.POST_NOTIFICATIONS is not declared.',
          id: 'android-post-notifications',
          fix:
              'Declare POST_NOTIFICATIONS when targeting modern Android if the app shows notifications.',
        ),
      );
    }
  }

  Future<bool> _hasNotificationFirebaseSignal(
    Directory project,
    String gradleText,
  ) async {
    final pubspec = File(_join(project, 'pubspec.yaml'));
    if (await pubspec.exists()) {
      final text = (await pubspec.readAsString()).toLowerCase();
      if (text.contains('firebase_messaging') ||
          text.contains('flutter_local_notifications') ||
          text.contains('awesome_notifications')) {
        return true;
      }
    }

    if (RegExp(
      r'firebase[-_]messaging|com\.google\.firebase:firebase-messaging',
      caseSensitive: false,
    ).hasMatch(gradleText)) {
      return true;
    }

    final googleServices =
        File(_join(project, 'android/app/google-services.json'));
    if (await googleServices.exists()) {
      final text = await googleServices.readAsString();
      if (text.contains('"messaging_service"') ||
          text.contains('firebase_messaging') ||
          text.contains('"gcm"') ||
          RegExp(r'"mobilesdk_app_id"').hasMatch(text)) {
        // google-services.json alone is weak; require messaging-ish content or
        // companion iOS plist with GCM/FCM markers plus messaging dependency.
        // Treat presence of google-services + any fcm/gcm client service as signal.
        if (text.contains('fcm') ||
            text.contains('gcm') ||
            text.contains('messaging')) {
          return true;
        }
      }
    }
    return false;
  }

  Future<void> _checkIos(Directory project, List<Finding> findings) async {
    final iosDir = Directory(_join(project, 'ios'));
    if (!await iosDir.exists()) return;

    final pbxproj =
        File(_join(project, 'ios/Runner.xcodeproj/project.pbxproj'));
    if (!await pbxproj.exists()) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS deployment target',
          'ios/ exists but project.pbxproj was not found; IPHONEOS_DEPLOYMENT_TARGET cannot be resolved.',
          id: 'ios-deployment-target',
        ),
      );
    } else {
      final text = await pbxproj.readAsString();
      final targets = RegExp(
        r'IPHONEOS_DEPLOYMENT_TARGET\s*=\s*([^;]+);',
      )
          .allMatches(text)
          .map((m) => m.group(1)!.trim().replaceAll('"', ''))
          .where((v) => v.isNotEmpty)
          .toList();

      if (targets.isEmpty) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'iOS deployment target',
            'IPHONEOS_DEPLOYMENT_TARGET could not be resolved from project.pbxproj.',
            id: 'ios-deployment-target',
            fix:
                'Set IPHONEOS_DEPLOYMENT_TARGET on Runner build configurations.',
          ),
        );
      } else {
        final unique = targets.toSet();
        if (unique.length == 1) {
          findings.add(
            Finding(
              FindingLevel.passed,
              'iOS deployment target',
              'IPHONEOS_DEPLOYMENT_TARGET=${unique.single} is resolved and consistent across build configurations.',
              id: 'ios-deployment-target',
            ),
          );
        } else {
          findings.add(
            Finding(
              FindingLevel.warning,
              'iOS deployment target',
              'IPHONEOS_DEPLOYMENT_TARGET differs across configurations: ${unique.join(', ')}.',
              id: 'ios-deployment-target',
              fix:
                  'Align Debug/Release (and other) Runner configurations on one deployment target.',
            ),
          );
        }
      }
    }

    await _checkPrivacyManifest(project, findings);
  }

  Future<void> _checkPrivacyManifest(
    Directory project,
    List<Finding> findings,
  ) async {
    final manifest = await _findPrivacyManifest(project);
    if (manifest != null) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'iOS privacy manifest',
          'Found `${_relative(project, manifest)}`. Contents were not validated for full App Store compliance.',
          id: 'ios-privacy-manifest',
        ),
      );
      return;
    }

    final sensitive = await _hasIosPrivacySensitiveSignals(project);
    if (!sensitive) return;

    findings.add(
      const Finding(
        FindingLevel.warning,
        'iOS privacy manifest',
        'Privacy-sensitive APIs or permission usage descriptions are present, but no PrivacyInfo.xcprivacy was found.',
        id: 'ios-privacy-manifest',
        fix:
            'Add a PrivacyInfo.xcprivacy manifest covering required-reason APIs and tracked data for App Store submission.',
      ),
    );
  }

  Future<File?> _findPrivacyManifest(Directory project) async {
    final direct = File(_join(project, 'ios/Runner/PrivacyInfo.xcprivacy'));
    if (await direct.exists()) return direct;

    final ios = Directory(_join(project, 'ios'));
    if (!await ios.exists()) return null;
    await for (final entity in ios.list(recursive: true, followLinks: false)) {
      if (entity is File &&
          entity.path.replaceAll('\\', '/').endsWith('PrivacyInfo.xcprivacy')) {
        return entity;
      }
    }
    return null;
  }

  Future<bool> _hasIosPrivacySensitiveSignals(Directory project) async {
    final info = File(_join(project, 'ios/Runner/Info.plist'));
    if (await info.exists()) {
      final text = await info.readAsString();
      for (final key in _privacyUsageKeys) {
        if (text.contains(key)) return true;
      }
    }

    final entitlements = File(_join(project, 'ios/Runner/Runner.entitlements'));
    if (await entitlements.exists()) {
      final text = await entitlements.readAsString();
      if (RegExp(
        r'aps-environment|com\.apple\.developer\.healthkit|NFC|Associated Domains',
        caseSensitive: false,
      ).hasMatch(text)) {
        return true;
      }
    }
    return false;
  }

  Future<File?> _androidAppGradle(Directory project) async {
    final groovy = File(_join(project, 'android/app/build.gradle'));
    if (await groovy.exists()) return groovy;
    final kts = File(_join(project, 'android/app/build.gradle.kts'));
    if (await kts.exists()) return kts;
    return null;
  }

  Future<Map<String, int>> _loadAndroidSdkSymbols(
    Directory project,
    String appGradle,
  ) async {
    final symbols = <String, int>{};

    void absorb(String text) {
      for (final match in RegExp(
        r'''flutter\.(minSdkVersion|targetSdkVersion|compileSdkVersion)\s*=\s*(\d+)''',
      ).allMatches(text)) {
        symbols['flutter.${match.group(1)}'] = int.parse(match.group(2)!);
      }

      final flutterBlock = _balancedBlockBody(text, 'flutter');
      if (flutterBlock != null) {
        for (final key in [
          'minSdkVersion',
          'targetSdkVersion',
          'compileSdkVersion',
        ]) {
          final m = RegExp('$key\\s+(\\d+)').firstMatch(flutterBlock) ??
              RegExp('$key\\s*=\\s*(\\d+)').firstMatch(flutterBlock);
          if (m != null) symbols['flutter.$key'] = int.parse(m.group(1)!);
        }
      }

      final extBlock = _balancedBlockBody(text, 'ext');
      if (extBlock != null) {
        for (final key in [
          'minSdkVersion',
          'targetSdkVersion',
          'compileSdkVersion',
        ]) {
          final m = RegExp('$key\\s*=\\s*(\\d+)').firstMatch(extBlock);
          if (m != null) {
            symbols[key] = int.parse(m.group(1)!);
            symbols['ext.$key'] = int.parse(m.group(1)!);
          }
        }
      }

      for (final match in RegExp(
        r'''(?:^|\n)\s*(minSdkVersion|targetSdkVersion|compileSdkVersion)\s*=\s*(\d+)''',
      ).allMatches(text)) {
        symbols[match.group(1)!] = int.parse(match.group(2)!);
      }
    }

    absorb(appGradle);

    for (final relative in [
      'android/gradle.properties',
      'android/local.properties',
      'android/build.gradle',
      'android/build.gradle.kts',
      'gradle.properties',
    ]) {
      final file = File(_join(project, relative));
      if (await file.exists()) absorb(await file.readAsString());
    }

    return symbols;
  }

  int? _resolveSdkValue(
    String gradleText,
    List<String> keys,
    Map<String, int> symbols,
  ) {
    for (final key in keys) {
      // Numeric: minSdk 24 / minSdk = 24 / minSdkVersion 24
      final patterns = [
        RegExp('$key\\s*=\\s*(\\d+)'),
        RegExp('$key\\s+(\\d+)'),
        RegExp('$key\\.set\\(\\s*(\\d+)\\s*\\)'),
      ];
      for (final pattern in patterns) {
        final match = pattern.firstMatch(gradleText);
        if (match != null) return int.parse(match.group(1)!);
      }

      // flutter.minSdkVersion / flutter.compileSdkVersion
      final flutterRef = RegExp(
        '$key\\s*=?\\s*flutter\\.(minSdkVersion|targetSdkVersion|compileSdkVersion)',
      ).firstMatch(gradleText);
      if (flutterRef != null) {
        final symbol = 'flutter.${flutterRef.group(1)}';
        if (symbols.containsKey(symbol)) return symbols[symbol];
      }

      // key = flutter.minSdkVersion without '=' variants already covered;
      // also: minSdkVersion flutter.minSdkVersion
      final spacedFlutter = RegExp(
        '$key\\s+flutter\\.(minSdkVersion|targetSdkVersion|compileSdkVersion)',
      ).firstMatch(gradleText);
      if (spacedFlutter != null) {
        final symbol = 'flutter.${spacedFlutter.group(1)}';
        if (symbols.containsKey(symbol)) return symbols[symbol];
      }

      // ext.minSdkVersion / project.xxx
      final extRef = RegExp(
        '$key\\s*=?\\s*(?:rootProject\\.)?ext\\.(\\w+)',
      ).firstMatch(gradleText);
      if (extRef != null) {
        final name = extRef.group(1)!;
        if (symbols.containsKey(name)) return symbols[name];
        if (symbols.containsKey('ext.$name')) return symbols['ext.$name'];
      }

      final spacedExt = RegExp(
        '$key\\s+(?:rootProject\\.)?ext\\.(\\w+)',
      ).firstMatch(gradleText);
      if (spacedExt != null) {
        final name = spacedExt.group(1)!;
        if (symbols.containsKey(name)) return symbols[name];
        if (symbols.containsKey('ext.$name')) return symbols['ext.$name'];
      }

      if (symbols.containsKey(key)) return symbols[key];
    }
    return null;
  }

  String _resolvedSummary(int? minSdk, int? targetSdk, int? compileSdk) {
    final parts = <String>[
      if (minSdk != null) 'minSdk=$minSdk',
      if (targetSdk != null) 'targetSdk=$targetSdk',
      if (compileSdk != null) 'compileSdk=$compileSdk',
    ];
    if (parts.isEmpty) return '';
    return ' (resolved: ${parts.join(', ')})';
  }

  String? _balancedBlockBody(String text, String keyword) {
    final startMatch = RegExp('(?:\\b$keyword\\b)\\s*\\{').firstMatch(text);
    if (startMatch == null) return null;
    final start = startMatch.end - 1;
    var depth = 0;
    for (var i = start; i < text.length; i++) {
      if (text[i] == '{') depth++;
      if (text[i] == '}') {
        depth--;
        if (depth == 0) return text.substring(start + 1, i);
      }
    }
    return null;
  }

  String _relative(Directory project, File file) {
    final prefix = project.path;
    if (file.path.startsWith(prefix)) {
      return file.path
          .substring(prefix.length)
          .replaceFirst(RegExp(r'^[/\\]'), '')
          .replaceAll('\\', '/');
    }
    return file.uri.pathSegments.last;
  }

  String _join(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}
