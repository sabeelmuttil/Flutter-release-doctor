import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';

/// Android and iOS signing / release-build safety checks.
///
/// Never reports keystore passwords, aliases, store paths, provisioning
/// profile IDs, certificate identifiers, team IDs, or other secrets.
class SigningCheck {
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

    final groovy = File(_join(project, 'android/app/build.gradle'));
    final kts = File(_join(project, 'android/app/build.gradle.kts'));
    File? gradle;
    if (await groovy.exists()) {
      gradle = groovy;
    } else if (await kts.exists()) {
      gradle = kts;
    }

    if (gradle == null) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Android release signing',
          'Android folder exists but android/app/build.gradle(.kts) was not found; signing configuration cannot be resolved.',
          id: 'android-release-signing',
          fix:
              'Ensure the standard Flutter Android Gradle files are present before release.',
        ),
      );
      return;
    }

    final text = await gradle.readAsString();
    final releaseBody = _buildTypeBody(text, 'release');
    if (releaseBody == null) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android release signing',
          'No `release` build type was found in ${gradle.uri.pathSegments.last}; signing configuration cannot be resolved.',
          id: 'android-release-signing',
          fix:
              'Define a `release` buildType with an explicit non-debug signingConfig.',
        ),
      );
      return;
    }

    if (_usesDebugSigning(releaseBody)) {
      findings.add(
        const Finding(
          FindingLevel.error,
          'Android release signing',
          'The `release` build type explicitly uses `signingConfigs.debug`.',
          id: 'android-release-signing',
          fix:
              'Configure a release signingConfig (typically loaded from key.properties) and assign it to the release build type.',
        ),
      );
    } else {
      final signingConfigured = _hasReleaseSigningConfig(releaseBody, text);
      final keyProps = await _findKeyProperties(project);
      final referencesKeyProps = _referencesKeyProperties(text);

      if (signingConfigured && (keyProps != null || referencesKeyProps)) {
        findings.add(
          const Finding(
            FindingLevel.passed,
            'Android release signing',
            'Release signingConfig is configured and a local key.properties (or equivalent) reference is present.',
            id: 'android-release-signing',
          ),
        );
      } else if (!signingConfigured &&
          keyProps == null &&
          !referencesKeyProps) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Android release signing',
            'Release build type exists in ${gradle.uri.pathSegments.last} but release signingConfig / key.properties could not be resolved.',
            id: 'android-release-signing',
            fix:
                'Add a release signingConfig backed by key.properties (or your CI secret store) and wire it to the release build type.',
          ),
        );
      } else {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Android release signing',
            'Android signing setup is partially present but could not be fully resolved from ${gradle.uri.pathSegments.last}.',
            id: 'android-release-signing',
            fix:
                'Confirm release signingConfig and key.properties are both configured for store builds.',
          ),
        );
      }

      if (keyProps != null) {
        final ignored = await _isKeyPropertiesGitignored(project);
        if (!ignored) {
          findings.add(
            Finding(
              FindingLevel.warning,
              'Android key.properties gitignore',
              '`${_relative(project, keyProps)}` exists but is not ignored by `.gitignore`.',
              id: 'android-key-properties-gitignore',
              fix:
                  'Add `key.properties` (or the exact path) to `.gitignore` so signing secrets are never committed.',
            ),
          );
        }
      }
    }

    await _checkAndroidMinify(releaseBody, findings);
  }

  Future<void> _checkAndroidMinify(
    String releaseBody,
    List<Finding> findings,
  ) async {
    final minifySet = RegExp(
          r'(?:minifyEnabled|isMinifyEnabled)\s*=?\s*(true|false)',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'minifyEnabled\s+(true|false)',
          caseSensitive: false,
        ).hasMatch(releaseBody);

    final shrinkSet = RegExp(
          r'(?:shrinkResources|isShrinkResources)\s*=?\s*(true|false)',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'shrinkResources\s+(true|false)',
          caseSensitive: false,
        ).hasMatch(releaseBody);

    if (minifySet && shrinkSet) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'Android release minification',
          'Release build explicitly configures minification and resource shrinking.',
          id: 'android-release-minification',
        ),
      );
    } else {
      final missing = <String>[
        if (!minifySet) 'minifyEnabled/isMinifyEnabled',
        if (!shrinkSet) 'shrinkResources/isShrinkResources',
      ].join(' and ');
      findings.add(
        Finding(
          FindingLevel.warning,
          'Android release minification',
          'Release build does not explicitly configure $missing.',
          id: 'android-release-minification',
          fix:
              'Set minifyEnabled/isMinifyEnabled and shrinkResources/isShrinkResources in the release build type.',
        ),
      );
    }
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
          'iOS release signing',
          'ios/ exists but Runner.xcodeproj/project.pbxproj was not found; signing settings cannot be resolved.',
          id: 'ios-release-signing',
          fix: 'Restore the Flutter iOS Xcode project before release.',
        ),
      );
      return;
    }

    final text = await pbxproj.readAsString();
    final releaseSections = _configurationSections(text, 'Release');
    if (releaseSections.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS release signing',
          'No Release build configuration was found in project.pbxproj.',
          id: 'ios-release-signing',
          fix: 'Ensure a Release XCBuildConfiguration exists for Runner.',
        ),
      );
      return;
    }

    final combined = releaseSections.join('\n');
    final style = _pbxSetting(combined, 'CODE_SIGN_STYLE');
    final team = _pbxSetting(combined, 'DEVELOPMENT_TEAM');

    final styleOk = style != null && !_looksUnresolved(style);
    final teamOk = team != null && !_looksUnresolved(team);

    if (styleOk && teamOk) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'iOS release signing',
          'Release configuration defines CODE_SIGN_STYLE and DEVELOPMENT_TEAM.',
          id: 'ios-release-signing',
        ),
      );
    } else {
      final missing = <String>[
        if (!styleOk) 'CODE_SIGN_STYLE',
        if (!teamOk) 'DEVELOPMENT_TEAM',
      ].join(' and ');
      findings.add(
        Finding(
          FindingLevel.warning,
          'iOS release signing',
          'Release signing settings could not be resolved ($missing missing or uses an unsupported variable structure).',
          id: 'ios-release-signing',
          fix:
              'Set CODE_SIGN_STYLE and DEVELOPMENT_TEAM on the Release configuration in Xcode (values are not printed by Release Doctor).',
        ),
      );
    }

    await _checkIosSchemes(project, findings);
    await _checkIosEntitlements(project, text, findings);
  }

  Future<void> _checkIosSchemes(
    Directory project,
    List<Finding> findings,
  ) async {
    final schemesDir = Directory(
      _join(project, 'ios/Runner.xcodeproj/xcshareddata/xcschemes'),
    );
    if (!await schemesDir.exists()) return;

    final problems = <String>[];
    await for (final entity
        in schemesDir.list(followLinks: false, recursive: false)) {
      if (entity is! File || !entity.path.endsWith('.xcscheme')) continue;
      final name = entity.uri.pathSegments.last.replaceAll('.xcscheme', '');
      final xml = await entity.readAsString();

      final archive = RegExp(
        r'<ArchiveAction[^>]*buildConfiguration\s*=\s*"([^"]+)"',
        caseSensitive: false,
      ).firstMatch(xml)?.group(1);
      final profile = RegExp(
        r'<ProfileAction[^>]*buildConfiguration\s*=\s*"([^"]+)"',
        caseSensitive: false,
      ).firstMatch(xml)?.group(1);
      final launch = RegExp(
        r'<LaunchAction[^>]*buildConfiguration\s*=\s*"([^"]+)"',
        caseSensitive: false,
      ).firstMatch(xml)?.group(1);

      final releaseLikeName = RegExp(
        r'(release|prod|production|appstore|distribute)',
        caseSensitive: false,
      ).hasMatch(name);

      if (archive != null && archive.toLowerCase().contains('debug')) {
        problems.add('$name ArchiveAction→$archive');
      } else if (releaseLikeName &&
          profile != null &&
          profile.toLowerCase().contains('debug')) {
        problems.add('$name ProfileAction→$profile');
      } else if (releaseLikeName &&
          launch != null &&
          launch.toLowerCase().contains('debug') &&
          (archive == null || archive.toLowerCase().contains('debug'))) {
        problems.add('$name LaunchAction→$launch');
      }
    }

    if (problems.isEmpty) return;
    findings.add(
      Finding(
        FindingLevel.warning,
        'iOS Release scheme',
        'A Release/production scheme or Archive action references a Debug configuration: ${problems.join('; ')}.',
        id: 'ios-release-scheme',
        fix:
            'Point Archive/Profile actions for release schemes at the Release build configuration.',
      ),
    );
  }

  Future<void> _checkIosEntitlements(
    Directory project,
    String pbxproj,
    List<Finding> findings,
  ) async {
    final entitlementsPaths = <String>{
      'ios/Runner/Runner.entitlements',
      ...RegExp(r'CODE_SIGN_ENTITLEMENTS\s*=\s*([^;]+);')
          .allMatches(pbxproj)
          .map((m) => m.group(1)!.trim().replaceAll('"', ''))
          .where((p) => p.isNotEmpty && !_looksUnresolved(p))
          .map((p) => p.startsWith('ios/') ? p : 'ios/$p'),
    };

    var pushReferenced = false;
    var apsFound = false;
    var entitlementsSeen = false;

    for (final relative in entitlementsPaths) {
      final file = File(_join(project, relative));
      if (!await file.exists()) continue;
      entitlementsSeen = true;
      final text = await file.readAsString();
      if (text.contains('aps-environment')) {
        apsFound = true;
        pushReferenced = true;
      }
      if (RegExp(
        r'com\.apple\.Developer\.Push|push-notification|aps-environment',
        caseSensitive: false,
      ).hasMatch(text)) {
        pushReferenced = true;
      }
    }

    final infoPlist = File(_join(project, 'ios/Runner/Info.plist'));
    if (await infoPlist.exists()) {
      final info = await infoPlist.readAsString();
      if (info.contains('remote-notification')) {
        pushReferenced = true;
      }
    }

    if (!entitlementsSeen && !pushReferenced) return;

    if (pushReferenced && !apsFound) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'iOS push entitlements',
          'Push notification capability appears referenced, but `aps-environment` was not found in Runner entitlements.',
          id: 'ios-push-entitlements',
          fix:
              'Add `aps-environment` to Runner.entitlements for the correct development/production push environment.',
        ),
      );
    } else if (apsFound) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'iOS push entitlements',
          'Runner entitlements define `aps-environment` for push notifications.',
          id: 'ios-push-entitlements',
        ),
      );
    }
  }

  bool _usesDebugSigning(String releaseBody) {
    return RegExp(
          r'''signingConfig\s*=?\s*signingConfigs\.debug''',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'''signingConfig\s*=?\s*signingConfigs\.getByName\(\s*["']debug["']\s*\)''',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'signingConfig\s+signingConfigs\.debug',
          caseSensitive: false,
        ).hasMatch(releaseBody);
  }

  bool _hasReleaseSigningConfig(String releaseBody, String fullGradle) {
    final assignsRelease = RegExp(
          r'''signingConfig\s*=?\s*signingConfigs\.release''',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'''signingConfig\s*=?\s*signingConfigs\.getByName\(\s*["']release["']\s*\)''',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'signingConfig\s+signingConfigs\.release',
          caseSensitive: false,
        ).hasMatch(releaseBody) ||
        RegExp(
          r'''signingConfig\s*=?\s*signingConfigs\.getByName\(\s*["'][^"']+["']\s*\)''',
          caseSensitive: false,
        ).hasMatch(releaseBody);

    if (assignsRelease) return true;

    // signingConfig may reference a custom name defined under signingConfigs.
    final custom = RegExp(
      r'signingConfig\s*=?\s*signingConfigs\.([A-Za-z_]\w*)',
      caseSensitive: false,
    ).firstMatch(releaseBody);
    if (custom != null) {
      final name = custom.group(1)!.toLowerCase();
      return name != 'debug';
    }
    return RegExp(
      r'signingConfigs\s*\{[\s\S]*?\brelease\b',
      caseSensitive: false,
    ).hasMatch(fullGradle);
  }

  bool _referencesKeyProperties(String gradleText) {
    return RegExp(
      r'key\.properties',
      caseSensitive: false,
    ).hasMatch(gradleText);
  }

  Future<File?> _findKeyProperties(Directory project) async {
    final candidates = [
      File(_join(project, 'android/key.properties')),
      File(_join(project, 'key.properties')),
      File(_join(project, 'android/app/key.properties')),
    ];
    for (final file in candidates) {
      if (await file.exists()) return file;
    }
    return null;
  }

  Future<bool> _isKeyPropertiesGitignored(Directory project) async {
    final gitignore = File(_join(project, '.gitignore'));
    if (!await gitignore.exists()) return false;
    final lines = await gitignore.readAsLines();
    for (final raw in lines) {
      final line = raw.trim();
      if (line.isEmpty || line.startsWith('#')) continue;
      if (line == 'key.properties' ||
          line == '/key.properties' ||
          line == 'android/key.properties' ||
          line == '/android/key.properties' ||
          line == '**/key.properties' ||
          line == 'android/**/key.properties' ||
          line.endsWith('/key.properties') ||
          line == '*.properties') {
        return true;
      }
    }
    return false;
  }

  String? _buildTypeBody(String gradleText, String name) {
    final buildTypes = _balancedBlockBody(gradleText, 'buildTypes');
    if (buildTypes == null) {
      // Some templates nest getByName("release") outside a classic block.
      return _balancedBlockBody(gradleText, name) ??
          _ktsGetByNameBody(gradleText, name);
    }
    return _balancedBlockBody(buildTypes, name) ??
        _ktsGetByNameBody(buildTypes, name);
  }

  String? _ktsGetByNameBody(String text, String name) {
    final match = RegExp(
      'getByName\\(\\s*[\'"]$name[\'"]\\s*\\)\\s*\\{',
    ).firstMatch(text);
    if (match == null) return null;
    final start = match.end - 1;
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

  List<String> _configurationSections(String pbxproj, String configName) {
    final sections = <String>[];
    final matches = RegExp(
      r'/\*\s*' +
          RegExp.escape(configName) +
          r'\s*\*/\s*=\s*\{([\s\S]*?)\n\s*\};',
    ).allMatches(pbxproj);
    for (final match in matches) {
      sections.add(match.group(1)!);
    }

    // Fallback: buildSettings blocks that set name = Release;
    if (sections.isEmpty) {
      final blocks = RegExp(
        r'isa\s*=\s*XCBuildConfiguration;\s*([\s\S]*?)\};',
      ).allMatches(pbxproj);
      for (final block in blocks) {
        final body = block.group(1)!;
        final name = RegExp(r'name\s*=\s*([^;]+);').firstMatch(body);
        if (name == null) continue;
        final value = name.group(1)!.trim().replaceAll('"', '');
        if (value == configName) sections.add(body);
      }
    }
    return sections;
  }

  String? _pbxSetting(String section, String key) {
    final match = RegExp(
      '$key\\s*=\\s*([^;]+);',
    ).firstMatch(section);
    if (match == null) return null;
    return match.group(1)!.trim().replaceAll('"', '');
  }

  bool _looksUnresolved(String value) {
    final trimmed = value.trim();
    return trimmed.contains(r'$(') ||
        trimmed.contains(r'${') ||
        trimmed == '""' ||
        trimmed.isEmpty;
  }

  String? _balancedBlockBody(String text, String keyword) {
    final startMatch = RegExp(
      '(?:\\b$keyword\\b)\\s*\\{',
    ).firstMatch(text);
    if (startMatch == null) return null;
    final start = startMatch.end - 1;
    var depth = 0;
    for (var i = start; i < text.length; i++) {
      final ch = text[i];
      if (ch == '{') depth++;
      if (ch == '}') {
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
