import 'dart:convert';
import 'dart:io';

import 'package:flutter_release_doctor/src/finding.dart';

/// Detects risky multi-environment / flavor configuration mistakes.
class EnvironmentFlavorCheck {
  static const _envFileNames = <String>{
    '.env',
    '.env.dev',
    '.env.uat',
    '.env.staging',
    '.env.prod',
    '.env.production',
  };

  static const _productionEnvFiles = <String>{
    '.env.prod',
    '.env.production',
  };

  static final _apiUrlKey = RegExp(
    r'^(?:API_BASE_URL|BASE_URL|API_URL|APP_BASE_URL|APP_API_URL)\s*=\s*(.*)$',
    caseSensitive: false,
  );

  static final _secretKey = RegExp(
    r'(api[_-]?key|secret|token|password|private[_-]?key|auth[_-]?key)',
    caseSensitive: false,
  );

  static final _hardCodedUrl = RegExp(
    r'''(?:https?://[^\s'"<>]+)''',
    caseSensitive: false,
  );

  static final _dartApiAssignment = RegExp(
    r'''(?:apiBaseUrl|baseUrl|apiUrl|base_url|api_url)\s*=\s*['"](https?://[^'"]+)['"]''',
    caseSensitive: false,
  );

  Future<void> run(Directory project, List<Finding> findings) async {
    final envFiles = await _loadEnvFiles(project);
    await _checkEnvFiles(envFiles, findings);
    await _checkHardCodedUrls(project, findings);
    await _checkAndroidFlavors(project, findings);
    await _checkIosSchemes(project, findings);
    await _checkFirebaseProjectIds(project, findings);
  }

  Future<List<_EnvFile>> _loadEnvFiles(Directory project) async {
    final loaded = <_EnvFile>[];
    for (final name in _envFileNames) {
      final file = File(_join(project, name));
      if (!await file.exists()) continue;
      final text = await file.readAsString();
      loaded.add(
        _EnvFile(
          name: name,
          apiBaseUrl: _extractApiBaseUrl(text),
          isProduction: _productionEnvFiles.contains(name),
        ),
      );
    }
    return loaded;
  }

  Future<void> _checkEnvFiles(
    List<_EnvFile> envFiles,
    List<Finding> findings,
  ) async {
    if (envFiles.isEmpty) return;

    final namedEnvs =
        envFiles.where((f) => f.name != '.env').map((f) => f.name).toList();
    final clearConvention = namedEnvs.length >= 2 &&
        namedEnvs.every((name) => RegExp(
              r'^\.env\.(dev|uat|staging|prod|production)$',
            ).hasMatch(name));

    final withUrls =
        envFiles.where((f) => f.apiBaseUrl != null && f.apiBaseUrl!.isNotEmpty);
    final allHaveUrls = envFiles.every(
      (f) => f.apiBaseUrl != null && f.apiBaseUrl!.isNotEmpty,
    );

    final hasProductionFile =
        envFiles.any((f) => _productionEnvFiles.contains(f.name));
    if (!hasProductionFile) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Production environment file',
          'Environment files found (${envFiles.map((f) => f.name).join(', ')}) but no production-like file (`.env.prod` or `.env.production`).',
          fix:
              'Add a production environment file with the production API base URL.',
        ),
      );
    }

    var productionUrlError = false;
    for (final file in envFiles.where((f) => f.isProduction)) {
      final url = file.apiBaseUrl;
      if (url == null || url.isEmpty) continue;
      if (_containsNonProdMarker(url)) {
        productionUrlError = true;
        findings.add(
          Finding(
            FindingLevel.error,
            'Production API URL',
            'Production file `${file.name}` API base URL `${_safeUrl(url)}` looks like a non-production endpoint.',
            fix:
                'Point production at the real production API. Do not use uat, staging, dev, localhost, or 10.0.2.2 in production.',
          ),
        );
      }
    }

    for (final file in envFiles.where((f) => !f.isProduction)) {
      final url = file.apiBaseUrl;
      if (url == null || url.isEmpty) continue;
      if (_looksProductionLike(url)) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Non-production API URL',
            'Environment file `${file.name}` points to a production-like API `${_safeUrl(url)}`.',
            fix:
                'Confirm this non-production environment should not use a dedicated non-prod API host.',
          ),
        );
      }
    }

    final urlToFiles = <String, List<String>>{};
    for (final file in withUrls) {
      final normalized = file.apiBaseUrl!.trim().toLowerCase();
      urlToFiles.putIfAbsent(normalized, () => []).add(file.name);
    }
    for (final entry in urlToFiles.entries) {
      if (entry.value.length < 2) continue;
      findings.add(
        Finding(
          FindingLevel.warning,
          'Duplicate environment API URL',
          'Multiple environment files share the same API base URL `${_safeUrl(entry.key)}`: ${entry.value.join(', ')}.',
          fix:
              'Give each environment its own API base URL unless they intentionally share one.',
        ),
      );
    }

    if (clearConvention &&
        allHaveUrls &&
        hasProductionFile &&
        !productionUrlError) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Environment files',
          'Found ${envFiles.length} environment files with a clear naming convention and non-empty API base URLs.',
        ),
      );
    } else if (envFiles.length >= 2 && !allHaveUrls) {
      final missing = envFiles
          .where((f) => f.apiBaseUrl == null || f.apiBaseUrl!.isEmpty)
          .map((f) => f.name);
      findings.add(
        Finding(
          FindingLevel.warning,
          'Environment API URL',
          'Environment file(s) missing a non-empty API base URL: ${missing.join(', ')}.',
          fix:
              'Set API_BASE_URL (or BASE_URL / API_URL) in each environment file.',
        ),
      );
    }
  }

  Future<void> _checkHardCodedUrls(
    Directory project,
    List<Finding> findings,
  ) async {
    final libDir = Directory(_join(project, 'lib'));
    if (!await libDir.exists()) return;

    final offenders = <String>[];
    await for (final entity
        in libDir.list(recursive: true, followLinks: false)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      final relative = entity.path
          .substring(project.path.length)
          .replaceFirst(RegExp(r'^[/\\]'), '');
      if (_isApprovedConfigPath(relative)) continue;
      final text = await entity.readAsString();
      final seen = <String>{};

      for (final match in _dartApiAssignment.allMatches(text)) {
        final url = match.group(1)!;
        if (_isLocalUrl(url)) continue;
        final label = '$relative → ${_safeUrl(url)}';
        if (seen.add(label)) offenders.add(label);
      }

      for (final match in _hardCodedUrl.allMatches(text)) {
        final url = match.group(0)!;
        if (_isLocalUrl(url)) continue;
        if (!_looksLikeApiUrl(url)) continue;
        final label = '$relative → ${_safeUrl(url)}';
        if (seen.add(label)) offenders.add(label);
      }
    }

    if (offenders.isEmpty) return;
    findings.add(
      Finding(
        FindingLevel.warning,
        'Hard-coded API URL',
        'Non-local API URL(s) found in Dart source outside approved environment/config files: ${offenders.take(5).join('; ')}${offenders.length > 5 ? '…' : ''}.',
        fix:
            'Move API base URLs into `.env*` or a dedicated environment config loaded per flavor.',
      ),
    );
  }

  Future<void> _checkAndroidFlavors(
    Directory project,
    List<Finding> findings,
  ) async {
    final candidates = [
      File(_join(project, 'android/app/build.gradle')),
      File(_join(project, 'android/app/build.gradle.kts')),
    ];
    String? text;
    for (final file in candidates) {
      if (await file.exists()) {
        text = await file.readAsString();
        break;
      }
    }
    if (text == null) return;

    final body = _balancedBlockBody(text, 'productFlavors');
    if (body == null) return;

    final flavorNames =
        RegExp(r'''^\s*([A-Za-z_][\w]*)\s*\{''', multiLine: true)
            .allMatches(body)
            .map((m) => m.group(1)!)
            .where((name) => name != 'create' && name != 'maybeCreate')
            .toSet()
            .toList();

    if (flavorNames.isEmpty) return;

    final mapped = flavorNames.where(_looksLikeEnvName).toList();
    if (mapped.length == flavorNames.length && flavorNames.length >= 2) {
      findings.add(
        Finding(
          FindingLevel.passed,
          'Android product flavors',
          'Product flavors map clearly to environments: ${flavorNames.join(', ')}.',
        ),
      );
      return;
    }

    findings.add(
      Finding(
        FindingLevel.warning,
        'Android product flavors',
        'Android product flavors exist (${flavorNames.join(', ')}) but their names/application IDs cannot be mapped clearly to environments (dev/uat/staging/prod).',
        fix:
            'Name flavors after environments and use distinct applicationId or applicationIdSuffix values per flavor.',
      ),
    );
  }

  Future<void> _checkIosSchemes(
    Directory project,
    List<Finding> findings,
  ) async {
    final schemesDir = Directory(
      _join(project, 'ios/Runner.xcodeproj/xcshareddata/xcschemes'),
    );
    final schemeNames = <String>[];
    if (await schemesDir.exists()) {
      await for (final entity
          in schemesDir.list(followLinks: false, recursive: false)) {
        if (entity is File && entity.path.endsWith('.xcscheme')) {
          schemeNames.add(
            entity.uri.pathSegments.last.replaceAll('.xcscheme', ''),
          );
        }
      }
    }

    final pbxproj =
        File(_join(project, 'ios/Runner.xcodeproj/project.pbxproj'));
    final configNames = <String>{};
    if (await pbxproj.exists()) {
      final text = await pbxproj.readAsString();
      for (final match in RegExp(
        r'name\s*=\s*([^;]+);',
      ).allMatches(text)) {
        final name = match.group(1)!.trim().replaceAll('"', '');
        if (_looksLikeEnvName(name) ||
            name == 'Debug' ||
            name == 'Release' ||
            name == 'Profile') {
          configNames.add(name);
        }
      }
    }

    final envSchemes = schemeNames.where(_looksLikeEnvName).toList();
    final envConfigs = configNames.where((n) => _looksLikeEnvName(n)).toList();

    if (schemeNames.length >= 2 &&
        envSchemes.length != schemeNames.length &&
        envConfigs.isEmpty) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'iOS schemes',
          'Multiple iOS schemes found (${schemeNames.join(', ')}) without clear environment naming.',
          fix:
              'Name shared schemes/configurations after environments (dev, uat, staging, prod) when using flavors.',
        ),
      );
    } else if (envSchemes.length >= 2 || envConfigs.length >= 2) {
      final labels = [
        ...envSchemes,
        ...envConfigs,
      ].toSet().join(', ');
      findings.add(
        Finding(
          FindingLevel.passed,
          'iOS environment configurations',
          'iOS schemes/configurations appear environment-aware: $labels.',
        ),
      );
    }
  }

  Future<void> _checkFirebaseProjectIds(
    Directory project,
    List<Finding> findings,
  ) async {
    final detected = <_FirebaseProject>[];

    final androidFirebase =
        File(_join(project, 'android/app/google-services.json'));
    if (await androidFirebase.exists()) {
      final id = await _androidProjectId(androidFirebase);
      if (id != null) {
        detected.add(
          _FirebaseProject(
            source: 'android/app/google-services.json',
            projectId: id,
            productionLikeName: false,
          ),
        );
      }
    }

    final androidAppDir = Directory(_join(project, 'android/app'));
    if (await androidAppDir.exists()) {
      await for (final entity
          in androidAppDir.list(followLinks: false, recursive: false)) {
        if (entity is! File) continue;
        final name = entity.uri.pathSegments.last;
        if (!name.startsWith('google-services') || !name.endsWith('.json')) {
          continue;
        }
        if (name == 'google-services.json') continue;
        final id = await _androidProjectId(entity);
        if (id == null) continue;
        detected.add(
          _FirebaseProject(
            source: 'android/app/$name',
            projectId: id,
            productionLikeName: _nameLooksProduction(name),
          ),
        );
      }
    }

    final iosFirebase =
        File(_join(project, 'ios/Runner/GoogleService-Info.plist'));
    if (await iosFirebase.exists()) {
      final text = await iosFirebase.readAsString();
      final id = _plistString(text, 'PROJECT_ID');
      if (id != null) {
        detected.add(
          _FirebaseProject(
            source: 'ios/Runner/GoogleService-Info.plist',
            projectId: id,
            productionLikeName: false,
          ),
        );
      }
    }

    final iosRunner = Directory(_join(project, 'ios/Runner'));
    if (await iosRunner.exists()) {
      await for (final entity
          in iosRunner.list(followLinks: false, recursive: false)) {
        if (entity is! File) continue;
        final name = entity.uri.pathSegments.last;
        if (!name.contains('GoogleService') || !name.endsWith('.plist')) {
          continue;
        }
        if (name == 'GoogleService-Info.plist') continue;
        final id = _plistString(await entity.readAsString(), 'PROJECT_ID');
        if (id == null) continue;
        detected.add(
          _FirebaseProject(
            source: 'ios/Runner/$name',
            projectId: id,
            productionLikeName: _nameLooksProduction(name),
          ),
        );
      }
    }

    if (detected.isEmpty) return;

    for (final item in detected) {
      if (item.productionLikeName && _containsNonProdMarker(item.projectId)) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Firebase project ID',
            'Firebase config `${item.source}` looks production-named but project ID `${item.projectId}` contains a non-production marker.',
            fix:
                'Use the production Firebase project config for production builds.',
          ),
        );
      }
    }

    final ids = detected.map((d) => d.projectId).toSet();
    if (ids.length >= 2) {
      final summary =
          detected.map((d) => '${d.source}→${d.projectId}').take(6).join(', ');
      findings.add(
        Finding(
          FindingLevel.passed,
          'Firebase environments',
          'Detected multiple Firebase project IDs across config files: $summary.',
        ),
      );
    }
  }

  String? _extractApiBaseUrl(String text) {
    for (final line in text.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
      final match = _apiUrlKey.firstMatch(trimmed);
      if (match == null) continue;
      var value = match.group(1)!.trim();
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.substring(1, value.length - 1);
      }
      // Never treat secret-looking assignments as URLs.
      final key = trimmed.split('=').first.trim();
      if (_secretKey.hasMatch(key)) continue;
      return value;
    }
    return null;
  }

  Future<String?> _androidProjectId(File file) async {
    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map) return null;
      final projectInfo = decoded['project_info'];
      if (projectInfo is Map && projectInfo['project_id'] is String) {
        return projectInfo['project_id'] as String;
      }
      final projectId = decoded['project_id'];
      if (projectId is String) return projectId;
    } catch (_) {}
    return null;
  }

  String? _plistString(String plist, String key) {
    final match = RegExp(
      '<key>$key</key>\\s*<string>([^<]*)</string>',
      multiLine: true,
    ).firstMatch(plist);
    final value = match?.group(1)?.trim();
    if (value == null || value.isEmpty) return null;
    return value;
  }

  bool _containsNonProdMarker(String value) {
    final lower = value.toLowerCase();
    if (lower.contains('localhost') || lower.contains('10.0.2.2')) return true;
    return RegExp(r'(^|[./\-_])(uat|staging|dev)([./\-_:]|$)').hasMatch(lower);
  }

  bool _looksProductionLike(String url) {
    if (_containsNonProdMarker(url)) return false;
    final lower = url.toLowerCase();
    if (lower.contains('test') ||
        lower.contains('qa') ||
        lower.contains('sandbox') ||
        lower.contains('local')) {
      return false;
    }
    final host = _hostOf(url);
    if (host == null) return false;
    // Require a real-looking host with a dot.
    return host.contains('.') && !host.endsWith('.local');
  }

  bool _isLocalUrl(String url) {
    final lower = url.toLowerCase();
    return lower.contains('localhost') ||
        lower.contains('127.0.0.1') ||
        lower.contains('10.0.2.2');
  }

  bool _looksLikeApiUrl(String url) {
    final lower = url.toLowerCase();
    final host = _hostOf(url) ?? '';
    return host.startsWith('api.') ||
        host.contains('.api.') ||
        lower.contains('/api/') ||
        lower.endsWith('/api') ||
        RegExp(r'api[_-]?(base|url)', caseSensitive: false).hasMatch(lower);
  }

  bool _isApprovedConfigPath(String relative) {
    final normalized = relative.replaceAll('\\', '/').toLowerCase();
    if (normalized.endsWith('.env') || normalized.contains('/.env')) {
      return true;
    }
    // Dedicated generated/env config modules are treated as approved sinks.
    final file = normalized.split('/').last;
    return file == 'env.dart' ||
        file == 'environment.dart' ||
        file == 'app_config.dart' ||
        file.startsWith('env_') ||
        file.endsWith('_env.dart');
  }

  bool _looksLikeEnvName(String name) {
    final lower = name.toLowerCase();
    return RegExp(
      r'(^|[^a-z])(dev|uat|staging|stage|prod|production|qa)([^a-z]|$)',
    ).hasMatch(lower);
  }

  bool _nameLooksProduction(String name) {
    final lower = name.toLowerCase();
    return lower.contains('prod') || lower.contains('production');
  }

  String? _hostOf(String url) {
    final match = RegExp(r'https?://([^/?:#]+)').firstMatch(url);
    return match?.group(1)?.toLowerCase();
  }

  /// Returns the inside of `keyword { ... }` using brace matching.
  String? _balancedBlockBody(String text, String keyword) {
    final startMatch = RegExp('$keyword\\s*\\{').firstMatch(text);
    if (startMatch == null) return null;
    var depth = 0;
    final start = startMatch.end - 1;
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

  /// Strip query/fragment so tokens in URLs are never reported.
  String _safeUrl(String url) {
    final cleaned = url.split('?').first.split('#').first.trim();
    // Belt-and-suspenders: if a secret-looking value slipped in, redact.
    if (_secretKey.hasMatch(cleaned) && !cleaned.contains('://')) {
      return '[REDACTED]';
    }
    return cleaned;
  }

  String _join(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}${relative.replaceAll('/', Platform.pathSeparator)}';
}

class _EnvFile {
  const _EnvFile({
    required this.name,
    required this.apiBaseUrl,
    required this.isProduction,
  });

  final String name;
  final String? apiBaseUrl;
  final bool isProduction;
}

class _FirebaseProject {
  const _FirebaseProject({
    required this.source,
    required this.projectId,
    required this.productionLikeName,
  });

  final String source;
  final String projectId;
  final bool productionLikeName;
}
