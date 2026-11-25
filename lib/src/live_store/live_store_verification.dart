import 'dart:io';

import 'package:flutter_release_doctor/src/auth/google_token_store.dart';
import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/finding.dart';
import 'package:flutter_release_doctor/src/live_store/app_store_live_check.dart';
import 'package:flutter_release_doctor/src/live_store/google_play_live_check.dart';
import 'package:flutter_release_doctor/src/live_store/live_store_options.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';

/// Optional live store verification. Network I/O only when [LiveStoreOptions.shouldRun].
class LiveStoreVerification {
  LiveStoreVerification({
    required this.options,
    this.http,
    this.environment,
    this.readFile,
    this.googleTokenStore,
  });

  final LiveStoreOptions options;
  final StoreHttpClient? http;
  final Map<String, String>? environment;
  final Future<String> Function(String path)? readFile;
  final GoogleTokenStore? googleTokenStore;

  static const disclaimer =
      'Live API data is informational and not a store approval guarantee.';

  Future<void> run(
    Directory project,
    DoctorConfig config,
    List<Finding> findings,
  ) async {
    if (!options.shouldRun) {
      return;
    }

    final client = http ?? DartIoStoreHttpClient();
    final env = environment ?? Map<String, String>.from(Platform.environment);

    if (options.includeGoogle) {
      final package = config.storeIntegrations.googlePlayPackageName ??
          await _resolveAndroidPackage(project);
      await GooglePlayLiveCheck(
        http: client,
        environment: env,
        packageName: package,
        readFile: readFile,
        googleTokenStore: googleTokenStore,
      ).run(findings);
    }

    if (options.includeApple) {
      final bundle = config.storeIntegrations.appStoreBundleId ??
          await _resolveIosBundleId(project);
      await AppStoreLiveCheck(
        http: client,
        environment: env,
        bundleId: bundle,
        readFile: readFile,
      ).run(findings);
    }
  }

  Future<String?> _resolveAndroidPackage(Directory project) async {
    final groovy = File(_join(project, 'android/app/build.gradle'));
    final kts = File(_join(project, 'android/app/build.gradle.kts'));
    for (final file in [groovy, kts]) {
      if (!await file.exists()) continue;
      final text = await file.readAsString();
      final quoted = RegExp(
        r'''applicationId\s*(?:=|:)\s*["']([^"']+)["']''',
      ).firstMatch(text);
      if (quoted != null) {
        final value = quoted.group(1)!;
        if (!_looksLikeVariable(value)) return value;
      }
    }

    final manifest = File(
      _join(project, 'android/app/src/main/AndroidManifest.xml'),
    );
    if (await manifest.exists()) {
      final text = await manifest.readAsString();
      final match =
          RegExp(r'''package\s*=\s*["']([^"']+)["']''').firstMatch(text);
      if (match != null) {
        final value = match.group(1)!;
        if (!_looksLikeVariable(value)) return value;
      }
    }
    return null;
  }

  Future<String?> _resolveIosBundleId(Directory project) async {
    final plist = File(_join(project, 'ios/Runner/Info.plist'));
    if (!await plist.exists()) return null;
    final text = await plist.readAsString();
    final match = RegExp(
      r'<key>\s*CFBundleIdentifier\s*</key>\s*<string>\s*([^<]+)\s*</string>',
      caseSensitive: false,
    ).firstMatch(text);
    if (match == null) return null;
    final value = match.group(1)!.trim();
    if (value == r'$(PRODUCT_BUNDLE_IDENTIFIER)') {
      final pbx = File(
        _join(project, 'ios/Runner.xcodeproj/project.pbxproj'),
      );
      if (!await pbx.exists()) return null;
      final pbxText = await pbx.readAsString();
      final product = RegExp(
        r'PRODUCT_BUNDLE_IDENTIFIER\s*=\s*([^;]+);',
      ).firstMatch(pbxText);
      if (product == null) return null;
      final resolved = product.group(1)!.trim().replaceAll('"', '');
      if (_looksLikeVariable(resolved)) return null;
      return resolved;
    }
    if (_looksLikeVariable(value)) return null;
    return value;
  }

  bool _looksLikeVariable(String value) =>
      value.contains(r'$') ||
      value.contains('{') ||
      value.contains('}') ||
      value.startsWith('project.') ||
      value.contains('PRODUCT_BUNDLE');

  String _join(Directory project, String relative) =>
      '${project.path}${Platform.pathSeparator}'
      '${relative.replaceAll('/', Platform.pathSeparator)}';
}
