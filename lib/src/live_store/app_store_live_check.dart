import 'dart:io';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:flutter_release_doctor/src/finding.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';

/// Optional App Store Connect API verification (network only when asked).
class AppStoreLiveCheck {
  AppStoreLiveCheck({
    required this.http,
    required this.environment,
    this.bundleId,
    this.readFile,
  });

  final StoreHttpClient http;
  final Map<String, String> environment;
  final String? bundleId;
  final Future<String> Function(String path)? readFile;

  Future<void> run(List<Finding> findings) async {
    final bundle = bundleId?.trim();
    if (bundle == null || bundle.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.manualReview,
          'App Store Connect bundle',
          'No App Store Connect bundle_id configured and none could be resolved. '
              'Set store_integrations.app_store.bundle_id.',
          id: 'app-store-connect-access',
          confidence: FindingConfidence.low,
          source: FindingSource.liveApi,
        ),
      );
      return;
    }

    final token = await _resolveJwt(findings);
    if (token == null) return;

    try {
      final appsResponse = await http.get(
        Uri.parse(
          'https://api.appstoreconnect.apple.com/v1/apps'
          '?filter[bundleId]=${Uri.encodeQueryComponent(bundle)}',
        ),
        headers: {
          'Authorization': 'Bearer $token',
          'Accept': 'application/json',
        },
      );

      if (appsResponse.statusCode == 401 || appsResponse.statusCode == 403) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'App Store Connect access',
            'Authentication failed for App Store Connect API '
                '(HTTP ${appsResponse.statusCode}). ${redactStoreApiError(appsResponse.body)}',
            id: 'app-store-connect-access',
            confidence: FindingConfidence.high,
            source: FindingSource.liveApi,
            evidenceSummary: 'HTTP ${appsResponse.statusCode} from ASC API',
            fix:
                'Verify issuer ID, key ID, and .p8 key permissions for this bundle.',
          ),
        );
        return;
      }

      if (appsResponse.statusCode < 200 || appsResponse.statusCode >= 300) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'App Store Connect access',
            'App Store Connect API returned HTTP ${appsResponse.statusCode} for bundle `$bundle`. '
                '${redactStoreApiError(appsResponse.body)}',
            id: 'app-store-connect-access',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return;
      }

      final data = appsResponse.jsonBody?['data'];
      if (data is! List || data.isEmpty) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'App Store Connect access',
            'Bundle `$bundle` was not found via App Store Connect API (empty data).',
            id: 'app-store-connect-access',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return;
      }

      final app = data.first;
      final appId = app is Map ? app['id']?.toString() : null;
      findings.add(
        Finding(
          FindingLevel.passed,
          'App Store Connect access',
          'Bundle `$bundle` is accessible via App Store Connect API.',
          id: 'app-store-connect-access',
          confidence: FindingConfidence.high,
          source: FindingSource.liveApi,
          evidenceSummary: 'ASC apps filter by bundleId matched',
        ),
      );

      if (appId == null || appId.isEmpty) {
        findings.add(
          const Finding(
            FindingLevel.manualReview,
            'TestFlight build status',
            'App id missing from ASC response; TestFlight builds could not be queried.',
            id: 'testflight-build-status',
            confidence: FindingConfidence.low,
            source: FindingSource.liveApi,
          ),
        );
        return;
      }

      final buildsResponse = await http.get(
        Uri.parse(
          'https://api.appstoreconnect.apple.com/v1/builds'
          '?filter[app]=${Uri.encodeQueryComponent(appId)}'
          '&limit=5'
          '&sort=-uploadedDate',
        ),
        headers: {
          'Authorization': 'Bearer $token',
          'Accept': 'application/json',
        },
      );

      if (buildsResponse.statusCode < 200 || buildsResponse.statusCode >= 300) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'TestFlight build status',
            'Could not list builds for `$bundle` (HTTP ${buildsResponse.statusCode}). '
                '${redactStoreApiError(buildsResponse.body)}',
            id: 'testflight-build-status',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return;
      }

      final builds = buildsResponse.jsonBody?['data'];
      if (builds is! List || builds.isEmpty) {
        findings.add(
          Finding(
            FindingLevel.info,
            'TestFlight build status',
            'No builds returned for `$bundle`.',
            id: 'testflight-build-status',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return;
      }

      final latest = builds.first;
      final attrs = latest is Map ? latest['attributes'] : null;
      final processing = attrs is Map
          ? attrs['processingState']?.toString() ?? 'unknown'
          : 'unknown';
      final version =
          attrs is Map ? attrs['version']?.toString() ?? 'unknown' : 'unknown';
      final uploaded = attrs is Map
          ? attrs['uploadedDate']?.toString() ?? 'unknown'
          : 'unknown';
      findings.add(
        Finding(
          FindingLevel.info,
          'TestFlight build status',
          'Latest build for `$bundle`: version=$version processingState=$processing uploadedDate=$uploaded.',
          id: 'testflight-build-status',
          confidence: FindingConfidence.medium,
          source: FindingSource.liveApi,
          evidenceSummary: 'ASC builds sorted by uploadedDate',
        ),
      );
    } catch (e) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'App Store Connect access',
          'App Store Connect live verification failed: ${redactStoreApiError(e.toString())}',
          id: 'app-store-connect-access',
          confidence: FindingConfidence.medium,
          source: FindingSource.liveApi,
        ),
      );
    }
  }

  Future<String?> _resolveJwt(List<Finding> findings) async {
    final envToken = environment['APP_STORE_CONNECT_ACCESS_TOKEN']?.trim();
    if (envToken != null && envToken.isNotEmpty) {
      return envToken;
    }

    final issuer = environment['APP_STORE_CONNECT_ISSUER_ID']?.trim();
    final keyId = environment['APP_STORE_CONNECT_KEY_ID']?.trim();
    final keyPath = environment['APP_STORE_CONNECT_PRIVATE_KEY_PATH']?.trim();
    final keyInline = environment['APP_STORE_CONNECT_PRIVATE_KEY']?.trim();

    if (issuer == null ||
        issuer.isEmpty ||
        keyId == null ||
        keyId.isEmpty ||
        ((keyPath == null || keyPath.isEmpty) &&
            (keyInline == null || keyInline.isEmpty))) {
      findings.add(
        const Finding(
          FindingLevel.info,
          'App Store Connect credentials',
          'App Store Connect live check skipped: no credentials in environment. '
              'Set APP_STORE_CONNECT_ACCESS_TOKEN, or APP_STORE_CONNECT_ISSUER_ID + '
              'APP_STORE_CONNECT_KEY_ID + APP_STORE_CONNECT_PRIVATE_KEY_PATH (or PRIVATE_KEY). '
              'Missing optional credentials do not reduce the release score.',
          id: 'app-store-connect-access',
          confidence: FindingConfidence.low,
          source: FindingSource.liveApi,
          evidenceSummary: 'No ASC credentials in environment',
        ),
      );
      return null;
    }

    try {
      String pem;
      if (keyInline != null && keyInline.isNotEmpty) {
        pem = keyInline.contains('\\n')
            ? keyInline.replaceAll('\\n', '\n')
            : keyInline;
      } else {
        final reader = readFile ?? (String p) => File(p).readAsString();
        pem = await reader(keyPath!);
      }

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final jwt = JWT(
        {
          'iss': issuer,
          'iat': now,
          'exp': now + 20 * 60,
          'aud': 'appstoreconnect-v1',
        },
        header: {'kid': keyId, 'typ': 'JWT'},
      );
      return jwt.sign(
        ECPrivateKey(pem),
        algorithm: JWTAlgorithm.ES256,
      );
    } catch (e) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'App Store Connect credentials',
          'Could not mint App Store Connect JWT. ${redactStoreApiError(e.toString())}',
          id: 'app-store-connect-access',
          confidence: FindingConfidence.medium,
          source: FindingSource.liveApi,
        ),
      );
      return null;
    }
  }
}
