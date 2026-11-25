import 'dart:convert';
import 'dart:io';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:flutter_release_doctor/src/auth/auth_commands.dart';
import 'package:flutter_release_doctor/src/auth/google_token_store.dart';
import 'package:flutter_release_doctor/src/finding.dart';
import 'package:flutter_release_doctor/src/live_store/store_http.dart';

/// Offline-safe Google Play Developer API verification (network only when asked).
class GooglePlayLiveCheck {
  GooglePlayLiveCheck({
    required this.http,
    required this.environment,
    this.packageName,
    this.readFile,
    this.googleTokenStore,
  });

  final StoreHttpClient http;
  final Map<String, String> environment;
  final String? packageName;
  final Future<String> Function(String path)? readFile;
  final GoogleTokenStore? googleTokenStore;

  Future<void> run(List<Finding> findings) async {
    final pkg = packageName?.trim();
    if (pkg == null || pkg.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.manualReview,
          'Google Play package',
          'No Google Play package_name configured and none could be resolved. '
              'Set store_integrations.google_play.package_name or ensure Android applicationId is detectable.',
          id: 'store-api-access',
          confidence: FindingConfidence.low,
          source: FindingSource.liveApi,
        ),
      );
      return;
    }

    final token = await _resolveAccessToken(findings);
    if (token == null) return;

    try {
      // Create a short-lived edit to list tracks / release status.
      final editResponse = await http.post(
        Uri.parse(
          'https://androidpublisher.googleapis.com/androidpublisher/v3/'
          'applications/${Uri.encodeComponent(pkg)}/edits',
        ),
        headers: {
          'Authorization': 'Bearer $token',
          'Content-Type': 'application/json',
        },
        body: '{}',
      );

      if (editResponse.statusCode == 401 || editResponse.statusCode == 403) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Google Play API access',
            'Authentication or authorization failed when contacting Google Play Developer API '
                'for package `$pkg` (HTTP ${editResponse.statusCode}). '
                '${redactStoreApiError(editResponse.body)}',
            id: 'store-api-access',
            confidence: FindingConfidence.high,
            source: FindingSource.liveApi,
            evidenceSummary: 'HTTP ${editResponse.statusCode} from Play API',
            fix:
                'Sign in with `flutter_release_doctor connect google`, or verify '
                'the Google account / service account has Play Console API access for this app.',
          ),
        );
        return;
      }

      if (editResponse.statusCode < 200 || editResponse.statusCode >= 300) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Google Play API access',
            'Google Play Developer API returned HTTP ${editResponse.statusCode} for package `$pkg`. '
                '${redactStoreApiError(editResponse.body)}',
            id: 'store-api-access',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
            evidenceSummary: 'Unexpected Play API status',
          ),
        );
        return;
      }

      final editId = editResponse.jsonBody?['id']?.toString();
      findings.add(
        Finding(
          FindingLevel.passed,
          'Google Play API access',
          'Package `$pkg` is accessible via Google Play Developer API.',
          id: 'store-api-access',
          confidence: FindingConfidence.high,
          source: FindingSource.liveApi,
          evidenceSummary: 'Play API edit created for package',
        ),
      );

      if (editId == null || editId.isEmpty) {
        findings.add(
          const Finding(
            FindingLevel.manualReview,
            'Google Play release status',
            'Play API edit response did not include an edit id; tracks could not be listed.',
            id: 'google-play-release-status',
            confidence: FindingConfidence.low,
            source: FindingSource.liveApi,
          ),
        );
        return;
      }

      final tracksResponse = await http.get(
        Uri.parse(
          'https://androidpublisher.googleapis.com/androidpublisher/v3/'
          'applications/${Uri.encodeComponent(pkg)}/edits/'
          '${Uri.encodeComponent(editId)}/tracks',
        ),
        headers: {'Authorization': 'Bearer $token'},
      );

      if (tracksResponse.statusCode < 200 || tracksResponse.statusCode >= 300) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Google Play release status',
            'Could not list tracks for `$pkg` (HTTP ${tracksResponse.statusCode}). '
                '${redactStoreApiError(tracksResponse.body)}',
            id: 'google-play-release-status',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
      } else {
        final summary = _summarizeTracks(tracksResponse.jsonBody);
        findings.add(
          Finding(
            FindingLevel.info,
            'Google Play release status',
            'Tracks/release summary for `$pkg`: $summary',
            id: 'google-play-release-status',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
            evidenceSummary: 'Play API tracks.list',
          ),
        );
      }

      // Vitals require Play Developer Reporting API; keep informational.
      findings.add(
        Finding(
          FindingLevel.manualReview,
          'Google Play vitals',
          'Crash/ANR vitals are not fetched by this offline-first CLI. '
              'Review Play Console vitals for `$pkg` manually. Live API data here is informational only.',
          id: 'google-play-vitals-summary',
          confidence: FindingConfidence.low,
          source: FindingSource.liveApi,
          evidenceSummary: 'Vitals require Play Console / Reporting API review',
        ),
      );
    } catch (e) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Google Play API access',
          'Google Play live verification failed: ${redactStoreApiError(e.toString())}',
          id: 'store-api-access',
          confidence: FindingConfidence.medium,
          source: FindingSource.liveApi,
        ),
      );
    }
  }

  Future<String?> _resolveAccessToken(List<Finding> findings) async {
    final resolver = GoogleAccessTokenResolver(
      http: http,
      environment: environment,
      tokenStore: googleTokenStore,
    );
    final oauthToken = await resolver.resolve();
    if (oauthToken != null && oauthToken.isNotEmpty) {
      return oauthToken;
    }

    final path = environment['GOOGLE_PLAY_SERVICE_ACCOUNT_FILE']?.trim() ??
        environment['GOOGLE_APPLICATION_CREDENTIALS']?.trim();
    if (path == null || path.isEmpty) {
      findings.add(
        const Finding(
          FindingLevel.info,
          'Google Play credentials',
          'Google Play live check skipped: not signed in and no CI credentials. '
              'Run `flutter_release_doctor connect google`, or set GOOGLE_PLAY_ACCESS_TOKEN '
              'for CI. Missing optional credentials do not reduce the release score.',
          id: 'store-api-access',
          confidence: FindingConfidence.low,
          source: FindingSource.liveApi,
          evidenceSummary: 'No OAuth session or Play API credentials',
        ),
      );
      return null;
    }

    try {
      final reader = readFile ?? (p) => File(p).readAsString();
      final raw = await reader(path);
      final json = jsonDecode(raw);
      if (json is! Map) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'Google Play credentials',
            'Service account file was not valid JSON.',
            id: 'store-api-access',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return null;
      }
      final clientEmail = json['client_email']?.toString();
      final privateKey = json['private_key']?.toString();
      final tokenUri = json['token_uri']?.toString() ??
          'https://oauth2.googleapis.com/token';
      if (clientEmail == null || privateKey == null) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'Google Play credentials',
            'Service account JSON is missing client_email or private_key fields.',
            id: 'store-api-access',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return null;
      }

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final jwt = JWT(
        {
          'iss': clientEmail,
          'scope': 'https://www.googleapis.com/auth/androidpublisher',
          'aud': tokenUri,
          'iat': now,
          'exp': now + 3600,
        },
      );
      final assertion = jwt.sign(
        RSAPrivateKey(privateKey),
        algorithm: JWTAlgorithm.RS256,
      );

      final tokenResponse = await http.post(
        Uri.parse(tokenUri),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body:
            'grant_type=${Uri.encodeComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}'
            '&assertion=${Uri.encodeComponent(assertion)}',
      );
      if (tokenResponse.statusCode < 200 || tokenResponse.statusCode >= 300) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Google Play credentials',
            'Failed to exchange service-account JWT for an access token '
                '(HTTP ${tokenResponse.statusCode}). ${redactStoreApiError(tokenResponse.body)}',
            id: 'store-api-access',
            confidence: FindingConfidence.high,
            source: FindingSource.liveApi,
          ),
        );
        return null;
      }
      final accessToken = tokenResponse.jsonBody?['access_token']?.toString();
      if (accessToken == null || accessToken.isEmpty) {
        findings.add(
          const Finding(
            FindingLevel.warning,
            'Google Play credentials',
            'Token endpoint response did not include an access_token.',
            id: 'store-api-access',
            confidence: FindingConfidence.medium,
            source: FindingSource.liveApi,
          ),
        );
        return null;
      }
      return accessToken;
    } catch (e) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Google Play credentials',
          'Could not load or use the service-account credential file. '
              '${redactStoreApiError(e.toString())}',
          id: 'store-api-access',
          confidence: FindingConfidence.medium,
          source: FindingSource.liveApi,
        ),
      );
      return null;
    }
  }

  String _summarizeTracks(Map<String, dynamic>? body) {
    if (body == null) return 'no track payload';
    final tracks = body['tracks'];
    if (tracks is! List || tracks.isEmpty) return 'no tracks returned';
    final parts = <String>[];
    for (final track in tracks) {
      if (track is! Map) continue;
      final name = track['track']?.toString() ?? 'unknown';
      final releases = track['releases'];
      if (releases is! List || releases.isEmpty) {
        parts.add('$name (no releases)');
        continue;
      }
      final release = releases.first;
      if (release is! Map) {
        parts.add(name);
        continue;
      }
      final status = release['status']?.toString() ?? 'unknown';
      final codes = release['versionCodes'];
      final codeLabel = codes is List && codes.isNotEmpty
          ? 'versionCodes=${codes.take(5).join(',')}'
          : 'versionCodes=none';
      parts.add('$name status=$status $codeLabel');
    }
    return parts.isEmpty ? 'no parseable tracks' : parts.join('; ');
  }
}
