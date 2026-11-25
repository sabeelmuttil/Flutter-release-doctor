import 'package:flutter_release_doctor/src/auth/google_oauth_client_config.dart';

/// Endpoint/scope defaults for Google Desktop OAuth.
///
/// **No real OAuth client ID or client secret is shipped in this repository.**
/// Supply credentials outside git via:
/// - `--oauth-client-file /secure/path/client_secret_….json`
/// - `FLUTTER_RELEASE_DOCTOR_GOOGLE_OAUTH_CLIENT_FILE`
/// - `GOOGLE_OAUTH_CLIENT_ID` (+ optional `GOOGLE_OAUTH_CLIENT_SECRET`)
///
/// Never embed user tokens or service-account private keys here.
class BundledGoogleOAuthClient {
  const BundledGoogleOAuthClient._();

  /// Intentionally unset in source — real IDs must stay outside the repo.
  static const String? clientId = null;

  /// Intentionally unset in source — real secrets must stay outside the repo.
  static const String? clientSecret = null;

  static const projectId = 'flutter-release-doctor';

  static const authUri = 'https://accounts.google.com/o/oauth2/v2/auth';

  static const tokenUri = 'https://oauth2.googleapis.com/token';

  static const userInfoUri = 'https://www.googleapis.com/oauth2/v3/userinfo';

  /// Android Publisher / Google Play Developer API scope.
  static const androidPublisherScope =
      'https://www.googleapis.com/auth/androidpublisher';

  static const openIdScope = 'openid';
  static const emailScope = 'email';
  static const profileScope = 'profile';

  static const scopes = <String>[
    androidPublisherScope,
    openIdScope,
    emailScope,
    profileScope,
  ];

  /// Returns a config only when a non-empty [clientId] is configured in source.
  ///
  /// Currently always `null` so credentials are never committed.
  static GoogleOAuthClientConfig? get config {
    final id = clientId?.trim();
    if (id == null || id.isEmpty) return null;
    final secret = clientSecret?.trim();
    return GoogleOAuthClientConfig(
      clientId: id,
      projectId: projectId,
      authUri: authUri,
      tokenUri: tokenUri,
      clientType: GoogleOAuthClientType.installed,
      clientSecret: (secret == null || secret.isEmpty) ? null : secret,
    );
  }

  static const missingCredentialsHelp =
      'No Google Desktop OAuth client is configured in this build.\n'
      'Real client IDs and client secrets must stay outside the repository.\n\n'
      'Provide a Desktop OAuth client JSON (not a service-account key):\n'
      '  flutter_release_doctor connect google '
      '--oauth-client-file /secure/path/client_secret_xxx.json\n\n'
      'Or set one of:\n'
      '  FLUTTER_RELEASE_DOCTOR_GOOGLE_OAUTH_CLIENT_FILE=/secure/path/client_secret_xxx.json\n'
      '  GOOGLE_OAUTH_CLIENT_ID=….apps.googleusercontent.com\n'
      '  GOOGLE_OAUTH_CLIENT_SECRET=…   (Desktop installed-app credential only)\n\n'
      'Create a Desktop OAuth client in Google Cloud Console, download the JSON, '
      'and keep that file out of git.';
}
