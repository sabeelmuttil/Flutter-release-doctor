import 'dart:io';

import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/evidence.dart';
import 'package:flutter_release_doctor/src/finding.dart';

/// Offline Google Play / App Store *guideline risk* scanner.
///
/// Identifies risk signals only. Never claims Data Safety, App Privacy, or
/// legal compliance is complete. Never makes network calls.
class StoreComplianceCheck {
  StoreComplianceCheck({
    required this.storeCompliance,
    required this.transactionType,
  });

  final StoreComplianceConfig storeCompliance;
  final TransactionType transactionType;

  static const disclaimer =
      'Automated checks identify risk signals; store approval and legal compliance require human review.';

  static final _sensitiveAndroidPermission = RegExp(
    r'android\.permission\.(CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|'
    r'ACCESS_COARSE_LOCATION|READ_CONTACTS|WRITE_CONTACTS|READ_EXTERNAL_STORAGE|'
    r'ACCESS_BACKGROUND_LOCATION|READ_MEDIA_IMAGES|READ_PHONE_STATE)',
  );

  static final _iosPrivacyKeys = RegExp(
    r'NSCameraUsageDescription|NSMicrophoneUsageDescription|'
    r'NSLocationWhenInUseUsageDescription|NSLocationAlwaysUsageDescription|'
    r'NSLocationAlwaysAndWhenInUseUsageDescription|'
    r'NSPhotoLibraryUsageDescription|NSContactsUsageDescription|'
    r'NSUserTrackingUsageDescription',
  );

  static final _analyticsDeps = RegExp(
    r'\b(firebase_analytics|google_analytics|amplitude_flutter|mixpanel_flutter|'
    r'segment_analytics|sentry_flutter|posthog_flutter)\b',
    caseSensitive: false,
  );

  static final _firebaseDeps = RegExp(
    r'\b(firebase_core|firebase_auth|firebase_messaging|firebase_analytics|'
    r'cloud_firestore|firebase_crashlytics)\b',
    caseSensitive: false,
  );

  static final _adsDeps = RegExp(
    r'\b(google_mobile_ads|facebook_audience_network|applovin_max|'
    r'unity_ads|admob|ironsource)\b',
    caseSensitive: false,
  );

  static final _locationDeps = RegExp(
    r'\b(geolocator|location|google_maps_flutter)\b',
    caseSensitive: false,
  );

  static final _cameraDeps = RegExp(
    r'\b(camera|image_picker|photo_manager)\b',
    caseSensitive: false,
  );

  static final _contactsDeps = RegExp(
    r'\b(flutter_contacts|contacts_service)\b',
    caseSensitive: false,
  );

  static final _socialLoginDeps = RegExp(
    r'\b(google_sign_in|flutter_facebook_auth|facebook_auth|'
    r'twitter_login|sign_in_with_twitter|linkedin_login|'
    r'flutter_login_facebook)\b',
    caseSensitive: false,
  );

  static final _signInWithApple = RegExp(
    r'\b(sign_in_with_apple|SignInWithApple|ASAuthorizationAppleIDProvider|'
    r'com\.apple\.developer\.applesignin)\b',
    caseSensitive: false,
  );

  static final _socialLoginUsage = RegExp(
    r'GoogleSignIn\s*\(|FacebookAuth\.|signInWithFacebook|'
    r'signInWithGoogle|TwitterLogin\s*\(|'
    r'''OAuthProvider\s*\(\s*['"]google\.com|'''
    r'''OAuthProvider\s*\(\s*['"]facebook\.com|'''
    r'''OAuthProvider\s*\(\s*['"]twitter\.com''',
    caseSensitive: false,
  );

  static final _ownAuthOnly = RegExp(
    r'signInWithEmailAndPassword|createUserWithEmailAndPassword|'
    r'signInWithPhoneNumber|PhoneAuthProvider|EmailAuthProvider',
    caseSensitive: false,
  );

  static final _attUsage = RegExp(
    r'NSUserTrackingUsageDescription|ATTrackingManager|'
    r'requestTrackingAuthorization',
    caseSensitive: false,
  );

  static final _adSupport = RegExp(
    r'\bAdSupport\b|ASIdentifierManager|advertisingIdentifier',
    caseSensitive: false,
  );

  static final _billingDeps = RegExp(
    r'\b(in_app_purchase(?:_android|_storekit)?|purchases_flutter|'
    r'flutter_inapp_purchase)\b',
    caseSensitive: false,
  );

  static final _externalPaymentDeps = RegExp(
    r'[a-z0-9_-]*(?:stripe|razorpay|paytm|juspay|cashfree|payu|phonepe|'
    r'paypal|ccavenue|flutterwave|squareup)[a-z0-9_-]*',
    caseSensitive: false,
  );

  static final _externalPaymentUsage = RegExp(
    r'Razorpay\s*\(|razorpay\.open|Stripe\.\w+|\bStripe\b|openCheckout|'
    r'\bPaytm\b|\bJuspay\b|\bCashfree\b',
    caseSensitive: false,
  );

  Future<void> run(Directory project, List<Finding> findings) async {
    findings.add(
      const Finding(
        FindingLevel.info,
        'Store guideline risk disclaimer',
        disclaimer,
        id: 'store-guideline-risk-disclaimer',
      ),
    );

    final signals = await _scan(project);
    _analyzePlay(signals, findings);
    _analyzeApple(signals, findings);
  }

  void _analyzePlay(_Signals s, List<Finding> findings) {
    final cfg = storeCompliance;
    final hasSensitive =
        s.hasSensitiveAndroidPermissions || s.hasDataCollectionSignals;

    if (s.hasSensitiveAndroidPermissions && !cfg.hasPrivacyPolicyUrl) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Play privacy policy',
          'Sensitive Android permissions were detected but `privacy_policy_url` is not configured. '
              'Google Play User Data / privacy policy expectations require a publicly accessible policy URL when personal/sensitive data is collected (risk signal; not a compliance verdict).',
          id: 'play-privacy-policy-missing',
          file: s.androidManifestFile,
          line: s.androidManifestLine,
          fix:
              'Set store_compliance.privacy_policy_url in `.release-doctor.yaml` and host a real privacy policy.',
        ),
      );
    }

    if (hasSensitive ||
        s.hasAnalytics ||
        s.hasFirebase ||
        s.hasAds ||
        s.hasLocation ||
        s.hasCamera ||
        s.hasContacts) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Play Data Safety review',
          'Permissions, analytics, Firebase, location, camera, contacts, and/or advertising SDKs were detected. '
              'Play Console Data Safety declarations must be reviewed manually — this tool never claims Data Safety forms are complete.',
          id: 'play-data-safety-review',
          file: s.dataSafetyEvidenceFile,
          line: s.dataSafetyEvidenceLine,
          fix:
              'Reconcile collected data types, sharing, and purposes in Play Console Data Safety against actual SDK/permission usage.',
        ),
      );
    }

    if (cfg.accountRequired == true && !cfg.hasAccountDeletionUrl) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'Play account deletion',
          '`account_required` is true but `account_deletion_url` is not configured. '
              'Google Play account deletion policy expects an in-app and/or web deletion path when accounts are created (risk signal).',
          id: 'play-account-deletion-missing',
          fix:
              'Provide store_compliance.account_deletion_url and implement account deletion.',
        ),
      );
    }

    final isDigital = transactionType == TransactionType.digitalGoods ||
        transactionType == TransactionType.subscription;
    if (isDigital && s.hasExternalPayment && !s.hasBilling) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'Play Billing bypass risk',
          'transaction_type is digital_goods/subscription and an external payment flow appears present without detectable Google Play Billing / in_app_purchase. '
              'Google Play Payments policy generally requires Play Billing for digital goods (risk signal; human policy review required).',
          id: 'play-billing-bypass-risk',
          file: s.externalPaymentFile,
          line: s.externalPaymentLine,
          fix:
              'Use Google Play Billing for digital goods/subscriptions, or confirm an allowed exception with counsel.',
        ),
      );
    }

    if (transactionType == TransactionType.physicalGoods) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'Play physical goods payments',
          'transaction_type is physical_goods. Google Play Payments policy generally permits external payment methods for physical goods and offline services; Play Billing is not required for those cases (risk framing only).',
          id: 'play-physical-goods-payments-allowed',
        ),
      );
    }

    findings.add(
      const Finding(
        FindingLevel.info,
        'Play Families / target audience',
        'Target audience and Families / Designed for Families compliance cannot be determined from static analysis. Do not guess age ratings or Families requirements — review Play Console target audience settings manually.',
        id: 'play-families-audience-unknown',
      ),
    );
  }

  void _analyzeApple(_Signals s, List<Finding> findings) {
    final cfg = storeCompliance;

    if (s.hasIosPrivacyDescriptions && !cfg.hasPrivacyPolicyUrl) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'App Store privacy policy',
          'Sensitive iOS usage descriptions were detected but `privacy_policy_url` is not configured. '
              'App Store Review Guideline 5.1.1 (Data Collection and Storage) expects a privacy policy when personal data is collected (risk signal).',
          id: 'apple-privacy-policy-missing',
          file: s.infoPlistFile,
          line: s.infoPlistLine,
          fix:
              'Set store_compliance.privacy_policy_url and ensure App Privacy / privacy policy links are accurate.',
        ),
      );
    }

    if (cfg.accountRequired == true && !cfg.hasAccountDeletionUrl) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'App Store account deletion',
          '`account_required` is true but `account_deletion_url` is not configured. '
              'App Store Review Guideline 5.1.1(v) expects account deletion when account creation is offered (risk signal).',
          id: 'apple-account-deletion-missing',
          fix:
              'Provide store_compliance.account_deletion_url and an in-app deletion flow.',
        ),
      );
    }

    if (s.hasSocialLogin) {
      if (!s.hasSignInWithApple) {
        findings.add(
          Finding(
            FindingLevel.warning,
            'Sign in with Apple',
            'Third-party/social sign-in appears present, but Sign in with Apple configuration was not detected. '
                'App Store Review Guideline 4.8 (Sign in with Apple) may apply when other third-party/social logins are offered (risk signal; verify entitlement and UX manually).',
            id: 'apple-sign-in-with-apple-review',
            file: s.socialLoginFile,
            line: s.socialLoginLine,
            fix:
                'Add Sign in with Apple if Guideline 4.8 applies, or document why an exception applies.',
          ),
        );
      }
    } else if (s.hasOwnAuthOnly) {
      findings.add(
        Finding(
          FindingLevel.info,
          'Sign in with Apple',
          'Only first-party email/password/phone login signals were detected (no third-party/social login packages found). '
              'Sign in with Apple is typically not required for that pattern, but static analysis has evidence limitations and may miss custom OAuth.',
          id: 'apple-sign-in-with-apple-review',
          file: s.ownAuthFile,
          line: s.ownAuthLine,
        ),
      );
    }

    final trackingDeclared = cfg.usesTracking != null;
    if ((s.hasAds || s.hasAdSupport || s.hasAttSignals) && !trackingDeclared) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'App tracking declaration',
          'Advertising/tracking SDKs or AdSupport-related signals were detected, but `uses_tracking` is not explicitly declared in `.release-doctor.yaml`. '
              'App Privacy / tracking disclosures and ATT (Guideline 5.1.2) require human review (risk signal).',
          id: 'apple-att-review',
          file: s.trackingEvidenceFile,
          line: s.trackingEvidenceLine,
          fix:
              'Set store_compliance.uses_tracking to true or false after reviewing App Privacy and ATT requirements.',
        ),
      );
    }

    if (cfg.usesTracking == true && !s.hasAttUsageDescription) {
      findings.add(
        Finding(
          FindingLevel.warning,
          'App Tracking Transparency',
          '`uses_tracking` is true but NSUserTrackingUsageDescription / ATT request handling was not detected. '
              'Guideline 5.1.2 (Privacy - Data Use and Sharing) expects ATT when tracking users (risk signal).',
          id: 'apple-att-review',
          file: s.infoPlistFile,
          line: s.infoPlistLine,
          fix:
              'Add NSUserTrackingUsageDescription and request authorization before tracking.',
        ),
      );
    }

    final isDigital = transactionType == TransactionType.digitalGoods ||
        transactionType == TransactionType.subscription;
    if (isDigital && !s.hasBilling) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'App Store In-App Purchase',
          'transaction_type is digital_goods/subscription but Apple In-App Purchase / in_app_purchase support was not detected. '
              'Guideline 3.1.1 (In-App Purchase) generally requires IAP for digital goods (risk signal).',
          id: 'apple-iap-missing',
          fix:
              'Integrate StoreKit / in_app_purchase for digital content, or confirm an allowed Reader/multiplatform exception.',
        ),
      );
    }

    if (transactionType == TransactionType.physicalGoods) {
      findings.add(
        const Finding(
          FindingLevel.passed,
          'App Store physical goods payments',
          'transaction_type is physical_goods. Guideline 3.1.5(a) generally allows external payment methods for goods/services consumed outside the app (risk framing only; not a compliance certificate).',
          id: 'apple-physical-goods-payments-allowed',
        ),
      );
    }

    if (cfg.accountRequired == true && cfg.demoAccountProvided == false) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'App Review access',
          '`account_required` is true and `reviewer_access.demo_account_provided` is false. '
              'App Store Review Guideline 2.1 (App Completeness) expects demo credentials when login is required (risk signal).',
          id: 'apple-reviewer-access-missing',
          fix:
              'Provide a demo account in App Store Connect review notes and set demo_account_provided: true when ready.',
        ),
      );
    }

    if (cfg.userGeneratedContent == true) {
      findings.add(
        const Finding(
          FindingLevel.warning,
          'User-generated content',
          '`user_generated_content` is true. Guideline 1.2 (User-Generated Content) expects filtering, reporting, blocking, and contact mechanisms — these require manual product/legal review (risk signal; not auto-verified).',
          id: 'apple-ugc-moderation-review',
          fix:
              'Verify moderation, report/block flows, and published contact methods before submission.',
        ),
      );
    }
  }

  Future<_Signals> _scan(Directory project) async {
    final signals = _Signals();

    final pubspec = File(
      '${project.path}${Platform.pathSeparator}pubspec.yaml',
    );
    if (await pubspec.exists()) {
      final text = await pubspec.readAsString();
      void dep(
        RegExp pattern,
        void Function(int line) set, {
        required bool Function() already,
      }) {
        if (already()) return;
        final m = pattern.firstMatch(text);
        if (m == null) return;
        set(Evidence.lineOfOffset(text, m.start));
      }

      dep(
        _analyticsDeps,
        (line) {
          signals.hasAnalytics = true;
          signals.dataSafetyEvidenceFile ??= 'pubspec.yaml';
          signals.dataSafetyEvidenceLine ??= line;
        },
        already: () => signals.hasAnalytics,
      );
      dep(
        _firebaseDeps,
        (line) {
          signals.hasFirebase = true;
          signals.dataSafetyEvidenceFile ??= 'pubspec.yaml';
          signals.dataSafetyEvidenceLine ??= line;
        },
        already: () => signals.hasFirebase,
      );
      dep(
        _adsDeps,
        (line) {
          signals.hasAds = true;
          signals.trackingEvidenceFile ??= 'pubspec.yaml';
          signals.trackingEvidenceLine ??= line;
          signals.dataSafetyEvidenceFile ??= 'pubspec.yaml';
          signals.dataSafetyEvidenceLine ??= line;
        },
        already: () => signals.hasAds,
      );
      dep(
        _locationDeps,
        (line) {
          signals.hasLocation = true;
          signals.dataSafetyEvidenceFile ??= 'pubspec.yaml';
          signals.dataSafetyEvidenceLine ??= line;
        },
        already: () => signals.hasLocation,
      );
      dep(
        _cameraDeps,
        (line) {
          signals.hasCamera = true;
          signals.dataSafetyEvidenceFile ??= 'pubspec.yaml';
          signals.dataSafetyEvidenceLine ??= line;
        },
        already: () => signals.hasCamera,
      );
      dep(
        _contactsDeps,
        (line) {
          signals.hasContacts = true;
          signals.dataSafetyEvidenceFile ??= 'pubspec.yaml';
          signals.dataSafetyEvidenceLine ??= line;
        },
        already: () => signals.hasContacts,
      );
      dep(
        _socialLoginDeps,
        (line) {
          signals.hasSocialLogin = true;
          signals.socialLoginFile ??= 'pubspec.yaml';
          signals.socialLoginLine ??= line;
        },
        already: () => signals.hasSocialLogin,
      );
      dep(
        _signInWithApple,
        (line) {
          signals.hasSignInWithApple = true;
        },
        already: () => signals.hasSignInWithApple,
      );
      dep(
        _billingDeps,
        (line) {
          signals.hasBilling = true;
        },
        already: () => signals.hasBilling,
      );
      dep(
        _externalPaymentDeps,
        (line) {
          signals.hasExternalPayment = true;
          signals.externalPaymentFile ??= 'pubspec.yaml';
          signals.externalPaymentLine ??= line;
        },
        already: () => signals.hasExternalPayment,
      );
    }

    final gs = File(
      '${project.path}${Platform.pathSeparator}android'
      '${Platform.pathSeparator}app'
      '${Platform.pathSeparator}google-services.json',
    );
    if (await gs.exists()) {
      signals.hasFirebase = true;
      signals.dataSafetyEvidenceFile ??= 'android/app/google-services.json';
      signals.dataSafetyEvidenceLine ??= 1;
    }

    final manifest = File(
      '${project.path}${Platform.pathSeparator}android'
      '${Platform.pathSeparator}app'
      '${Platform.pathSeparator}src'
      '${Platform.pathSeparator}main'
      '${Platform.pathSeparator}AndroidManifest.xml',
    );
    if (await manifest.exists()) {
      final text = await manifest.readAsString();
      final m = _sensitiveAndroidPermission.firstMatch(text);
      if (m != null) {
        signals.hasSensitiveAndroidPermissions = true;
        signals.androidManifestFile = Evidence.relativePath(project, manifest);
        signals.androidManifestLine = Evidence.lineOfOffset(text, m.start);
        signals.dataSafetyEvidenceFile ??= signals.androidManifestFile;
        signals.dataSafetyEvidenceLine ??= signals.androidManifestLine;
        if (text.contains('LOCATION')) signals.hasLocation = true;
        if (text.contains('CAMERA')) signals.hasCamera = true;
        if (text.contains('CONTACTS')) signals.hasContacts = true;
      }
    }

    final infoPlist = File(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner'
      '${Platform.pathSeparator}Info.plist',
    );
    if (await infoPlist.exists()) {
      final text = await infoPlist.readAsString();
      final m = _iosPrivacyKeys.firstMatch(text);
      if (m != null) {
        signals.hasIosPrivacyDescriptions = true;
        signals.infoPlistFile = Evidence.relativePath(project, infoPlist);
        signals.infoPlistLine = Evidence.lineOfOffset(text, m.start);
      }
      if (text.contains('NSUserTrackingUsageDescription')) {
        signals.hasAttUsageDescription = true;
        signals.hasAttSignals = true;
        signals.trackingEvidenceFile ??= signals.infoPlistFile;
        signals.trackingEvidenceLine ??= Evidence.lineOfOffset(
            text, text.indexOf('NSUserTrackingUsageDescription'));
      }
    }

    final entitlements = <File>[
      File(
        '${project.path}${Platform.pathSeparator}ios'
        '${Platform.pathSeparator}Runner'
        '${Platform.pathSeparator}Runner.entitlements',
      ),
      File(
        '${project.path}${Platform.pathSeparator}ios'
        '${Platform.pathSeparator}Runner'
        '${Platform.pathSeparator}DebugProfile.entitlements',
      ),
      File(
        '${project.path}${Platform.pathSeparator}ios'
        '${Platform.pathSeparator}Runner'
        '${Platform.pathSeparator}Release.entitlements',
      ),
    ];
    for (final file in entitlements) {
      if (!await file.exists()) continue;
      final text = await file.readAsString();
      if (_signInWithApple.hasMatch(text)) {
        signals.hasSignInWithApple = true;
        break;
      }
    }

    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    if (!await lib.exists()) return signals;

    await for (final entity in lib.list(recursive: true, followLinks: false)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      final relative = Evidence.relativePath(project, entity);
      final text = await entity.readAsString();

      if (!signals.hasSocialLogin && _socialLoginUsage.hasMatch(text)) {
        signals.hasSocialLogin = true;
        final m = _socialLoginUsage.firstMatch(text)!;
        signals.socialLoginFile = relative;
        signals.socialLoginLine = Evidence.lineOfOffset(text, m.start);
      }
      if (!signals.hasSignInWithApple && _signInWithApple.hasMatch(text)) {
        signals.hasSignInWithApple = true;
      }
      if (!signals.hasOwnAuthOnly && _ownAuthOnly.hasMatch(text)) {
        signals.hasOwnAuthOnly = true;
        final m = _ownAuthOnly.firstMatch(text)!;
        signals.ownAuthFile = relative;
        signals.ownAuthLine = Evidence.lineOfOffset(text, m.start);
      }
      if (!signals.hasExternalPayment && _externalPaymentUsage.hasMatch(text)) {
        signals.hasExternalPayment = true;
        final m = _externalPaymentUsage.firstMatch(text)!;
        signals.externalPaymentFile = relative;
        signals.externalPaymentLine = Evidence.lineOfOffset(text, m.start);
      }
      if (!signals.hasAttSignals && _attUsage.hasMatch(text)) {
        signals.hasAttSignals = true;
        final m = _attUsage.firstMatch(text)!;
        signals.trackingEvidenceFile ??= relative;
        signals.trackingEvidenceLine ??= Evidence.lineOfOffset(text, m.start);
      }
      if (!signals.hasAdSupport && _adSupport.hasMatch(text)) {
        signals.hasAdSupport = true;
        final m = _adSupport.firstMatch(text)!;
        signals.trackingEvidenceFile ??= relative;
        signals.trackingEvidenceLine ??= Evidence.lineOfOffset(text, m.start);
      }
      if (!signals.hasBilling && _billingDeps.hasMatch(text)) {
        signals.hasBilling = true;
      }
    }

    signals.hasDataCollectionSignals = signals.hasAnalytics ||
        signals.hasFirebase ||
        signals.hasAds ||
        signals.hasLocation ||
        signals.hasCamera ||
        signals.hasContacts ||
        signals.hasSensitiveAndroidPermissions;

    return signals;
  }
}

class _Signals {
  bool hasSensitiveAndroidPermissions = false;
  String? androidManifestFile;
  int? androidManifestLine;

  bool hasIosPrivacyDescriptions = false;
  String? infoPlistFile;
  int? infoPlistLine;

  bool hasAnalytics = false;
  bool hasFirebase = false;
  bool hasAds = false;
  bool hasLocation = false;
  bool hasCamera = false;
  bool hasContacts = false;
  bool hasDataCollectionSignals = false;
  String? dataSafetyEvidenceFile;
  int? dataSafetyEvidenceLine;

  bool hasSocialLogin = false;
  String? socialLoginFile;
  int? socialLoginLine;

  bool hasSignInWithApple = false;
  bool hasOwnAuthOnly = false;
  String? ownAuthFile;
  int? ownAuthLine;

  bool hasAttUsageDescription = false;
  bool hasAttSignals = false;
  bool hasAdSupport = false;
  String? trackingEvidenceFile;
  int? trackingEvidenceLine;

  bool hasBilling = false;
  bool hasExternalPayment = false;
  String? externalPaymentFile;
  int? externalPaymentLine;
}
