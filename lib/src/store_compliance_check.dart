import 'dart:io';

import 'package:flutter_release_doctor/src/doctor_config.dart';
import 'package:flutter_release_doctor/src/evidence.dart';
import 'package:flutter_release_doctor/src/finding.dart';
import 'package:flutter_release_doctor/src/guidelines/guideline_registry.dart';

/// Offline Google Play / App Store *guideline risk* scanner.
///
/// Uses the versioned [GuidelineRuleRegistry]. Never calls Google Play or
/// App Store Connect APIs. Never claims guaranteed approval or rejection.
class StoreComplianceCheck {
  StoreComplianceCheck({
    required this.storeCompliance,
    required this.transactionType,
    this.storeProfile = StoreProfile.empty,
  });

  final StoreComplianceConfig storeCompliance;
  final TransactionType transactionType;
  final StoreProfile storeProfile;

  static const disclaimer = GuidelineRuleRegistry.disclaimer;
  static const guidelineVersion = GuidelineRuleRegistry.guidelineVersion;

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
      Finding(
        FindingLevel.info,
        'Store guideline risk disclaimer',
        disclaimer,
        id: 'store-guideline-risk-disclaimer',
        ruleVersion: guidelineVersion,
        platform: GuidelinePlatform.both,
        evidenceSummary: 'Offline guideline registry $guidelineVersion',
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
        GuidelineRuleRegistry.playPrivacyPolicy.finding(
          FindingLevel.warning,
          'Sensitive Android permissions were detected but `privacy_policy_url` is not configured. '
          'Potential rejection risk if personal/sensitive data is collected without a public privacy policy.',
          file: s.androidManifestFile,
          line: s.androidManifestLine,
          evidence:
              'Sensitive Android permission(s) without configured privacy_policy_url',
          fix:
              'Set store_compliance.privacy_policy_url in `.release-doctor.yaml` and host a real privacy policy.',
        ),
      );
    }

    if (s.hasSensitiveAndroidPermissions) {
      findings.add(
        GuidelineRuleRegistry.playSensitivePermissions.finding(
          FindingLevel.manualReview,
          'Sensitive Android permissions / APIs were detected. Confirm each permission is justified and accurately declared in Play Data Safety. '
          'Static analysis cannot prove declaration completeness.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          file: s.androidManifestFile,
          line: s.androidManifestLine,
          evidence: 'Sensitive Android permission declaration(s)',
          fix:
              'Review Play Console Data Safety and remove unused sensitive permissions.',
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
        GuidelineRuleRegistry.playDataSafety.finding(
          FindingLevel.manualReview,
          'Permissions, analytics, Firebase, location, camera, contacts, and/or advertising SDKs were detected. '
          'Play Console Data Safety declarations require manual review — this tool never claims Data Safety forms are complete.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          file: s.dataSafetyEvidenceFile,
          line: s.dataSafetyEvidenceLine,
          evidence: 'Data-collection related SDK/permission signals present',
          fix:
              'Reconcile collected data types, sharing, and purposes in Play Console Data Safety against actual SDK/permission usage.',
        ),
      );
    }

    final accountRequired =
        cfg.accountRequired == true || storeProfile.hasUserAccounts == true;
    if (accountRequired && !cfg.hasAccountDeletionUrl) {
      findings.add(
        GuidelineRuleRegistry.playAccountDeletion.finding(
          FindingLevel.warning,
          '`account_required` / has_user_accounts is true but `account_deletion_url` is not configured. '
          'Potential rejection risk under Google Play account deletion expectations.',
          source: FindingSource.projectConfig,
          fix:
              'Provide store_compliance.account_deletion_url and implement account deletion.',
        ),
      );
    }

    final isPhysical = storeProfile.isPhysicalGoodsOnly ||
        transactionType == TransactionType.physicalGoods;
    final isDigital = !isPhysical &&
        (storeProfile.isDigitalLike ||
            transactionType == TransactionType.digitalGoods ||
            transactionType == TransactionType.subscription);
    if (isDigital && s.hasExternalPayment && !s.hasBilling) {
      findings.add(
        GuidelineRuleRegistry.playBillingBypass.finding(
          FindingLevel.warning,
          'Digital goods/subscription profile and an external payment flow appear present without detectable Google Play Billing / in_app_purchase. '
          'Potential rejection risk under Google Play Payments policy for digital goods.',
          file: s.externalPaymentFile,
          line: s.externalPaymentLine,
          evidence: 'External payment without Play Billing dependency',
          fix:
              'Use Google Play Billing for digital goods/subscriptions, or confirm an allowed exception with counsel.',
        ),
      );
    }

    if (isPhysical) {
      findings.add(
        GuidelineRuleRegistry.playPhysicalGoods.finding(
          FindingLevel.passed,
          'business_model/transaction_type is physical_goods. Google Play Payments policy generally permits external payment methods for physical goods and offline services; Play Billing is not required for those cases. '
          'This is risk framing only — not a store approval certificate.',
          confidence: FindingConfidence.high,
          source: FindingSource.projectConfig,
        ),
      );
    }

    findings.add(
      GuidelineRuleRegistry.playFamilies.finding(
        FindingLevel.manualReview,
        'Target audience and Families / Designed for Families compliance cannot be determined from static analysis. '
        'Do not guess age ratings — review Play Console target audience settings manually.',
        confidence: FindingConfidence.low,
        source: FindingSource.manualReview,
        evidence: 'Static analysis cannot prove Families / target audience',
        fix:
            'Confirm target audience and Families policy requirements in Play Console before release.',
      ),
    );

    if (s.hasInsecureHttp) {
      findings.add(
        GuidelineRuleRegistry.playInsecureNetworking.finding(
          FindingLevel.warning,
          'Non-local HTTP endpoints were detected. Potential rejection risk and user-data exposure under Play network security expectations.',
          confidence: FindingConfidence.high,
          file: s.insecureHttpFile,
          line: s.insecureHttpLine,
          evidence: 'Non-local http:// endpoint in project sources',
          fix: 'Use HTTPS for production endpoints; avoid cleartext traffic.',
        ),
      );
    }

    if (s.androidReleaseSigningMissing) {
      findings.add(
        GuidelineRuleRegistry.playSigningReadiness.finding(
          FindingLevel.warning,
          'Android release signingConfig / key.properties could not be confirmed. '
          'Potential rejection risk or blocked Play upload if release builds are unsigned.',
          confidence: FindingConfidence.medium,
          file: s.signingEvidenceFile,
          line: s.signingEvidenceLine,
          evidence: 'Release signingConfig not resolved',
          fix:
              'Configure a release signingConfig (typically via key.properties) for store builds.',
        ),
      );
    } else if (s.androidHasReleaseGradle) {
      findings.add(
        GuidelineRuleRegistry.playSigningReadiness.finding(
          FindingLevel.manualReview,
          'Release Gradle configuration was found. Confirm Play App Signing and keystore handling manually — static analysis cannot prove store upload readiness.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          file: s.signingEvidenceFile,
          evidence: 'Android release build configuration present',
        ),
      );
    }

    if (accountRequired &&
        cfg.demoAccountProvided == false &&
        storeProfile.reviewerDemoAccount != true) {
      findings.add(
        GuidelineRuleRegistry.playReviewerAccess.finding(
          FindingLevel.warning,
          'Accounts appear required and reviewer demo access is not confirmed. '
          'Potential rejection risk if Play reviewers cannot access gated features.',
          source: FindingSource.projectConfig,
          fix:
              'Provide reviewer instructions / demo credentials in Play Console and set demo_account_provided / reviewer_demo_account when ready.',
        ),
      );
    }
  }

  void _analyzeApple(_Signals s, List<Finding> findings) {
    final cfg = storeCompliance;

    if (s.hasIosPrivacyDescriptions && !cfg.hasPrivacyPolicyUrl) {
      findings.add(
        GuidelineRuleRegistry.applePrivacyPolicy.finding(
          FindingLevel.warning,
          'Sensitive iOS usage descriptions were detected but `privacy_policy_url` is not configured. '
          'Potential rejection risk under App Review 5.1 privacy expectations when personal data is collected.',
          file: s.infoPlistFile,
          line: s.infoPlistLine,
          evidence: 'iOS usage description(s) without privacy_policy_url',
          fix:
              'Set store_compliance.privacy_policy_url and ensure App Privacy / privacy policy links are accurate.',
        ),
      );
    }

    final accountRequired =
        cfg.accountRequired == true || storeProfile.hasUserAccounts == true;
    if (accountRequired && !cfg.hasAccountDeletionUrl) {
      findings.add(
        GuidelineRuleRegistry.appleAccountDeletion.finding(
          FindingLevel.warning,
          '`account_required` / has_user_accounts is true but `account_deletion_url` is not configured. '
          'Potential rejection risk under App Review 5.1.1(v) account deletion.',
          source: FindingSource.projectConfig,
          fix:
              'Provide store_compliance.account_deletion_url and an in-app deletion flow.',
        ),
      );
    }

    final firstPartyAuth = storeProfile.isFirstPartyAuthOnly;
    if (s.hasSocialLogin &&
        !s.hasSignInWithApple &&
        !firstPartyAuth &&
        storeProfile.authentication != StoreAuthentication.emailPassword &&
        storeProfile.authentication != StoreAuthentication.phoneOtp) {
      findings.add(
        GuidelineRuleRegistry.appleSignInWithApple.finding(
          FindingLevel.warning,
          'Third-party/social sign-in appears present, but Sign in with Apple configuration was not detected. '
          'Potential rejection risk under App Review 4.8 Login Services.',
          file: s.socialLoginFile,
          line: s.socialLoginLine,
          evidence: 'Social login dependency/usage without Sign in with Apple',
          fix:
              'Add Sign in with Apple if Guideline 4.8 applies, or document why an exception applies.',
        ),
      );
    } else if (s.hasOwnAuthOnly || firstPartyAuth) {
      findings.add(
        GuidelineRuleRegistry.appleSignInWithApple.finding(
          FindingLevel.info,
          'Only first-party email/password/phone login signals were detected (or store_profile.authentication declares first-party login). '
          'Sign in with Apple is typically not required for that pattern, but static analysis may miss custom OAuth.',
          confidence: FindingConfidence.low,
          source: FindingSource.projectConfig,
          file: s.ownAuthFile,
          line: s.ownAuthLine,
          evidence: 'First-party auth profile or email/phone login signals',
        ),
      );
    }

    final trackingDeclared =
        cfg.usesTracking != null || storeProfile.usesTracking != null;
    final usesTracking =
        cfg.usesTracking == true || storeProfile.usesTracking == true;
    if ((s.hasAds || s.hasAdSupport || s.hasAttSignals) && !trackingDeclared) {
      findings.add(
        GuidelineRuleRegistry.appleAtt.finding(
          FindingLevel.warning,
          'Advertising/tracking SDKs or AdSupport-related signals were detected, but `uses_tracking` is not explicitly declared. '
          'Potential rejection risk for App Privacy / ATT disclosures.',
          file: s.trackingEvidenceFile,
          line: s.trackingEvidenceLine,
          evidence: 'Ads/tracking signals without uses_tracking declaration',
          fix:
              'Set store_compliance.uses_tracking or store_profile.uses_tracking after reviewing App Privacy and ATT requirements.',
        ),
      );
    }

    if (usesTracking && !s.hasAttUsageDescription) {
      findings.add(
        GuidelineRuleRegistry.appleAtt.finding(
          FindingLevel.warning,
          '`uses_tracking` is true but NSUserTrackingUsageDescription / ATT request handling was not detected. '
          'Potential rejection risk under App Review 5.1.2 tracking rules.',
          source: FindingSource.projectConfig,
          file: s.infoPlistFile,
          line: s.infoPlistLine,
          evidence: 'uses_tracking=true without ATT usage description',
          fix:
              'Add NSUserTrackingUsageDescription and request authorization before tracking.',
        ),
      );
    }

    final isPhysical = storeProfile.isPhysicalGoodsOnly ||
        transactionType == TransactionType.physicalGoods;
    final isDigital = !isPhysical &&
        (storeProfile.isDigitalLike ||
            transactionType == TransactionType.digitalGoods ||
            transactionType == TransactionType.subscription);
    if (isDigital && !s.hasBilling) {
      findings.add(
        GuidelineRuleRegistry.appleIap.finding(
          FindingLevel.warning,
          'Digital goods/subscription profile but Apple In-App Purchase / in_app_purchase support was not detected. '
          'Potential rejection risk under App Review 3.1 Payments.',
          fix:
              'Integrate StoreKit / in_app_purchase for digital content, or confirm an allowed Reader/multiplatform exception.',
        ),
      );
    }

    if (isPhysical) {
      findings.add(
        GuidelineRuleRegistry.applePhysicalGoods.finding(
          FindingLevel.passed,
          'business_model/transaction_type is physical_goods. Guideline 3.1.5(a) generally allows external payment methods for goods/services consumed outside the app. '
          'This is risk framing only — not a store approval certificate.',
          confidence: FindingConfidence.high,
          source: FindingSource.projectConfig,
        ),
      );
    }

    final demoMissing =
        (cfg.accountRequired == true || storeProfile.hasUserAccounts == true) &&
            (cfg.demoAccountProvided == false ||
                storeProfile.reviewerDemoAccount == false);
    if (demoMissing && storeProfile.reviewerDemoAccount != true) {
      findings.add(
        GuidelineRuleRegistry.appleReviewerAccess.finding(
          FindingLevel.warning,
          'Accounts appear required and reviewer demo account is not confirmed. '
          'Potential rejection risk under App Review 2.1 App Completeness.',
          source: FindingSource.projectConfig,
          fix:
              'Provide a demo account in App Store Connect review notes and set reviewer_demo_account / demo_account_provided: true when ready.',
        ),
      );
    }

    final ugc = cfg.userGeneratedContent == true ||
        storeProfile.hasUserGeneratedContent == true;
    if (ugc && storeProfile.hasUserGeneratedContent != false) {
      findings.add(
        GuidelineRuleRegistry.appleUgc.finding(
          FindingLevel.manualReview,
          '`user_generated_content` / has_user_generated_content is true. '
          'Filtering, reporting, blocking, and contact mechanisms require manual product/legal review.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          fix:
              'Verify moderation, report/block flows, and published contact methods before submission.',
        ),
      );
    }

    if (s.hasIosPrivacyDescriptions && !s.hasAppPrivacyManifest) {
      findings.add(
        GuidelineRuleRegistry.applePrivacyManifest.finding(
          FindingLevel.warning,
          'Privacy-sensitive iOS usage was detected but an app-owned PrivacyInfo.xcprivacy was not found. '
          'Potential rejection risk for privacy manifest / required-reason API declarations.',
          file: s.infoPlistFile,
          line: s.infoPlistLine,
          evidence: 'Sensitive iOS usage without app PrivacyInfo.xcprivacy',
          fix:
              'Add ios/Runner/PrivacyInfo.xcprivacy covering required-reason APIs and tracked data.',
        ),
      );
    } else if (s.hasIosPrivacyDescriptions && s.hasAppPrivacyManifest) {
      findings.add(
        GuidelineRuleRegistry.applePrivacyManifest.finding(
          FindingLevel.manualReview,
          'PrivacyInfo.xcprivacy was found. Confirm required-reason APIs and tracking declarations match real usage — static analysis cannot prove completeness.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          file: s.privacyManifestFile,
          evidence: 'App-owned PrivacyInfo.xcprivacy present',
        ),
      );
    }

    if (s.hasEmptyIosPurposeString) {
      findings.add(
        GuidelineRuleRegistry.applePermissionStrings.finding(
          FindingLevel.warning,
          'One or more iOS permission purpose strings appear empty or placeholder-like. '
          'Potential rejection risk under App Review 5.1.1 permission purpose string rules.',
          file: s.infoPlistFile,
          line: s.emptyPurposeLine,
          evidence: 'Empty or placeholder NS*UsageDescription value',
          fix:
              'Provide clear, user-facing purpose strings for each sensitive permission.',
        ),
      );
    } else if (s.hasIosPrivacyDescriptions) {
      findings.add(
        GuidelineRuleRegistry.applePermissionStrings.finding(
          FindingLevel.manualReview,
          'iOS permission purpose strings were detected. Confirm wording accurately describes use — static analysis cannot prove App Review acceptability.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          file: s.infoPlistFile,
          line: s.infoPlistLine,
          evidence: 'NS*UsageDescription keys present',
        ),
      );
    }

    if (storeProfile.usesUniversalLinks == true &&
        !s.hasAssociatedDomainsApplinks) {
      findings.add(
        GuidelineRuleRegistry.appleUniversalLinks.finding(
          FindingLevel.warning,
          'store_profile.uses_universal_links=true but applinks associated domains were not detected in Runner entitlements. '
          'Potential rejection risk or broken Universal Links configuration.',
          file: s.entitlementsFile,
          evidence:
              'Profile expects Universal Links; entitlements missing applinks',
          fix:
              'Add com.apple.developer.associated-domains with applinks: entries in Runner entitlements.',
        ),
      );
    } else if (s.hasAssociatedDomainsKey && !s.hasAssociatedDomainsApplinks) {
      findings.add(
        GuidelineRuleRegistry.appleUniversalLinks.finding(
          FindingLevel.manualReview,
          'associated-domains entitlement is present without clear applinks: entries. Manual review required for Universal Links setup.',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          file: s.entitlementsFile,
          evidence: 'associated-domains key without applinks entries',
        ),
      );
    } else if (storeProfile.usesUniversalLinks != false) {
      findings.add(
        GuidelineRuleRegistry.appleUniversalLinks.finding(
          FindingLevel.manualReview,
          'Universal Links / associated domains cannot be fully validated offline (AASA hosting and entitlement alignment require manual review).',
          confidence: FindingConfidence.low,
          source: FindingSource.manualReview,
          evidence: 'Offline scan cannot prove Universal Links end-to-end',
          fix:
              'Verify applinks entitlements and apple-app-site-association hosting before release.',
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
      final emptyPurpose = RegExp(
        r'<key>\s*(NS\w+UsageDescription)\s*</key>\s*<string>\s*(TODO|TBD|changeme|xxx|test|\.{0,3})\s*</string>',
        caseSensitive: false,
      ).firstMatch(text);
      final blankPurpose = RegExp(
        r'<key>\s*(NS\w+UsageDescription)\s*</key>\s*<string>\s*</string>',
        caseSensitive: false,
      ).firstMatch(text);
      final purposeHit = emptyPurpose ?? blankPurpose;
      if (purposeHit != null) {
        signals.hasEmptyIosPurposeString = true;
        signals.emptyPurposeLine =
            Evidence.lineOfOffset(text, purposeHit.start);
      }
    }

    final privacyManifest = File(
      '${project.path}${Platform.pathSeparator}ios'
      '${Platform.pathSeparator}Runner'
      '${Platform.pathSeparator}PrivacyInfo.xcprivacy',
    );
    if (await privacyManifest.exists()) {
      signals.hasAppPrivacyManifest = true;
      signals.privacyManifestFile =
          Evidence.relativePath(project, privacyManifest);
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
      signals.entitlementsFile ??= Evidence.relativePath(project, file);
      if (_signInWithApple.hasMatch(text)) {
        signals.hasSignInWithApple = true;
      }
      if (text.contains('com.apple.developer.associated-domains')) {
        signals.hasAssociatedDomainsKey = true;
      }
      if (RegExp(r'applinks:', caseSensitive: false).hasMatch(text)) {
        signals.hasAssociatedDomainsApplinks = true;
      }
    }

    await _scanInsecureHttp(project, signals);
    await _scanAndroidSigning(project, signals);

    final lib = Directory('${project.path}${Platform.pathSeparator}lib');
    if (!await lib.exists()) {
      signals.hasDataCollectionSignals = signals.hasAnalytics ||
          signals.hasFirebase ||
          signals.hasAds ||
          signals.hasLocation ||
          signals.hasCamera ||
          signals.hasContacts ||
          signals.hasSensitiveAndroidPermissions;
      return signals;
    }

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

  Future<void> _scanInsecureHttp(Directory project, _Signals signals) async {
    final httpPattern = RegExp('http://[^\\s\'"<>]+', caseSensitive: false);
    final candidates = <File>[];
    await for (final entity in project.list(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File) continue;
      final path = entity.path.replaceAll('\\', '/');
      if (path.contains('/.git/') ||
          path.contains('/build/') ||
          path.contains('/.dart_tool/') ||
          path.contains('/ios/Pods/')) {
        continue;
      }
      if (path.endsWith('.dart') ||
          path.endsWith('.env') ||
          path.endsWith('.yaml') ||
          path.endsWith('.yml') ||
          path.endsWith('.json') ||
          path.endsWith('.plist') ||
          path.endsWith('.xml')) {
        candidates.add(entity);
      }
    }

    for (final file in candidates) {
      final text = await file.readAsString();
      for (final match in httpPattern.allMatches(text)) {
        final url = match.group(0)!.toLowerCase();
        if (url.contains('localhost') || url.contains('10.0.2.2')) continue;
        if (url.contains('www.apple.com/dtds/') ||
            url.contains('schemas.android.com/') ||
            url.contains('www.w3.org/')) {
          continue;
        }
        signals.hasInsecureHttp = true;
        signals.insecureHttpFile = Evidence.relativePath(project, file);
        signals.insecureHttpLine = Evidence.lineOfOffset(text, match.start);
        return;
      }
    }
  }

  Future<void> _scanAndroidSigning(Directory project, _Signals signals) async {
    final groovy = File(
      '${project.path}${Platform.pathSeparator}android'
      '${Platform.pathSeparator}app'
      '${Platform.pathSeparator}build.gradle',
    );
    final kts = File('${groovy.path}.kts');
    File? gradle;
    if (await groovy.exists()) {
      gradle = groovy;
    } else if (await kts.exists()) {
      gradle = kts;
    }
    if (gradle == null) return;

    signals.androidHasReleaseGradle = true;
    signals.signingEvidenceFile = Evidence.relativePath(project, gradle);
    final text = await gradle.readAsString();
    final hasSigningConfig = RegExp(
      r'signingConfigs|storeFile|key\.properties',
      caseSensitive: false,
    ).hasMatch(text);
    final hasRelease = RegExp(r'\brelease\s*\{').hasMatch(text);
    if (hasRelease && !hasSigningConfig) {
      signals.androidReleaseSigningMissing = true;
      final m = RegExp(r'\brelease\s*\{').firstMatch(text);
      if (m != null) {
        signals.signingEvidenceLine = Evidence.lineOfOffset(text, m.start);
      }
    }
  }
}

class _Signals {
  bool hasSensitiveAndroidPermissions = false;
  String? androidManifestFile;
  int? androidManifestLine;

  bool hasIosPrivacyDescriptions = false;
  String? infoPlistFile;
  int? infoPlistLine;
  bool hasEmptyIosPurposeString = false;
  int? emptyPurposeLine;

  bool hasAppPrivacyManifest = false;
  String? privacyManifestFile;

  bool hasAssociatedDomainsKey = false;
  bool hasAssociatedDomainsApplinks = false;
  String? entitlementsFile;

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

  bool hasInsecureHttp = false;
  String? insecureHttpFile;
  int? insecureHttpLine;

  bool androidHasReleaseGradle = false;
  bool androidReleaseSigningMissing = false;
  String? signingEvidenceFile;
  int? signingEvidenceLine;
}
