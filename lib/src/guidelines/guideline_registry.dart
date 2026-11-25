import 'package:flutter_release_doctor/src/finding.dart';

/// A versioned offline store-guideline rule (risk signals only).
class GuidelineRule {
  const GuidelineRule({
    required this.id,
    required this.platform,
    required this.guidelineReference,
    required this.ruleVersion,
    required this.title,
    this.alwaysManualReview = false,
  });

  final String id;
  final GuidelinePlatform platform;
  final String guidelineReference;
  final String ruleVersion;
  final String title;

  /// When true, static analysis cannot prove compliance; emit MANUAL REVIEW.
  final bool alwaysManualReview;

  Finding finding(
    FindingLevel level,
    String detail, {
    FindingConfidence confidence = FindingConfidence.medium,
    FindingSource source = FindingSource.staticAnalysis,
    String? evidence,
    String? file,
    int? line,
    String? fix,
  }) {
    final riskDetail = _ensureRiskWording(detail);
    return Finding(
      level,
      title,
      riskDetail,
      id: id,
      confidence: confidence,
      source: alwaysManualReview && level == FindingLevel.warning
          ? FindingSource.manualReview
          : source,
      platform: platform,
      guidelineReference: guidelineReference,
      ruleVersion: ruleVersion,
      evidenceSummary: evidence,
      file: file,
      line: line,
      fix: fix,
    );
  }

  static String _ensureRiskWording(String detail) {
    final lower = detail.toLowerCase();
    var text = detail.trim();
    if (!lower.contains('potential rejection risk') &&
        !lower.contains('risk signal') &&
        !lower.contains('not a store approval')) {
      text = '$text This is a potential rejection risk signal, not a store '
          'approval or rejection guarantee.';
    }
    if (!lower.contains('manual review') &&
        !lower.contains('needs verification') &&
        !lower.contains('human review')) {
      text = '$text Manual review required.';
    }
    return text;
  }
}

/// Versioned offline guideline rule registry.
///
/// Live Google Play / App Store Connect APIs are **not** used here.
class GuidelineRuleRegistry {
  const GuidelineRuleRegistry._();

  /// Bumped when offline guideline rule semantics change.
  static const guidelineVersion = '2026.1';

  static const disclaimer =
      'Flutter Release Doctor is an offline store-guideline *risk scanner*. '
      'Findings indicate potential rejection risk and require manual review. '
      'They are not a store approval certificate, guaranteed approval, or '
      'guaranteed rejection. Live Play / App Store Connect APIs are optional '
      'and separate from these offline checks.';

  // —— Google Play ——

  static const playDataSafety = GuidelineRule(
    id: 'play-data-safety-review',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play User Data / Data Safety',
    ruleVersion: guidelineVersion,
    title: 'Play Data Safety review',
    alwaysManualReview: true,
  );

  static const playPrivacyPolicy = GuidelineRule(
    id: 'play-privacy-policy-missing',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play User Data / Privacy Policy',
    ruleVersion: guidelineVersion,
    title: 'Play privacy policy',
  );

  static const playAccountDeletion = GuidelineRule(
    id: 'play-account-deletion-missing',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play Account Deletion',
    ruleVersion: guidelineVersion,
    title: 'Play account deletion',
  );

  static const playSensitivePermissions = GuidelineRule(
    id: 'play-sensitive-permissions-review',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play User Data / Permissions',
    ruleVersion: guidelineVersion,
    title: 'Play sensitive permissions',
  );

  static const playBillingBypass = GuidelineRule(
    id: 'play-billing-bypass-risk',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play Payments / Digital Goods',
    ruleVersion: guidelineVersion,
    title: 'Play Billing bypass risk',
  );

  static const playPhysicalGoods = GuidelineRule(
    id: 'play-physical-goods-payments-allowed',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play Payments / Physical Goods',
    ruleVersion: guidelineVersion,
    title: 'Play physical goods payments',
  );

  static const playFamilies = GuidelineRule(
    id: 'play-families-audience-unknown',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play Families / Target Audience',
    ruleVersion: guidelineVersion,
    title: 'Play Families / target audience',
    alwaysManualReview: true,
  );

  static const playInsecureNetworking = GuidelineRule(
    id: 'play-insecure-networking-risk',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play User Data / Network Security',
    ruleVersion: guidelineVersion,
    title: 'Play insecure networking',
  );

  static const playSigningReadiness = GuidelineRule(
    id: 'play-signing-release-readiness',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play Release Readiness / App Signing',
    ruleVersion: guidelineVersion,
    title: 'Play signing / release readiness',
  );

  static const playReviewerAccess = GuidelineRule(
    id: 'play-reviewer-access-missing',
    platform: GuidelinePlatform.googlePlay,
    guidelineReference: 'Google Play App Access / Reviewer Instructions',
    ruleVersion: guidelineVersion,
    title: 'Play reviewer access',
  );

  // —— Apple ——

  static const applePrivacyPolicy = GuidelineRule(
    id: 'apple-privacy-policy-missing',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 5.1 Privacy',
    ruleVersion: guidelineVersion,
    title: 'App Store privacy policy',
  );

  static const appleAccountDeletion = GuidelineRule(
    id: 'apple-account-deletion-missing',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 5.1.1(v) Account Deletion',
    ruleVersion: guidelineVersion,
    title: 'App Store account deletion',
  );

  static const appleIap = GuidelineRule(
    id: 'apple-iap-missing',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 3.1 Payments',
    ruleVersion: guidelineVersion,
    title: 'App Store In-App Purchase',
  );

  static const applePhysicalGoods = GuidelineRule(
    id: 'apple-physical-goods-payments-allowed',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 3.1.5(a) Physical Goods',
    ruleVersion: guidelineVersion,
    title: 'App Store physical goods payments',
  );

  static const appleSignInWithApple = GuidelineRule(
    id: 'apple-sign-in-with-apple-review',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 4.8 Login Services',
    ruleVersion: guidelineVersion,
    title: 'Sign in with Apple',
  );

  static const applePrivacyManifest = GuidelineRule(
    id: 'apple-privacy-manifest-review',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple Privacy Manifest / App Review 5.1',
    ruleVersion: guidelineVersion,
    title: 'App privacy manifest',
  );

  static const applePermissionStrings = GuidelineRule(
    id: 'apple-permission-purpose-strings',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 5.1.1 Permission Purpose Strings',
    ruleVersion: guidelineVersion,
    title: 'iOS permission purpose strings',
  );

  static const appleReviewerAccess = GuidelineRule(
    id: 'apple-reviewer-access-missing',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 2.1 App Completeness',
    ruleVersion: guidelineVersion,
    title: 'App Review access',
  );

  static const appleUniversalLinks = GuidelineRule(
    id: 'apple-universal-links-entitlements',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple Universal Links / Associated Domains',
    ruleVersion: guidelineVersion,
    title: 'Universal Links / entitlements',
  );

  static const appleAtt = GuidelineRule(
    id: 'apple-att-review',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 5.1.2 Tracking / ATT',
    ruleVersion: guidelineVersion,
    title: 'App Tracking Transparency',
  );

  static const appleUgc = GuidelineRule(
    id: 'apple-ugc-moderation-review',
    platform: GuidelinePlatform.appStore,
    guidelineReference: 'Apple App Review 1.2 User-Generated Content',
    ruleVersion: guidelineVersion,
    title: 'User-generated content',
    alwaysManualReview: true,
  );

  static List<GuidelineRule> get all => const [
        playDataSafety,
        playPrivacyPolicy,
        playAccountDeletion,
        playSensitivePermissions,
        playBillingBypass,
        playPhysicalGoods,
        playFamilies,
        playInsecureNetworking,
        playSigningReadiness,
        playReviewerAccess,
        applePrivacyPolicy,
        appleAccountDeletion,
        appleIap,
        applePhysicalGoods,
        appleSignInWithApple,
        applePrivacyManifest,
        applePermissionStrings,
        appleReviewerAccess,
        appleUniversalLinks,
        appleAtt,
        appleUgc,
      ];

  static GuidelineRule? byId(String id) {
    for (final rule in all) {
      if (rule.id == id) return rule;
    }
    return null;
  }
}
