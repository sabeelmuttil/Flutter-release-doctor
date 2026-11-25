/// Store platform for offline guideline findings.
enum GuidelinePlatform {
  googlePlay,
  appStore,
  both;

  String get reportLabel => switch (this) {
        GuidelinePlatform.googlePlay => 'google-play',
        GuidelinePlatform.appStore => 'app-store',
        GuidelinePlatform.both => 'both',
      };
}

enum FindingLevel {
  error,
  warning,
  manualReview,
  info,
  passed;

  String get reportSectionTitle => switch (this) {
        FindingLevel.error => 'ERROR',
        FindingLevel.warning => 'WARNING',
        FindingLevel.manualReview => 'MANUAL REVIEW',
        FindingLevel.info => 'INFO',
        FindingLevel.passed => 'PASSED',
      };

  String get levelLabel => switch (this) {
        FindingLevel.error => 'ERROR',
        FindingLevel.warning => 'WARN ',
        FindingLevel.manualReview => 'REVIEW',
        FindingLevel.info => 'INFO ',
        FindingLevel.passed => 'PASS ',
      };
}

enum FindingConfidence { high, medium, low }

enum FindingSource { staticAnalysis, projectConfig, manualReview, liveApi }

class Finding {
  const Finding(
    this.level,
    this.title,
    this.detail, {
    required this.id,
    this.fix,
    this.suppressed = false,
    this.file,
    this.line,
    this.classification,
    this.confidence = FindingConfidence.medium,
    this.source = FindingSource.staticAnalysis,
    this.platform,
    this.guidelineReference,
    this.ruleVersion,
    @Deprecated('Use guidelineReference') String? guideline,
    this.evidenceSummary,
  }) : _legacyGuideline = guideline;

  /// Stable machine-readable finding identifier (kebab-case).
  final String id;
  final FindingLevel level;
  final String title;
  final String detail;
  final String? fix;

  /// True when an ERROR was downgraded by project `ignore` configuration.
  final bool suppressed;

  /// Optional repo-relative path for actionable evidence.
  final String? file;

  /// Optional 1-based line number for actionable evidence.
  final int? line;

  /// Redacted classification for secret findings (never a secret value).
  final String? classification;

  /// How confident the analyzer is that this is a real store/release risk.
  final FindingConfidence confidence;

  /// Where the signal came from.
  final FindingSource source;

  /// Store platform this guideline finding applies to, when applicable.
  final GuidelinePlatform? platform;

  /// Store/policy guideline reference (e.g. Apple App Review 5.1).
  final String? guidelineReference;

  /// Offline guideline rule registry version that produced this finding.
  final String? ruleVersion;

  final String? _legacyGuideline;

  /// Short safe evidence summary (never secrets or tokens).
  final String? evidenceSummary;

  /// Alias for [guidelineReference] (backward compatible).
  String? get guideline => guidelineReference ?? _legacyGuideline;

  /// Alias preferred in reports/JSON as `evidence`.
  String? get evidence => evidenceSummary;

  bool get affectsScore {
    if (level == FindingLevel.manualReview ||
        level == FindingLevel.info ||
        level == FindingLevel.passed) {
      return false;
    }
    if (confidence == FindingConfidence.low) return false;
    return level == FindingLevel.error || level == FindingLevel.warning;
  }

  bool get affectsFailOnWarning => level == FindingLevel.warning;

  String get levelLabel => level.levelLabel;

  Finding copyWith({
    FindingLevel? level,
    String? title,
    String? detail,
    String? id,
    String? fix,
    bool? suppressed,
    String? file,
    int? line,
    String? classification,
    FindingConfidence? confidence,
    FindingSource? source,
    GuidelinePlatform? platform,
    String? guidelineReference,
    String? ruleVersion,
    String? guideline,
    String? evidenceSummary,
  }) {
    return Finding(
      level ?? this.level,
      title ?? this.title,
      detail ?? this.detail,
      id: id ?? this.id,
      fix: fix ?? this.fix,
      suppressed: suppressed ?? this.suppressed,
      file: file ?? this.file,
      line: line ?? this.line,
      classification: classification ?? this.classification,
      confidence: confidence ?? this.confidence,
      source: source ?? this.source,
      platform: platform ?? this.platform,
      guidelineReference: guidelineReference ??
          guideline ??
          this.guidelineReference ??
          this.guideline,
      ruleVersion: ruleVersion ?? this.ruleVersion,
      evidenceSummary: evidenceSummary ?? this.evidenceSummary,
    );
  }

  String? get evidenceLabel {
    if (file == null) return null;
    final location = line == null ? file! : '$file:$line';
    if (classification == null || classification!.isEmpty) return location;
    return '$location ($classification)';
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'level':
            level == FindingLevel.manualReview ? 'manual_review' : level.name,
        'title': title,
        'detail': detail,
        'fix': fix,
        'suppressed': suppressed,
        'file': file,
        'line': line,
        'classification': classification,
        'confidence': confidence.name,
        'source': switch (source) {
          FindingSource.staticAnalysis => 'static-analysis',
          FindingSource.projectConfig => 'project-config',
          FindingSource.manualReview => 'manual-review',
          FindingSource.liveApi => 'live-api',
        },
        'platform': platform?.reportLabel,
        'guidelineReference': guideline,
        'guideline': guideline,
        'ruleVersion': ruleVersion,
        'evidence': evidenceSummary,
        'evidenceSummary': evidenceSummary,
      };
}

/// Finding IDs that configuration must not suppress or downgrade below error
/// when they are errors (hard-coded secrets / signing material / prod HTTP).
const nonSuppressibleFindingIds = <String>{
  'hard-coded-secret',
  'ci-hard-coded-secret',
  'insecure-http',
  'android-release-signing',
  'play-insecure-networking-risk',
};
