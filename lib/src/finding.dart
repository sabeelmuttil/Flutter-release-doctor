enum FindingLevel { error, warning, passed }

class Finding {
  const Finding(this.level, this.title, this.detail, {this.fix});

  final FindingLevel level;
  final String title;
  final String detail;
  final String? fix;
}
