class SecurityReport:
    COLORS = {
        "HIGH": "\033[91m",
        "MEDIUM": "\033[93m",
        "LOW": "\033[94m",
        "PASS": "\033[92m",
        "CRITICAL": "\033[95m",
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
    }

    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []

    def add_finding(self, title, severity, description, curl_command=None):
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "curl_command": curl_command,
        })
    def print_report(self):
        print(f"\n{'='*60}")
        print(f"{self.COLORS['BOLD']}  SECURITY AUDIT REPORT{self.COLORS['RESET']}")
        print(f"  Target: {self.target_url}")
        print(f"{'='*60}\n")

        for finding in self.findings:
            severity = finding["severity"]
            color = self.COLORS.get(severity, self.COLORS["RESET"])
            icon = self._get_icon(severity)

            print(f"  {icon} {color}[{severity}]{self.COLORS['RESET']} {finding['title']}")
            print(f"     {finding['description']}")

            if finding["curl_command"]:
                print(f"     Reproduce: {finding['curl_command']}")
            print()

        self._print_summary()

    def _get_icon(self, severity):
        icons = {
            "CRITICAL": "!",
            "HIGH": "&",
            "MEDIUM": "#",
            "LOW": "%",
            "PASS": "$",
        }
        return icons.get(severity, "?")
    def _print_summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "PASS": 0}
        for finding in self.findings:
            severity = finding["severity"]
            if severity in counts:
                counts[severity] += 1

        print(f"{'='*60}")
        print(f"{self.COLORS['BOLD']}  SUMMARY{self.COLORS['RESET']}")
        print(f"{'='*60}")
        print(f"  Total checks: {len(self.findings)}")

        vuln_count = counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
        print(f"  Vulnerabilities found: {vuln_count}")
        print()

        if counts["CRITICAL"] > 0:
            print(f"  {self.COLORS['CRITICAL']}CRITICAL: {counts['CRITICAL']}{self.COLORS['RESET']}")
        if counts["HIGH"] > 0:
            print(f"  {self.COLORS['HIGH']}HIGH: {counts['HIGH']}{self.COLORS['RESET']}")
        if counts["MEDIUM"] > 0:
            print(f"  {self.COLORS['MEDIUM']}MEDIUM: {counts['MEDIUM']}{self.COLORS['RESET']}")
        if counts["LOW"] > 0:
            print(f"  {self.COLORS['LOW']}LOW: {counts['LOW']}{self.COLORS['RESET']}")
        if counts["PASS"] > 0:
            print(f"  {self.COLORS['PASS']}PASS: {counts['PASS']}{self.COLORS['RESET']}")

        print(f"\n{'='*60}\n")