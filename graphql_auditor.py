import requests
import sys
import time
from report import SecurityReport


class GraphQLAuditor:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.report = SecurityReport(target_url)
        self.headers = {"Content-Type": "application/json"}

    def send_query(self, query, variables=None, method="POST"):
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            if method == "POST":
                response = requests.post(
                    self.target_url,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            else:
                response = requests.get(
                    self.target_url,
                    params={"query": query},
                    timeout=self.timeout,
                )
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None

    def get_curl_command(self, query, method="POST"):
        if method == "POST":
            escaped_query = query.replace('"', '\\"').replace("\n", " ")
            return (
                f'curl -X POST -H "Content-Type: application/json" '
                f'-d \'{{"query": "{escaped_query}"}}\'  '
                f"'{self.target_url}'"
            )
        else:
            import urllib.parse
            encoded_query = urllib.parse.quote(query)
            return f"curl '{self.target_url}?query={encoded_query}'"

    def check_introspection(self):
        print("[*] Testing: Introspection Query...")
        query = """
        query {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        response = self.send_query(query)
        if response and response.status_code == 200:
            data = response.json()
            if "data" in data and "__schema" in data["data"]:
                types = data["data"]["__schema"]["types"]
                type_count = len(types)
                self.report.add_finding(
                    title="Introspection Query Enabled",
                    severity="HIGH",
                    description=(
                        f"Full schema introspection is enabled. "
                        f"Discovered {type_count} types. "
                        f"Attackers can map the entire API surface."
                    ),
                    curl_command=self.get_curl_command(query),
                )
                return True
        self.report.add_finding(
            title="Introspection Query",
            severity="PASS",
            description="Introspection is disabled or restricted.",
            curl_command=None,
        )
        return False

    def check_query_depth(self):
        print("[*] Testing: Query Depth Limit...")
        query = """
        query {
            pastes {
                owner {
                    pastes {
                        owner {
                            pastes {
                                owner {
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        response = self.send_query(query)
        if response and response.status_code == 200:
            data = response.json()
            if "data" in data and "errors" not in data:
                self.report.add_finding(
                    title="No Query Depth Limit",
                    severity="HIGH",
                    description=(
                        "Server accepts deeply nested queries (7 levels) "
                        "without restriction. Vulnerable to depth-based "
                        "denial of service attacks."
                    ),
                    curl_command=self.get_curl_command(query),
                )
                return True
            elif "errors" in data and "data" in data:
                self.report.add_finding(
                    title="No Query Depth Limit",
                    severity="HIGH",
                    description=(
                        "Server processes deeply nested queries (7 levels) "
                        "and returns partial data. Vulnerable to depth-based "
                        "denial of service attacks."
                    ),
                    curl_command=self.get_curl_command(query),
                )
                return True
        self.report.add_finding(
            title="Query Depth Limit",
            severity="PASS",
            description="Server enforces query depth limits.",
            curl_command=None,
        )
        return False

    def check_alias_overloading(self):
        print("[*] Testing: Alias Overloading...")
        aliases = " ".join(
            [f"alias{i}: __typename" for i in range(100)]
        )
        query = f"query {{ {aliases} }}"

        response = self.send_query(query)
        if response and response.status_code == 200:
            data = response.json()
            if "data" in data:
                alias_count = len(data["data"])
                if alias_count >= 100:
                    self.report.add_finding(
                        title="Alias Overloading Allowed",
                        severity="HIGH",
                        description=(
                            f"Server accepted {alias_count} aliases in a "
                            f"single query. Attackers can use aliases to "
                            f"bypass rate limiting and amplify attacks."
                        ),
                        curl_command=self.get_curl_command(query),
                    )
                    return True
        self.report.add_finding(
            title="Alias Overloading",
            severity="PASS",
            description="Server restricts alias count.",
            curl_command=None,
        )
        return False

    def check_batch_queries(self):
        print("[*] Testing: Batch Query Support...")
        batch_payload = [
            {"query": "query { __typename }"}
            for _ in range(10)
        ]

        try:
            response = requests.post(
                self.target_url,
                json=batch_payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            if response and response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) >= 10:
                    self.report.add_finding(
                        title="Batch Queries Accepted",
                        severity="MEDIUM",
                        description=(
                            f"Server processes {len(data)} batched operations "
                            f"in a single HTTP request. Attackers can bypass "
                            f"per-request rate limiting."
                        ),
                        curl_command=(
                            f'curl -X POST -H "Content-Type: application/json" '
                            f"-d '[{{\"query\": \"query {{ __typename }}\"}},"
                            f"{{\"query\": \"query {{ __typename }}\"}}]' "
                            f"'{self.target_url}'"
                        ),
                    )
                    return True
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            pass

        self.report.add_finding(
            title="Batch Queries",
            severity="PASS",
            description="Server does not accept batched operations.",
            curl_command=None,
        )
        return False

    def check_field_suggestions(self):
        print("[*] Testing: Field Suggestions...")
        query = "query { __typena }"

        response = self.send_query(query)
        if response and response.status_code in (200, 400):
            try:
                data = response.json()
                response_text = str(data)
                if "Did you mean" in response_text or "did you mean" in response_text:
                    self.report.add_finding(
                        title="Field Suggestions Enabled",
                        severity="LOW",
                        description=(
                            "Server returns field name suggestions in error "
                            "messages. Attackers can enumerate the schema even "
                            "if introspection is disabled."
                        ),
                        curl_command=self.get_curl_command(query),
                    )
                    return True
            except ValueError:
                pass

        self.report.add_finding(
            title="Field Suggestions",
            severity="PASS",
            description="Server does not expose field name suggestions.",
            curl_command=None,
        )
        return False

    def check_get_based_queries(self):
        print("[*] Testing: GET-based Queries (CSRF)...")
        query = "query { __typename }"

        response = self.send_query(query, method="GET")
        if response and response.status_code == 200:
            try:
                data = response.json()
                if "data" in data and "__typename" in data["data"]:
                    self.report.add_finding(
                        title="GET-based Queries Accepted",
                        severity="HIGH",
                        description=(
                            "Server processes GraphQL queries via HTTP GET. "
                            "This enables Cross-Site Request Forgery (CSRF) "
                            "attacks against authenticated users."
                        ),
                        curl_command=self.get_curl_command(query, method="GET"),
                    )
                    return True
            except ValueError:
                pass

        self.report.add_finding(
            title="GET-based Queries",
            severity="PASS",
            description="Server does not accept queries via GET method.",
            curl_command=None,
        )
        return False

    def check_circular_fragments(self):
        print("[*] Testing: Circular Fragment DoS...")
        query = """
        fragment A on Query {
            ...B
        }
        fragment B on Query {
            ...A
        }
        query CircularTest {
            ...A
        }
        """
        start_time = time.time()
        try:
            response = requests.post(
                self.target_url,
                json={"query": query},
                headers=self.headers,
                timeout=3,
            )
            elapsed = time.time() - start_time

            if response.status_code == 200:
                data = response.json()
                if "errors" in data:
                    error_text = str(data["errors"]).lower()
                    if "circular" in error_text or "cycle" in error_text or "recursive" in error_text:
                        self.report.add_finding(
                            title="Circular Fragment Reference",
                            severity="PASS",
                            description=(
                                "Server correctly detects and rejects circular "
                                "fragment references with a validation error."
                            ),
                            curl_command=None,
                        )
                        return False
                self.report.add_finding(
                    title="Circular Fragment Reference Accepted",
                    severity="HIGH",
                    description=(
                        f"Server processed circular fragments without rejection "
                        f"(responded in {elapsed:.2f}s). May be vulnerable to "
                        f"recursive fragment DoS (CVE-2026-47706 pattern)."
                    ),
                    curl_command=self.get_curl_command(query),
                )
                return True
            else:
                self.report.add_finding(
                    title="Circular Fragment Reference",
                    severity="PASS",
                    description="Server rejects circular fragment references.",
                    curl_command=None,
                )
                return False

        except requests.exceptions.Timeout:
            self.report.add_finding(
                title="Circular Fragment DoS - Server Timeout",
                severity="CRITICAL",
                description=(
                    "Server timed out processing circular fragment references. "
                    "Likely vulnerable to infinite recursion DoS "
                    "(CVE-2026-47706 pattern). A single request can exhaust "
                    "CPU and thread pools."
                ),
                curl_command=self.get_curl_command(query),
            )
            return True
        except requests.exceptions.ConnectionError:
            self.report.add_finding(
                title="Circular Fragment DoS - Server Crash",
                severity="CRITICAL",
                description=(
                    "Server connection lost after sending circular fragment "
                    "references. Server likely crashed due to infinite "
                    "recursion (CVE-2026-47706 pattern)."
                ),
                curl_command=self.get_curl_command(query),
            )
            return True

    def run_audit(self):
        print(f"\n{'='*60}")
        print(f"  GraphQL Security Auditor")
        print(f"  Target: {self.target_url}")
        print(f"{'='*60}\n")

        self.check_introspection()
        self.check_query_depth()
        self.check_alias_overloading()
        self.check_batch_queries()
        self.check_field_suggestions()
        self.check_get_based_queries()
        self.check_circular_fragments()

        self.report.print_report()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5013/graphql"
    auditor = GraphQLAuditor(target)
    auditor.run_audit()