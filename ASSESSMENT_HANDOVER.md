# Assessment workspace: two-day evaluation and ownership handover

This is an engineering evaluation release, not a certification or claim of government approval. Production acceptance belongs to the receiving organization's security and operations staff. No ownership transfer, credentials transfer or external target assessment has been performed.

## Delivered capability

- Responsive website, phone, evidence and CVE-reference workspace; keyboard navigation, reduced-motion support, motion pause, JSON export and print view.
- Twelve implemented observation families: HSTS presence, CSP presence, nosniff presence/value, referrer policy, permissions policy, framing, script policy breadth, HSTS duration, technology banners, wildcard CORS, cookie attributes and internationalized hostname review. These are bounded heuristics, not twelve exploitable vulnerabilities.
- One TLS-verified HTTPS GET to an exact approved hostname; no redirects, port sweep, exploit payloads, cookies, JavaScript execution or response-body collection. DNS resolves once, all answers must be public, and the connection is pinned to a validated address with hostname verification.
- Existing authentication and rate limiting; analysts may review evidence and phone metadata, only administrators can initiate collection. Request/result audit details use the existing encrypted audit store. No authentication tokens stored by the new frontend.
- International phone formatting with limited numbering-region metadata. Real names are only returned from an operator-verified public-business directory, attributed to its source. Entries older than 90 days are withheld. No private subscriber identities, device tracking or purchased database is supplied.
- Operator-controlled NVD 2.0 JSON import into SQLite, deduplication, 2024–2026 CVE identifiers and bounded keyword search. The catalogue starts empty; no claim of 100,000 loaded records or executed checks. Product/version applicability requires analyst review.

## Start and configure

Run the existing Python application as documented in README. Open `/static/assessment.html`. Sign in with the existing account and MFA when enabled. Production environment checks still apply.

`SKYRECON_SCAN_HOSTS` is a comma-separated **exact** hostname allowlist, empty by default. The receiving administrator must configure it only after documenting permission, contact, test window and permitted paths. Every collection requires an authorization-reference field. This field records the operator's assertion; it does not establish legal permission automatically. Paths on an approved hostname are allowed; egress policy should enforce any narrower organizational scope. Do not approve shared hosting domains broadly.

`SKYRECON_BUSINESS_DIRECTORY` optionally points to an access-controlled JSON object keyed by international number. Each record must contain `kind: public_business`, `name`, an HTTPS `source_url`, and timezone-aware ISO `verified_at`. Independently verify permission and source attribution before installing records. Do not commit personal data. With no directory the response is Owner unknown. Country prefixes currently cover +91, +44 and shared +1 only; formatting does not prove a number is assigned or active.

Download NVD 2.0 JSON from the official NVD feeds/API using the organization's permitted process. Import pages below 100 MB:

```text
python tools/import_cve_catalog.py approved-feed.json catalogue.sqlite
```

Set `SKYRECON_CVE_CATALOGUE` to that database path. Refresh through an operator-controlled maintenance process and record the source/download time. The importer preserves applicability and metrics, but search does not perform CPE matching. Identifier year is the inclusion filter; it is not necessarily publication year.

The existing Vercel site is a **static preview**: it serves the clearly labelled local fixture, not the Python APIs. Use a separately secured Python deployment for actual assessments. The preview never silently substitutes fixture results for a requested live scan.

## Evaluation: day 1

1. Create an isolated test deployment with synthetic records and organization-owned secrets. Keep collection disabled.
2. Run the automated tests, sign in/out, confirm denied anonymous requests and denied unlisted/private hosts.
3. Inspect fixture results, exports, desktop/mobile layout and unknown phone-owner behavior. Import a small approved CVE page and verify the count against the source.
4. Receiving staff record acceptance criteria and verify that security findings are not displayed as proof of fraud.

## Evaluation: day 2

1. Organization staff configure a narrowly authorized test host; verify one-request collection and audit entries. No external targets were tested during development.
2. Review scan egress/network timeouts, concurrency limits at the gateway, audit retention, encryption-key backup, recovery and storage access. DNS and total request time must be bounded by the deployment infrastructure; socket timeouts alone are not an overall deadline.
3. Conduct independent security review and deployment-specific load testing. Confirm the privacy and legal basis for phone directory entries. No claim of exhaustive vulnerability detection.
4. Transfer repository and hosting ownership through the platforms' supported flows. Replace developer accounts, rotate secrets, revoke developer sessions/tokens and remove test datasets. Test backup restore and record operator sign-off. Do not use an automatic two-day deletion timer.

## Unimplemented / not certified

No full DAST suite, authenticated crawling, exploit validation, universal CVE applicability, fraud verdict, domain registration lookup, commercial threat feed, private caller identification, live geolocation, SLA or formal government accreditation. Missing headers and public CORS may be intentional. Collecting an error/redirect response limits what can be concluded. Returned scan status identifies that limitation.

References: https://owasp.org/projects/secure-headers-project and https://nvd.nist.gov/developers/vulnerabilities . Follow source terms and maintain provenance when importing data.


## Open-source tool interoperability

The authenticated Tool reports tab accepts a bounded SARIF 2.1.0 subset: inline runs, driver name/version, plain message.text, rule identifiers, tool levels and up to ten locations per finding. Limit: 512 Ki characters, twenty runs and 1,000 results per import. Duplicate identical tool/rule/message/location findings are collapsed. Findings remain unverified observations. Source suppression presence is retained. External property files, unresolved message IDs and unsupported versions are rejected. Artifacts, fixes and linked resources are never executed or fetched. Review and redact report messages before upload; they can contain sensitive source fragments. Only digest and counts enter the encrypted audit log, not the imported report body. Save exported reports to organization-controlled storage.

This is a report interoperability layer, not bundled scanner execution. It was tested with synthetic SARIF fixtures, not every tool/version. Original reports remain authoritative. An empty import is not proof of successful coverage. Check the exact tool version, ruleset license, output format and target scope in the receiving environment.

| Reviewed upstream | Relevant purpose | Current integration status |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Dependency/container/configuration findings; [SARIF output](https://trivy.dev/docs/latest/configuration/reporting/) | SARIF and native schema-2 JSON package-vulnerability import implemented; native engine not bundled or run |
| [Semgrep](https://github.com/semgrep/semgrep) | Source analysis; [CLI reporting](https://docs.semgrep.dev/cli-reference) | SARIF subset import implemented; rules and native engine not bundled |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection | Candidate report producer; redact secrets; exact-version interoperability not validated |
| [ZAP](https://github.com/zaproxy/zaproxy) | Web application assessment | Traditional JSON report subset import implemented; scanner execution not implemented |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based assessments | Reviewed candidate; template execution not integrated |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Repository security-health signals | Reviewed candidate; no automated score ingestion |

The [awesome-security index](https://github.com/sbilly/awesome-security) was inspected for broader discovery. This was not an audit of all GitHub or 500 tools. Each additional engine needs version pinning, license/notice review, output fixtures, error handling and deployment resource limits. No third-party scanner source was copied into SkyRecon. Open-source software and separately licensed rules/data are distinct; ownership transfer does not override upstream terms.

Format reference: [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).


## Native report formats

The Tool reports format selector now accepts ZAP traditional JSON (`@version`, `site[].alerts[]`) and Trivy schema-2 JSON (`Results[].Vulnerabilities[]`) through authenticated POST `/api/assessment/tool-report`. The existing SARIF endpoint remains compatible. Maximum input is 512 Ki characters, 100 sites/targets, 1,000 findings and 1,000 URI instances per ZAP alert; oversized or malformed inputs are rejected rather than silently truncated.

ZAP retains supplied alert risk/confidence, description, remediation, target and URI instances. Request/response contents, attacks and per-instance evidence are excluded. Trivy retains advisory, package, installed/fixed version, target and tool severity; secret, license and misconfiguration records are not imported and their count is reported. Unknown additional fields are ignored. All reported text is displayed as text, not executable HTML. Export includes coverage limitations and a digest of the source document. Only digest, format and counts enter the encrypted audit log.

These adapters were tested with synthetic fixtures shaped from the upstream documentation, not with deployed scanner binaries. Submitted URI paths/descriptions can still contain private information: redact before import. Neither a zero-result report nor the presence of a fix version proves safety or remediation. Review the original report and verify tool/ruleset versions in the receiving environment.

Sources: [ZAP traditional JSON format](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/) and [Trivy reporting](https://trivy.dev/docs/latest/configuration/reporting/).
