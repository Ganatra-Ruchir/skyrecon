
from datetime import UTC, datetime, timedelta

from app.ioc import parser, scoring
from app.ioc.enrich import dga_likelihood, enrich, shannon_entropy
from app.models import IOCType


def test_refang_common_forms():
    assert parser.refang("hxxp://evil[.]com") == "http://evil.com"
    assert parser.refang("1.2.3[.]4") == "1.2.3.4"
    assert parser.refang("user[at]evil[dot]com") == "user@evil.com"


def test_extract_mixed_report():
    report = """
    Beacon to hxxps://cdn-update[.]tk/payload.exe from 45.155.205.233.
    Dropper hash 44d88612fea8a8f36de82e1278abb02f, contact evil[at]mail[dot]ru.
    Internal host 192.168.1.10 also touched google.com. See CVE-2024-3400.
    """
    found = {(p.value, p.ioc_type) for p in parser.extract(report)}
    values = {v for v, _ in found}
    assert "https://cdn-update.tk/payload.exe" in values
    assert "45.155.205.233" in values
    assert "44d88612fea8a8f36de82e1278abb02f" in values
    assert "CVE-2024-3400" in values
    # noise must be filtered
    assert "192.168.1.10" not in values, "private space is not an indicator"
    assert "google.com" not in values, "known-good domain is not an indicator"


def test_private_and_reserved_ips_rejected():
    for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1"):
        assert not parser.is_routable_ip(ip)
    assert parser.is_routable_ip("8.8.8.8")


def test_documentation_ranges_are_not_indicators():
    """TEST-NET space can never be real attacker infrastructure."""
    for ip in ("203.0.113.9", "198.51.100.7", "192.0.2.1"):
        assert not parser.is_routable_ip(ip)
        assert parser.detect_type(ip) is None


def test_detect_type():
    assert parser.detect_type("45.155.205.233") is IOCType.IPV4
    assert parser.detect_type("bad-domain.xyz") is IOCType.DOMAIN
    assert parser.detect_type("z" * 64) is None          # not hex
    assert parser.detect_type("d" * 64) is IOCType.SHA256


def test_normalisation_is_idempotent():
    v = parser.normalize("  EVIL.Example.COM. ", IOCType.DOMAIN)
    assert v == "evil.example.com"
    assert parser.normalize(v, IOCType.DOMAIN) == v


def test_confidence_decays_with_silence():
    now = datetime.now(UTC)
    fresh = scoring.decayed_confidence(90, now, half_life_days=30, now=now)
    aged = scoring.decayed_confidence(90, now - timedelta(days=30), half_life_days=30, now=now)
    ancient = scoring.decayed_confidence(90, now - timedelta(days=180), half_life_days=30, now=now)
    assert fresh == 90
    assert 43 <= aged <= 47, "one half-life should roughly halve confidence"
    assert ancient <= 10


def test_reinforcement_respects_source_trust():
    weak = scoring.reinforce(50, source="crowdsourced", hits=5)
    strong = scoring.reinforce(50, source="manual", hits=5)
    assert strong > weak
    assert weak <= 100 and strong <= 100


def test_dga_scores_random_higher_than_english():
    assert dga_likelihood("kqjxvbwzrtplmn.top") > dga_likelihood("newsletter.com")
    assert dga_likelihood("abc.com") == 0.0        # too short to judge


def test_entropy_ordering():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a8Xq2Lp0")


def test_enrichment_flags_phishing_url():
    e = enrich("http://secure-login-verify.tk/account/update.exe", IOCType.URL)
    assert e.risk_modifier > 0.4
    joined = " ".join(e.reasons).lower()
    assert "phishing" in joined or "executable" in joined
