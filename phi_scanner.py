import re


# Real Nepali citizenship and NID formats vary by district and issuing system.
# This demo assumes a hyphenated numeric format such as 12-34-56-78901.
CITIZENSHIP_PATTERN = re.compile(r"\b\d{2}-\d{2}-\d{2}-\d{5}\b")
PHONE_PATTERN = re.compile(r"\b98\d{8}\b")
DATE_PATTERN = r"(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})"

# Demo-only heuristic: two capitalized words near a date catches text like
# "Name Sita Tamang DOB 1994-05-20". This is not production-grade NER.
PATIENT_NAME_DATE_PATTERN = re.compile(
    rf"\b[A-Z][a-z]+ [A-Z][a-z]+\b(?=.{{0,50}}\b{DATE_PATTERN}\b)",
    re.DOTALL,
)

GENERAL_TERMS = [
    "diabetes",
    "cancer",
    "hypertension",
    "asthma",
    "stroke",
    "tuberculosis",
    "pneumonia",
    "fracture",
    "kidney disease",
    "heart disease",
    "pregnancy",
    "hepatitis",
    "malaria",
    "dengue",
    "epilepsy",
]

SENSITIVE_TERMS = [
    "hiv",
    "aids",
    "psychiatric",
    "depression",
    "bipolar",
    "schizophrenia",
    "suicide",
    "substance abuse",
]


def scan_text(content: str) -> list[dict]:
    matches: list[dict] = []
    matches.extend(_collect_regex_matches("citizenship_or_nid", CITIZENSHIP_PATTERN, content))
    matches.extend(_collect_regex_matches("phone_number", PHONE_PATTERN, content))
    matches.extend(_collect_regex_matches("patient_name_with_date", PATIENT_NAME_DATE_PATTERN, content))
    matches.extend(_collect_terms("diagnosis_term", GENERAL_TERMS, content))
    matches.extend(_collect_terms("sensitive_term", SENSITIVE_TERMS, content))
    return sorted(matches, key=lambda match: match["position"])


def _collect_regex_matches(pattern_type: str, pattern: re.Pattern, content: str) -> list[dict]:
    return [
        {
            "matched_pattern_type": pattern_type,
            "matched_text": _redact(match.group(0)),
            "position": match.start(),
        }
        for match in pattern.finditer(content)
    ]


def _collect_terms(pattern_type: str, terms: list[str], content: str) -> list[dict]:
    matches: list[dict] = []
    for term in terms:
        pattern = re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
        for match in pattern.finditer(content):
            matches.append(
                {
                    "matched_pattern_type": pattern_type,
                    "matched_text": _redact(match.group(0)),
                    "position": match.start(),
                }
            )
    return matches


def _redact(value: str) -> str:
    if len(value) <= 2:
        return "X" * len(value)
    return f"{value[0]}{'X' * (len(value) - 2)}{value[-1]}"
