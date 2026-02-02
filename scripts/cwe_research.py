#!/usr/bin/env python3
"""
CWE Research Module for SecMutBench

Fetches and parses CWE information from MITRE's CWE database.
Implements step 2 of the research-driven workflow:
    2. READ THE CWE PAGE from cwe.mitre.org/data/definitions/[NUMBER].html
       └── Look at: Description, Examples, Mitigations
"""

import re
import json
import hashlib
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup


@dataclass
class CWEInfo:
    """Structured information extracted from a CWE page."""
    cwe_id: str
    name: str
    description: str
    extended_description: str
    modes_of_introduction: List[str]
    common_consequences: List[Dict[str, str]]
    potential_mitigations: List[Dict[str, str]]
    detection_methods: List[Dict[str, str]]
    code_examples: List[Dict[str, str]]
    related_cwes: List[str]
    related_attack_patterns: List[str]
    applicable_platforms: List[str]
    likelihood_of_exploit: str
    url: str
    fetched_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CWETop25:
    """CWE Top 25 information."""
    year: int
    cwes: List[Dict[str, Any]]  # {rank, cwe_id, name, score}
    url: str


# CWE ID to Name mapping (fallback if fetch fails)
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-119": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-327": "Use of Broken or Risky Cryptographic Algorithm",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of Dangerous File Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-611": "XXE (XML External Entity)",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1336": "Improper Neutralization of Template Expressions",
}


class CWEResearcher:
    """
    Fetches and parses CWE information from MITRE's CWE database.

    Usage:
        researcher = CWEResearcher()
        cwe_info = researcher.fetch_cwe("CWE-89")
        print(cwe_info.description)
        print(cwe_info.potential_mitigations)
    """

    BASE_URL = "https://cwe.mitre.org"
    CWE_URL_TEMPLATE = "https://cwe.mitre.org/data/definitions/{id}.html"
    TOP25_URL = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"

    def __init__(self, cache_dir: Optional[str] = None, cache_ttl_hours: int = 24):
        """
        Initialize CWE researcher.

        Args:
            cache_dir: Directory to cache fetched CWE pages (None = no caching)
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.cache_ttl_hours = cache_ttl_hours
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecMutBench/1.0 (Security Research Tool)'
        })

        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, cwe_id: str) -> Path:
        """Get cache file path for a CWE."""
        clean_id = cwe_id.replace("CWE-", "").replace("-", "_")
        return self.cache_dir / f"cwe_{clean_id}.json"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache file is still valid."""
        if not cache_path.exists():
            return False

        import time
        mtime = cache_path.stat().st_mtime
        age_hours = (time.time() - mtime) / 3600
        return age_hours < self.cache_ttl_hours

    def _load_from_cache(self, cwe_id: str) -> Optional[CWEInfo]:
        """Load CWE info from cache."""
        if not self.cache_dir:
            return None

        cache_path = self._get_cache_path(cwe_id)
        if not self._is_cache_valid(cache_path):
            return None

        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
                return CWEInfo(**data)
        except Exception:
            return None

    def _save_to_cache(self, cwe_info: CWEInfo):
        """Save CWE info to cache."""
        if not self.cache_dir:
            return

        cache_path = self._get_cache_path(cwe_info.cwe_id)
        with open(cache_path, 'w') as f:
            json.dump(cwe_info.to_dict(), f, indent=2)

    def _extract_cwe_number(self, cwe_id: str) -> str:
        """Extract numeric part from CWE ID."""
        match = re.search(r'(\d+)', cwe_id)
        return match.group(1) if match else cwe_id

    def fetch_cwe(self, cwe_id: str, use_cache: bool = True) -> CWEInfo:
        """
        Fetch CWE information from MITRE.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89" or "89")
            use_cache: Whether to use cached results

        Returns:
            CWEInfo object with parsed data
        """
        # Normalize CWE ID
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        # Try cache first
        if use_cache:
            cached = self._load_from_cache(cwe_id)
            if cached:
                return cached

        # Fetch from MITRE
        cwe_number = self._extract_cwe_number(cwe_id)
        url = self.CWE_URL_TEMPLATE.format(id=cwe_number)

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            cwe_info = self._parse_cwe_page(response.text, cwe_id, url)

            # Cache the result
            self._save_to_cache(cwe_info)

            # Rate limiting
            time.sleep(0.5)

            return cwe_info

        except requests.RequestException as e:
            # Return minimal info on failure
            return CWEInfo(
                cwe_id=cwe_id,
                name=CWE_NAMES.get(cwe_id, "Unknown"),
                description=f"Failed to fetch: {str(e)}",
                extended_description="",
                modes_of_introduction=[],
                common_consequences=[],
                potential_mitigations=[],
                detection_methods=[],
                code_examples=[],
                related_cwes=[],
                related_attack_patterns=[],
                applicable_platforms=[],
                likelihood_of_exploit="Unknown",
                url=url,
                fetched_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

    def _parse_cwe_page(self, html: str, cwe_id: str, url: str) -> CWEInfo:
        """Parse CWE page HTML and extract structured information."""
        soup = BeautifulSoup(html, 'html.parser')

        # Extract name
        name = CWE_NAMES.get(cwe_id, "Unknown")
        title_elem = soup.find('h2')
        if title_elem:
            title_text = title_elem.get_text(strip=True)
            # Format: "CWE-89: Improper Neutralization of Special Elements..."
            if ':' in title_text:
                name = title_text.split(':', 1)[1].strip()

        # Extract description
        description = ""
        desc_div = soup.find('div', {'id': 'Description'})
        if desc_div:
            desc_text = desc_div.find('div', class_='detail')
            if desc_text:
                description = desc_text.get_text(strip=True)

        # Extract extended description
        extended_description = ""
        ext_div = soup.find('div', {'id': 'Extended_Description'})
        if ext_div:
            ext_text = ext_div.find('div', class_='detail')
            if ext_text:
                extended_description = ext_text.get_text(strip=True)

        # Extract modes of introduction
        modes_of_introduction = []
        modes_div = soup.find('div', {'id': 'Modes_of_Introduction'})
        if modes_div:
            for row in modes_div.find_all('tr'):
                cells = row.find_all('td')
                if cells:
                    modes_of_introduction.append(cells[0].get_text(strip=True))

        # Extract common consequences
        common_consequences = []
        conseq_div = soup.find('div', {'id': 'Common_Consequences'})
        if conseq_div:
            for row in conseq_div.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) >= 2:
                    common_consequences.append({
                        "scope": cells[0].get_text(strip=True),
                        "impact": cells[1].get_text(strip=True) if len(cells) > 1 else "",
                    })

        # Extract potential mitigations
        potential_mitigations = []
        mitig_div = soup.find('div', {'id': 'Potential_Mitigations'})
        if mitig_div:
            for row in mitig_div.find_all('tr'):
                cells = row.find_all('td')
                if cells:
                    phase = ""
                    strategy = ""
                    description_text = ""

                    for i, cell in enumerate(cells):
                        text = cell.get_text(strip=True)
                        if i == 0:
                            phase = text
                        elif i == 1:
                            strategy = text
                        elif i == 2:
                            description_text = text

                    if phase or description_text:
                        potential_mitigations.append({
                            "phase": phase,
                            "strategy": strategy,
                            "description": description_text,
                        })

        # Extract detection methods
        detection_methods = []
        detect_div = soup.find('div', {'id': 'Detection_Methods'})
        if detect_div:
            for row in detect_div.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) >= 2:
                    detection_methods.append({
                        "method": cells[0].get_text(strip=True),
                        "description": cells[1].get_text(strip=True) if len(cells) > 1 else "",
                    })

        # Extract code examples
        code_examples = []
        examples_div = soup.find('div', {'id': 'Demonstrative_Examples'})
        if examples_div:
            for example in examples_div.find_all('div', class_='example'):
                lang = "Unknown"
                code = ""
                description_text = ""

                # Try to find language
                lang_elem = example.find('span', class_='language')
                if lang_elem:
                    lang = lang_elem.get_text(strip=True)

                # Try to find code
                code_elem = example.find('pre')
                if code_elem:
                    code = code_elem.get_text(strip=True)

                # Try to find description
                desc_elem = example.find('p')
                if desc_elem:
                    description_text = desc_elem.get_text(strip=True)

                if code:
                    code_examples.append({
                        "language": lang,
                        "code": code,
                        "description": description_text,
                    })

        # Extract related CWEs
        related_cwes = []
        related_div = soup.find('div', {'id': 'Related_Weaknesses'})
        if related_div:
            for link in related_div.find_all('a', href=True):
                href = link['href']
                if '/definitions/' in href:
                    match = re.search(r'/definitions/(\d+)\.html', href)
                    if match:
                        related_cwes.append(f"CWE-{match.group(1)}")

        # Extract related attack patterns (CAPECs)
        related_attack_patterns = []
        capec_div = soup.find('div', {'id': 'Related_Attack_Patterns'})
        if capec_div:
            for link in capec_div.find_all('a', href=True):
                href = link['href']
                if 'capec' in href.lower():
                    match = re.search(r'(\d+)', href)
                    if match:
                        related_attack_patterns.append(f"CAPEC-{match.group(1)}")

        # Extract applicable platforms
        applicable_platforms = []
        platforms_div = soup.find('div', {'id': 'Applicable_Platforms'})
        if platforms_div:
            for item in platforms_div.find_all(['li', 'td']):
                text = item.get_text(strip=True)
                if text and text not in applicable_platforms:
                    applicable_platforms.append(text)

        # Extract likelihood of exploit
        likelihood_of_exploit = "Unknown"
        likelihood_div = soup.find('div', {'id': 'Likelihood_Of_Exploit'})
        if likelihood_div:
            detail = likelihood_div.find('div', class_='detail')
            if detail:
                likelihood_of_exploit = detail.get_text(strip=True)

        return CWEInfo(
            cwe_id=cwe_id,
            name=name,
            description=description,
            extended_description=extended_description,
            modes_of_introduction=modes_of_introduction,
            common_consequences=common_consequences,
            potential_mitigations=potential_mitigations,
            detection_methods=detection_methods,
            code_examples=code_examples,
            related_cwes=related_cwes,
            related_attack_patterns=related_attack_patterns,
            applicable_platforms=applicable_platforms,
            likelihood_of_exploit=likelihood_of_exploit,
            url=url,
            fetched_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )

    def fetch_top25(self, year: int = 2025) -> CWETop25:
        """
        Fetch CWE Top 25 list for a given year.

        Args:
            year: Year of Top 25 list (default: 2025)

        Returns:
            CWETop25 object with ranked CWEs
        """
        url = f"https://cwe.mitre.org/top25/archive/{year}/{year}_cwe_top25.html"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            cwes = []

            # Find the main table
            table = soup.find('table')
            if table:
                for row in table.find_all('tr')[1:]:  # Skip header
                    cells = row.find_all('td')
                    if len(cells) >= 3:
                        rank = cells[0].get_text(strip=True)

                        # Extract CWE ID from link
                        cwe_link = cells[1].find('a')
                        cwe_id = ""
                        cwe_name = cells[1].get_text(strip=True)
                        if cwe_link:
                            href = cwe_link.get('href', '')
                            match = re.search(r'/definitions/(\d+)\.html', href)
                            if match:
                                cwe_id = f"CWE-{match.group(1)}"

                        score = cells[2].get_text(strip=True) if len(cells) > 2 else ""

                        if cwe_id:
                            cwes.append({
                                "rank": int(rank) if rank.isdigit() else 0,
                                "cwe_id": cwe_id,
                                "name": cwe_name,
                                "score": score,
                            })

            return CWETop25(year=year, cwes=cwes, url=url)

        except requests.RequestException as e:
            # Return hardcoded Top 25 for 2025 as fallback
            return self._get_fallback_top25(year)

    def _get_fallback_top25(self, year: int) -> CWETop25:
        """Return hardcoded CWE Top 25 as fallback."""
        # CWE Top 25 2025 (based on MITRE data)
        cwes = [
            {"rank": 1, "cwe_id": "CWE-79", "name": "Cross-site Scripting (XSS)", "score": ""},
            {"rank": 2, "cwe_id": "CWE-89", "name": "SQL Injection", "score": ""},
            {"rank": 3, "cwe_id": "CWE-22", "name": "Path Traversal", "score": ""},
            {"rank": 4, "cwe_id": "CWE-78", "name": "OS Command Injection", "score": ""},
            {"rank": 5, "cwe_id": "CWE-416", "name": "Use After Free", "score": ""},
            {"rank": 6, "cwe_id": "CWE-787", "name": "Out-of-bounds Write", "score": ""},
            {"rank": 7, "cwe_id": "CWE-20", "name": "Improper Input Validation", "score": ""},
            {"rank": 8, "cwe_id": "CWE-125", "name": "Out-of-bounds Read", "score": ""},
            {"rank": 9, "cwe_id": "CWE-287", "name": "Improper Authentication", "score": ""},
            {"rank": 10, "cwe_id": "CWE-352", "name": "CSRF", "score": ""},
            {"rank": 11, "cwe_id": "CWE-434", "name": "Unrestricted File Upload", "score": ""},
            {"rank": 12, "cwe_id": "CWE-502", "name": "Deserialization of Untrusted Data", "score": ""},
            {"rank": 13, "cwe_id": "CWE-476", "name": "NULL Pointer Dereference", "score": ""},
            {"rank": 14, "cwe_id": "CWE-190", "name": "Integer Overflow", "score": ""},
            {"rank": 15, "cwe_id": "CWE-798", "name": "Hard-coded Credentials", "score": ""},
            {"rank": 16, "cwe_id": "CWE-306", "name": "Missing Authentication", "score": ""},
            {"rank": 17, "cwe_id": "CWE-862", "name": "Missing Authorization", "score": ""},
            {"rank": 18, "cwe_id": "CWE-918", "name": "SSRF", "score": ""},
            {"rank": 19, "cwe_id": "CWE-611", "name": "XXE", "score": ""},
            {"rank": 20, "cwe_id": "CWE-200", "name": "Information Exposure", "score": ""},
            {"rank": 21, "cwe_id": "CWE-327", "name": "Broken Crypto", "score": ""},
            {"rank": 22, "cwe_id": "CWE-362", "name": "Race Condition", "score": ""},
            {"rank": 23, "cwe_id": "CWE-269", "name": "Improper Privilege Management", "score": ""},
            {"rank": 24, "cwe_id": "CWE-276", "name": "Incorrect Default Permissions", "score": ""},
            {"rank": 25, "cwe_id": "CWE-119", "name": "Buffer Overflow", "score": ""},
        ]
        return CWETop25(year=year, cwes=cwes, url="fallback")

    def get_mitigations_for_cwe(self, cwe_id: str) -> List[str]:
        """
        Get simplified list of mitigations for a CWE.

        Returns list of actionable mitigation descriptions.
        """
        cwe_info = self.fetch_cwe(cwe_id)
        mitigations = []

        for m in cwe_info.potential_mitigations:
            desc = m.get('description', '')
            if desc:
                mitigations.append(desc)
            elif m.get('strategy'):
                mitigations.append(m.get('strategy'))

        return mitigations

    def get_attack_patterns_for_cwe(self, cwe_id: str) -> List[str]:
        """Get related attack patterns (CAPECs) for a CWE."""
        cwe_info = self.fetch_cwe(cwe_id)
        return cwe_info.related_attack_patterns


def main():
    """Test the CWE researcher."""
    import argparse

    parser = argparse.ArgumentParser(description="Fetch CWE information from MITRE")
    parser.add_argument("cwe_id", nargs="?", default="CWE-89", help="CWE ID to fetch")
    parser.add_argument("--cache-dir", default="data/cwe_cache", help="Cache directory")
    parser.add_argument("--top25", action="store_true", help="Fetch CWE Top 25")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    researcher = CWEResearcher(cache_dir=args.cache_dir)

    if args.top25:
        top25 = researcher.fetch_top25()
        print(f"\nCWE Top 25 ({top25.year}):")
        print("=" * 60)
        for cwe in top25.cwes:
            print(f"  {cwe['rank']:2}. {cwe['cwe_id']}: {cwe['name']}")
    else:
        print(f"\nFetching {args.cwe_id}...")
        cwe_info = researcher.fetch_cwe(args.cwe_id)

        if args.json:
            print(json.dumps(cwe_info.to_dict(), indent=2))
        else:
            print(f"\n{cwe_info.cwe_id}: {cwe_info.name}")
            print("=" * 60)
            print(f"\nDescription:\n{cwe_info.description[:500]}...")

            print(f"\nMitigations ({len(cwe_info.potential_mitigations)}):")
            for m in cwe_info.potential_mitigations[:3]:
                print(f"  - {m.get('phase', 'N/A')}: {m.get('description', '')[:100]}...")

            print(f"\nRelated CWEs: {', '.join(cwe_info.related_cwes[:5])}")
            print(f"Attack Patterns: {', '.join(cwe_info.related_attack_patterns[:5])}")


if __name__ == "__main__":
    main()
