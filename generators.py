import itertools
import re


HOMOGLYPHS = {
    'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ā', 'ă', 'ą', 'α', 'а'],
    'b': ['ḃ', 'ḅ', 'ƀ', 'ɓ'],
    'c': ['ć', 'ĉ', 'ċ', 'č', 'ç', 'с'],
    'd': ['ď', 'đ', 'ḋ', 'ḍ', 'ḏ', 'ḑ'],
    'e': ['è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě', 'е', 'ε'],
    'f': ['ƒ', 'ḟ'],
    'g': ['ĝ', 'ğ', 'ġ', 'ģ', 'ǵ'],
    'h': ['ĥ', 'ħ', 'ḣ', 'ḥ', 'ḧ', 'ḩ'],
    'i': ['ì', 'í', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į', 'ı', 'і', '1', 'l'],
    'j': ['ĵ'],
    'k': ['ķ', 'ǩ', 'ḱ', 'ḳ', 'ḵ'],
    'l': ['ĺ', 'ļ', 'ľ', 'ŀ', 'ł', 'ḷ', '1', 'i'],
    'm': ['ḿ', 'ṁ', 'ṃ', 'м'],
    'n': ['ñ', 'ń', 'ņ', 'ň', 'ŋ', 'ṅ', 'ṇ', 'ṉ', 'η'],
    'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', 'о', '0'],
    'p': ['р', 'ṕ', 'ṗ'],
    'q': ['ǫ'],
    'r': ['ŕ', 'ŗ', 'ř', 'ṙ', 'ṛ', 'ṝ', 'г'],
    's': ['ś', 'ŝ', 'ş', 'š', 'ṡ', 'ṣ', '$', '5'],
    't': ['ţ', 'ť', 'ŧ', 'ṭ', 'ṯ', 'ṱ'],
    'u': ['ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'υ'],
    'v': ['ν', 'ṿ', 'ṽ'],
    'w': ['ŵ', 'ẁ', 'ẃ', 'ẅ', 'ẇ', 'ẉ', 'ω'],
    'x': ['χ', 'ẋ', 'ẍ'],
    'y': ['ý', 'ÿ', 'ŷ', 'ẏ', 'ỳ', 'ỵ', 'γ'],
    'z': ['ź', 'ż', 'ž', 'ẑ', 'ẓ', 'ẕ', 'ζ'],
    '0': ['o', 'ο'],
    '1': ['l', 'i', 'I'],
}

# Common keyboard typo adjacency (QWERTY layout)
KEYBOARD_ADJACENT = {
    'a': ['q', 'w', 's', 'z'],
    'b': ['v', 'g', 'h', 'n'],
    'c': ['x', 'd', 'f', 'v'],
    'd': ['s', 'e', 'r', 'f', 'c', 'x'],
    'e': ['w', 'r', 'd', 's'],
    'f': ['d', 'r', 't', 'g', 'v', 'c'],
    'g': ['f', 't', 'y', 'h', 'b', 'v'],
    'h': ['g', 'y', 'u', 'j', 'n', 'b'],
    'i': ['u', 'o', 'k', 'j'],
    'j': ['h', 'u', 'i', 'k', 'm', 'n'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'],
    'm': ['n', 'j', 'k'],
    'n': ['b', 'h', 'j', 'm'],
    'o': ['i', 'p', 'l', 'k'],
    'p': ['o', 'l'],
    'q': ['w', 'a'],
    'r': ['e', 't', 'f', 'd'],
    's': ['a', 'w', 'e', 'd', 'x', 'z'],
    't': ['r', 'y', 'g', 'f'],
    'u': ['y', 'i', 'j', 'h'],
    'v': ['c', 'f', 'g', 'b'],
    'w': ['q', 'e', 's', 'a'],
    'x': ['z', 's', 'd', 'c'],
    'y': ['t', 'u', 'h', 'g'],
    'z': ['a', 's', 'x'],
}

# Common TLD variations
TLDS_COMMON = [
    'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'app',
    'online', 'site', 'web', 'store', 'shop', 'tech', 'digital',
    'cloud', 'services', 'solutions', 'group', 'global', 'co.uk',
    'de', 'fr', 'es', 'it', 'ru', 'cn', 'jp', 'br', 'in',
    'xyz', 'club', 'live', 'media', 'email', 'support', 'help',
]

# Common prefix/suffix for combosquatting
COMBO_PREFIXES = ['my', 'get', 'the', 'go', 'try', 'use', 'best', 'top', 'real', 'official', 'secure']
COMBO_SUFFIXES = ['login', 'signin', 'account', 'support', 'help', 'service', 'services',
                  'online', 'app', 'web', 'portal', 'secure', 'safe', 'official', 'verify']


class DomainGenerator:
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        
        parts = self.domain.rsplit('.', 1)
        if len(parts) == 2:
            self.name = parts[0]
            self.tld = parts[1]
        else:
            self.name = self.domain
            self.tld = 'com'

        self.variations: list[dict] = []
        self._seen: set[str] = {self.domain}

    def _add(self, domain: str, vtype: str):
        d = domain.lower()
        if d not in self._seen and self._is_valid(d):
            self._seen.add(d)
            self.variations.append({"domain": d, "variation_type": vtype})

    def _is_valid(self, domain: str) -> bool:
        # Basic domain validation
        return (
            len(domain) >= 4
            and len(domain) <= 253
            and bool(re.match(r'^[a-z0-9\-\.]+$', domain))
            and not domain.startswith('-')
            and not domain.endswith('-')
            and '.' in domain
        )

    def generate(
        self,
        homoglyphs: bool = True,
        typos: bool = True,
        tld: bool = True,
        subdomains: bool = True,
        bitsquatting: bool = False,
        combosquatting: bool = False,
        extra_keywords: list[str] = [],
    ) -> list[dict]:

        if typos:
            self._gen_missing_char()
            self._gen_extra_char()
            self._gen_transposition()
            self._gen_keyboard_typos()
            self._gen_double_char()
            self._gen_missing_dot()
            self._gen_hyphenation()

        if homoglyphs:
            self._gen_homoglyphs()

        if tld:
            self._gen_tld_variations()

        if subdomains:
            self._gen_subdomain_abuse()

        if bitsquatting:
            self._gen_bitsquatting()

        if combosquatting:
            self._gen_combosquatting(extra_keywords)

        return self.variations

    # Typo Generation 

    def _gen_missing_char(self):
        """Remove each character one at a time."""
        name = self.name
        for i in range(len(name)):
            new_name = name[:i] + name[i+1:]
            if new_name:
                self._add(f"{new_name}.{self.tld}", "missing-char")

    def _gen_extra_char(self):
        """Insert an extra character at each position."""
        name = self.name
        charset = 'abcdefghijklmnopqrstuvwxyz'
        for i in range(len(name) + 1):
            for c in charset:
                new_name = name[:i] + c + name[i:]
                self._add(f"{new_name}.{self.tld}", "extra-char")

    def _gen_transposition(self):
        """Swap adjacent characters."""
        name = self.name
        for i in range(len(name) - 1):
            chars = list(name)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            self._add(f"{''.join(chars)}.{self.tld}", "transposition")

    def _gen_keyboard_typos(self):
        """Replace each char with adjacent keyboard keys."""
        name = self.name
        for i, char in enumerate(name):
            if char in KEYBOARD_ADJACENT:
                for adj in KEYBOARD_ADJACENT[char]:
                    new_name = name[:i] + adj + name[i+1:]
                    self._add(f"{new_name}.{self.tld}", "keyboard-typo")

    def _gen_double_char(self):
        """Double each character (common typo)."""
        name = self.name
        for i, char in enumerate(name):
            new_name = name[:i] + char + char + name[i+1:]
            self._add(f"{new_name}.{self.tld}", "double-char")

    def _gen_missing_dot(self):
        """Generate variations with missing dot (common in mobile typos)."""
        # e.g., wwwgoogle.com instead of www.google.com
        self._add(f"www{self.name}.{self.tld}", "missing-dot")
        self._add(f"www-{self.name}.{self.tld}", "missing-dot")

    def _gen_hyphenation(self):
        """Add/remove hyphens."""
        name = self.name
        # Insert hyphens
        for i in range(1, len(name)):
            new_name = name[:i] + '-' + name[i:]
            self._add(f"{new_name}.{self.tld}", "hyphenation")
        # Remove hyphens if present
        if '-' in name:
            self._add(f"{name.replace('-', '')}.{self.tld}", "hyphenation")
            self._add(f"{name.replace('-', '.')}.{self.tld}", "hyphenation")

    # Homoglyphs 

    def _gen_homoglyphs(self):
        """Replace characters with visually similar Unicode characters (limited set)."""
        name = self.name
        for i, char in enumerate(name):
            if char in HOMOGLYPHS:
                for glyph in HOMOGLYPHS[char][:3]:  # limit to top 3 per char
                    try:
                        new_name = name[:i] + glyph + name[i+1:]
                        new_name_ascii = new_name.encode('idna').decode('ascii')
                        self._add(f"{new_name_ascii}.{self.tld}", "homoglyph")
                    except (UnicodeError, UnicodeDecodeError):
                        pass

    # TLD Variations

    def _gen_tld_variations(self):
        """Try different TLDs."""
        for tld in TLDS_COMMON:
            if tld != self.tld:
                self._add(f"{self.name}.{tld}", "tld-variation")

        # Wrong TLD (e.g., .co instead of .com)
        if self.tld == 'com':
            self._add(f"{self.name}.co", "tld-variation")
            self._add(f"{self.name}.com.co", "tld-variation")

        # TLD character swaps
        for i in range(len(self.tld) - 1):
            chars = list(self.tld)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            self._add(f"{self.name}.{''.join(chars)}", "tld-typo")

    # Subdomain Abuse 

    def _gen_subdomain_abuse(self):
        """Create subdomain-based phishing patterns."""
        phishing_keywords = ['www', 'login', 'secure', 'account', 'signin', 'verify', 'update', 'mail']
        for kw in phishing_keywords:
            self._add(f"{kw}.{self.name}.{self.tld}", "subdomain-abuse")
            self._add(f"{self.name}.{kw}.{self.tld}", "subdomain-abuse")

    # Bitsquatting 

    def _gen_bitsquatting(self):
        """Flip individual bits in each character of the domain name."""
        name = self.name
        for i, char in enumerate(name):
            code = ord(char)
            for bit in range(8):
                flipped = code ^ (1 << bit)
                flipped_char = chr(flipped)
                if flipped_char.isalnum() or flipped_char == '-':
                    new_name = name[:i] + flipped_char + name[i+1:]
                    self._add(f"{new_name}.{self.tld}", "bitsquatting")

    # Combosquatting 

    def _gen_combosquatting(self, extra_keywords: list[str] = []):
        """Combine domain name with common keywords."""
        keywords = COMBO_PREFIXES + COMBO_SUFFIXES + extra_keywords
        for kw in keywords:
            self._add(f"{self.name}{kw}.{self.tld}", "combosquatting")
            self._add(f"{kw}{self.name}.{self.tld}", "combosquatting")
            self._add(f"{self.name}-{kw}.{self.tld}", "combosquatting")
            self._add(f"{kw}-{self.name}.{self.tld}", "combosquatting")
