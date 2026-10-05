"""
Password Auditor Module for NetSec Toolkit Pro.

Generates wordlists and performs hash cracking against provided hashes.
"""

import hashlib
import itertools
import logging
import os
import string
from typing import List, Dict, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class WordlistGenerator:
    """Generates targeted password wordlists for auditing."""

    COMMON_PREFIXES = ["", "admin", "root", "user", "test", "guest", "default", ""]
    COMMON_SUFFIXES = [
        "", "123", "1234", "12345", "123456", "!", "@", "#", "2024", "2025",
        "@123", "admin", "pass", "word", "123!", "1q2w3e4r", "qwerty",
    ]

    def __init__(self, min_length: int = 8, max_length: int = 16):
        self.min_length = min_length
        self.max_length = max_length
        self.generated = 0

    def generate_from_words(self, base_words: List[str], variations: bool = True) -> List[str]:
        """Generate wordlist from base words with common mutations."""
        passwords = set()

        for word in base_words:
            # Original
            if self.min_length <= len(word) <= self.max_length:
                passwords.add(word)

            if variations:
                # Leet speak mutations
                for mutated in self._leet_mutate(word):
                    if self.min_length <= len(mutated) <= self.max_length:
                        passwords.add(mutated)

                # Add common suffixes
                for suffix in self.COMMON_SUFFIXES:
                    candidate = word + suffix
                    if self.min_length <= len(candidate) <= self.max_length:
                        passwords.add(candidate)

                # Add common prefixes
                for prefix in self.COMMON_PREFIXES:
                    if prefix:
                        candidate = prefix + word
                        if self.min_length <= len(candidate) <= self.max_length:
                            passwords.add(candidate)

                # Case variations
                if word.lower() != word:
                    passwords.add(word.lower())
                passwords.add(word.upper())
                # CamelCase
                if len(word) > 1:
                    passwords.add(word.capitalize())

        result = sorted(passwords)
        self.generated = len(result)
        logger.info(f"Generated {self.generated} password variations from {len(base_words)} base words")
        return result

    def _leet_mutate(self, word: str) -> List[str]:
        """Apply common leet speak substitutions."""
        mutations = [word]
        leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
        for i in range(len(word)):
            char = word[i].lower()
            if char in leet_map:
                # Replace with leet
                mutated = word[:i] + leet_map[char] + word[i + 1:]
                mutations.append(mutated)
        return mutations

    def generate_brute_force(self, charset: str, length: int, limit: int = 100000) -> List[str]:
        """Generate brute force candidates of a specific length."""
        passwords = []
        for combo in itertools.product(charset, repeat=length):
            passwords.append("".join(combo))
            self.generated += 1
            if len(passwords) >= limit:
                break
        logger.info(f"Generated {self.generated} brute force candidates at length {length}")
        return passwords

    def save_wordlist(self, passwords: List[str], filepath: str) -> str:
        """Save wordlist to a file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w") as f:
            for pwd in passwords:
                f.write(pwd + "\n")
        logger.info(f"Saved {len(passwords)} passwords to {filepath}")
        return filepath


class HashCracker:
    """Cracks password hashes using wordlists."""

    HASH_ALGORITHMS = ["md5", "sha1", "sha256"]

    def __init__(self):
        self._algo_map = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }

    def detect_hash_type(self, hash_value: str) -> Optional[str]:
        """Detect the hash algorithm based on hash length."""
        hash_value = hash_value.strip()
        length = len(hash_value)

        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        elif length == 128:
            return "sha512"
        elif length == 96:
            return "sha384"
        elif length == 56:
            return "sha224"

        return None

    def crack(self, hash_value: str, wordlist: List[str]) -> Tuple[bool, Optional[str]]:
        """Attempt to crack a hash using a wordlist. Returns (found, plaintext)."""
        hash_value = hash_value.strip().lower()
        algo = self.detect_hash_type(hash_value)

        if not algo:
            logger.warning(f"Could not detect hash type for: {hash_value[:20]}...")
            return False, None

        if algo not in self._algo_map:
            logger.warning(f"Algorithm {algo} not supported for cracking")
            return False, None

        hasher = self._algo_map[algo]
        target = hash_value

        for i, candidate in enumerate(wordlist):
            computed = hasher(candidate.encode("utf-8")).hexdigest()
            if computed == target:
                logger.info(f"✅ Hash cracked: {target[:16]}... -> {candidate}")
                return True, candidate

        return False, None

    def crack_bulk(self, hash_values: List[str], wordlist: List[str]) -> Dict[str, Tuple[bool, Optional[str]]]:
        """Crack multiple hashes at once."""
        results = {}
        for hash_val in hash_values:
            results[hash_val] = self.crack(hash_val, wordlist)
        return results

    @staticmethod
    def generate_hash(plaintext: str, algorithm: str = "sha256") -> str:
        """Generate a hash for a plaintext string."""
        hasher = hashlib.new(algorithm)
        hasher.update(plaintext.encode("utf-8"))
        return hasher.hexdigest()


def generate_common_passwords() -> List[str]:
    """Generate a list of the most common passwords for auditing."""
    return [
        "password", "123456", "12345678", "qwerty", "123456789",
        "1234567", "password1", "12345", "1234567890", "abc123",
        "iloveyou", "admin", "welcome", "monkey", "dragon",
        "letmein", "login", "master1", "sunshine", "ashley",
        "michael", "football", "000000", "password123", "passw0rd",
        "1234qwer", "root", "admin123", "toor", "changeme",
        "P@ssw0rd", "P@ssword1", "Welcome1", "administrator", "guest",
    ]
