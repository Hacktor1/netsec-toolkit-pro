"""
Configuration manager for NetSec Toolkit Pro.

Handles loading, merging, and validating configuration from YAML files.
"""

import os
import yaml
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class Config:
    """Central configuration management with YAML loading and defaults."""

    DEFAULTS: Dict[str, Any] = {
        "scanner": {
            "interface": "wlan0",
            "timeout": 5,
            "use_simulated": True,
        },
        "port_scanner": {
            "timeout": 3,
            "max_threads": 100,
            "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 8080],
            "banner_grab": True,
        },
        "sniffer": {
            "max_packets": 100,
            "promiscuous": False,
        },
        "password_auditor": {
            "min_length": 8,
            "max_length": 16,
            "common_words": ["password", "admin", "welcome", "company", "root", "user", "test"],
            "common_passwords_file": "~/.netsec/passwords.txt",
            "hash_algorithms": ["md5", "sha1", "sha256"],
        },
        "vuln_detector": {
            "cve_api": "https://cve.circl.lu/api",
            "timeout": 10,
            "known_vulns_db": [],
        },
        "report": {
            "output_dir": "reports",
            "format": "html",
            "include_raw_data": True,
        },
        "thresholds": {
            "signal_strength": -70,
            "risk_score": 50,
        },
    }

    def __init__(self, config_path: Optional[str] = None):
        self._config: Dict[str, Any] = {}
        self._load(config_path)

    def _load(self, config_path: Optional[str] = None) -> None:
        """Load configuration from file and merge with defaults."""
        self._config = {}
        for key, value in self.DEFAULTS.items():
            if isinstance(value, dict):
                self._config[key] = dict(value)
            else:
                self._config[key] = value

        if config_path:
            real_path = os.path.expanduser(config_path)
            if not os.path.isfile(real_path):
                logger.warning(f"Config file not found: {real_path}; using defaults")
                return
            try:
                with open(real_path, "r") as f:
                    user_config = yaml.safe_load(f)
                if user_config:
                    self._deep_merge(self._config, user_config)
                    logger.info(f"Loaded config from {real_path}")
            except yaml.YAMLError as e:
                logger.warning(f"Failed to parse config YAML: {e}; using defaults")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}; using defaults")
        else:
            # Try default config path
            default_paths = ["config.yaml", os.path.expanduser("~/.netsec/config.yaml")]
            for path in default_paths:
                real_path = os.path.expanduser(path)
                if os.path.isfile(real_path):
                    self._load(real_path)
                    return
            logger.info("Using default configuration")

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> None:
        """Recursively merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get a config value using dot notation, e.g. 'scanner.timeout'."""
        keys = key_path.split(".")
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path: str, value: Any) -> None:
        """Set a config value using dot notation."""
        keys = key_path.split(".")
        config = self._config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value

    @property
    def raw(self) -> Dict[str, Any]:
        """Return the full config dict."""
        return dict(self._config)
