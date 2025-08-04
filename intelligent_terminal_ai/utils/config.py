"""
Configuration management for the intelligent terminal AI
"""

import os
from typing import Dict, Any, Optional
from pathlib import Path
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration management class"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_file: Optional path to config file
        """
        self.config_file = config_file or os.path.join(os.getcwd(), "config.json")
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file and environment"""
        
        # Default configuration
        config = {
            "ai": {
                "model": "gpt-4",
                "api_key": None,
                "temperature": 0.1,
                "max_tokens": 1000
            },
            "browser": {
                "headless": False,
                "timeout": 30,
                "window_size": "1920,1080"
            },
            "terminal": {
                "timeout": 30,
                "max_history": 100
            },
            "logging": {
                "level": "INFO",
                "file": None
            },
            "session": {
                "max_iterations": 3,
                "save_screenshots": True,
                "save_history": True
            }
        }
        
        # Load from file if exists
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
        
        # Override with environment variables
        env_mappings = {
            "OPENAI_API_KEY": ("ai", "api_key"),
            "ANTHROPIC_API_KEY": ("ai", "api_key"),
            "GOOGLE_API_KEY": ("ai", "api_key"),
            "AI_MODEL": ("ai", "model"),
            "BROWSER_HEADLESS": ("browser", "headless"),
            "BROWSER_TIMEOUT": ("browser", "timeout"),
            "TERMINAL_TIMEOUT": ("terminal", "timeout"),
            "LOG_LEVEL": ("logging", "level"),
            "MAX_ITERATIONS": ("session", "max_iterations")
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert to appropriate type
                if key in ["headless", "save_screenshots", "save_history"]:
                    value = value.lower() in ["true", "1", "yes"]
                elif key in ["timeout", "max_tokens", "max_iterations", "max_history"]:
                    value = int(value)
                elif key == "temperature":
                    value = float(value)
                
                config[section][key] = value
        
        return config
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get a configuration value
        
        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        return self._config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: str, value: Any):
        """
        Set a configuration value
        
        Args:
            section: Configuration section
            key: Configuration key
            value: Value to set
        """
        if section not in self._config:
            self._config[section] = {}
        self._config[section][key] = value
    
    def save(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config file {self.config_file}: {e}")
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration"""
        return self._config.copy()


# Global configuration instance
config = Config()
