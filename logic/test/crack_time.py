import math
from dataclasses import dataclass
from enum import Enum, auto


class KDFType(Enum):
    PBKDF2 = auto()
    ARGON2 = auto()


@dataclass
class PasswordConfig:
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool


@dataclass
class GPUConfig:
    guesses_per_second: int  


class PasswordCrackerEstimator:
    def __init__(self, password: str, kdf_type: KDFType, kdf_iterations: int, gpu_config: GPUConfig):
        self.password = password
        self.kdf_type = kdf_type
        self.kdf_iterations = kdf_iterations
        self.gpu_config = gpu_config
        self.password_config = self._get_password_config()

    def _get_password_config(self) -> PasswordConfig:
        """Analyzes the password and returns its configuration."""
        return PasswordConfig(
            length=len(self.password),
            has_uppercase=any(c.isupper() for c in self.password),
            has_lowercase=any(c.islower() for c in self.password),
            has_digits=any(c.isdigit() for c in self.password),
            has_special=any(not c.isalnum() for c in self.password),
        )

    def _calculate_charset_size(self) -> int:
        """Calculates the size of the character set based on password configuration."""
        charset = 0
        if self.password_config.has_lowercase:
            charset += 26  # a-z
        if self.password_config.has_uppercase:
            charset += 26  # A-Z
        if self.password_config.has_digits:
            charset += 10  # 0-9
        if self.password_config.has_special:
            charset += 32  # Common special chars
        return charset

    def _adjust_for_kdf(self, combinations: float) -> float:
        """Adjusts the total combinations based on KDF iterations."""
        kdf_multiplier = 1
        if self.kdf_type == KDFType.ARGON2:
            kdf_multiplier = 100  # Argon2 is memory-hard; assume 100x slower than PBKDF2
        return combinations / (self.kdf_iterations * kdf_multiplier)

    def estimate_crack_time(self) -> dict:
        """Estimates the time required to crack the password."""
        charset_size = self._calculate_charset_size()
        total_combinations = charset_size ** self.password_config.length
        adjusted_combinations = self._adjust_for_kdf(total_combinations)

        seconds = adjusted_combinations / self.gpu_config.guesses_per_second

        return {
            "seconds": seconds,
            "minutes": seconds / 60,
            "hours": seconds / 3600,
            "days": seconds / 86400,
            "years": seconds / (86400 * 365),
        }


# Example Usage
if __name__ == "__main__":
    password = "Daniel@2410"  # Test password
    gpu = GPUConfig(guesses_per_second=1_000_000) 
    estimator = PasswordCrackerEstimator(
        password=password,
        kdf_type=KDFType.PBKDF2,
        kdf_iterations=600_000,  
        gpu_config=gpu,
    )

    results = estimator.estimate_crack_time()

    print(f"Password: {password}")
    print(f"Estimated crack time:")
    print(f"- Seconds: {results['seconds']:.2e}")
    print(f"- Hours: {results['hours']:.2e}")
    print(f"- Days: {results['days']:.2e}")
    print(f"- Years: {results['years']:.2e}")