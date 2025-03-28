import math
from dataclasses import dataclass
from enum import Enum, auto


class KDFType(Enum):
    PBKDF2 = auto()
    ARGON2ID = auto()


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
        self.password_config = self._analyze_password()

    def _analyze_password(self) -> PasswordConfig:
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
            charset += 26
        if self.password_config.has_uppercase:
            charset += 26
        if self.password_config.has_digits:
            charset += 10
        if self.password_config.has_special:
            charset += 32
        return charset

    def _apply_kdf_adjustment(self, combinations: float) -> float:
        """Adjusts the total combinations based on KDF type and iterations."""
        if self.kdf_type == KDFType.PBKDF2:
            return combinations / self.kdf_iterations
        if self.kdf_type == KDFType.ARGON2ID:
            return combinations / (self.kdf_iterations * 1000)
        return combinations

    def estimate_crack_time(self) -> dict:
        """Estimates the time required to crack the password."""
        charset_size = self._calculate_charset_size()
        total_combinations = charset_size ** self.password_config.length
        adjusted_combinations = self._apply_kdf_adjustment(total_combinations)

        seconds = adjusted_combinations / self.gpu_config.guesses_per_second

        return {
            "password": self.password,
            "entropy_bits": math.log2(total_combinations),
            "seconds": seconds,
            "minutes": seconds / 60,
            "hours": seconds / 3600,
            "days": seconds / 86400,
            "years": seconds / (86400 * 365),
            "kdf_type": self.kdf_type.name,
            "kdf_iterations": self.kdf_iterations,
            "gpu_speed": f"{self.gpu_config.guesses_per_second:,} guesses/sec",
        }


def format_time(seconds: float) -> str:
    """Formats time into human-readable units."""
    if seconds < 60:
        return f"{seconds:.2f} sec"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} min"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f} hours"
    elif seconds < 86400 * 365:
        days = seconds / 86400
        return f"{days:.2f} days"
    else:
        years = seconds / (86400 * 365)
        return f"{years:.2f} years"


def main():
    """Main function to demonstrate password cracking estimation."""
    password = "HowManY3E1I4agC"
    gpu = GPUConfig(guesses_per_second=10_000_000)

    for kdf_type, iterations in [(KDFType.PBKDF2, 600_000), (KDFType.ARGON2ID, 3)]:
        estimator = PasswordCrackerEstimator(
            password=password,
            kdf_type=kdf_type,
            kdf_iterations=iterations,
            gpu_config=gpu,
        )

        results = estimator.estimate_crack_time()

        print("\n" + "=" * 50)
        print(f"Password Analysis: {password}")
        print(f"KDF: {results['kdf_type']} ({results['kdf_iterations']} iterations)")
        print(f"GPU Speed: {results['gpu_speed']}")
        print(f"Entropy: {results['entropy_bits']:.1f} bits")
        print("\nEstimated crack time:")
        print(f"- {results['seconds']:.2f} sec")
        print(f"- {results['minutes']:.2f} min")
        print(f"- {results['hours']:.2f} hours")
        print(f"- {results['days']:.2f} days")
        print(f"- {results['years']:.2f} years")


if __name__ == "__main__":
    main()