"""Provider recognition from complete, label-bounded DNS suffixes."""

from dangl3.fingerprints import FingerprintDatabase, Provider


def identify_providers(targets: list[str], database: FingerprintDatabase) -> list[Provider]:
    """Return all matches so ambiguous multi-provider chains remain visible."""
    names = [target.lower().rstrip(".") for target in targets]
    return [provider for provider in database.providers
            if any(name.endswith("." + suffix)
                   for name in names for suffix in provider.dns_suffixes)
            or any(name in provider.dns_exact for name in names)]
