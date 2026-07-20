"""Independent bootstrap certification.

A certification forge cannot be its own circular root of trust: if the same key that signs run
verdicts also attests the forge's own integrity, a compromise of that key forges both. The bootstrap
certifier signs a self-certification attestation with a **bootstrap key that MUST be distinct from the
operational run-verdict signer**. The resulting envelope is verifiable with the shared
`TrustedPublicKeyRegistry`, and — critically — is NOT verifiable under the run-signer key, which is
what makes the bootstrap trust anchor independent.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .canonical import to_utc_iso
from .models import SignedVerdictEnvelope
from .signing import Ed25519VerdictSigner

BOOTSTRAP_SCHEMA_VERSION = "bootstrap.v1"
BOOTSTRAP_SUBJECT = "echo-certification-forge"


class BootstrapError(RuntimeError):
    """Raised when the bootstrap invariant (independent signer) is violated."""


@dataclass(frozen=True, slots=True)
class BootstrapClaim:
    """One self-certification claim about the forge's own integrity, with an evidence pointer."""
    name: str
    satisfied: bool
    evidence_ref: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "satisfied": self.satisfied, "evidence_ref": self.evidence_ref}


class BootstrapCertifier:
    """Signs the forge's independent self-certification attestation.

    The signer here is deliberately a SEPARATE Ed25519 key from any run-verdict signer. `certify`
    fail-closes if handed a run-signer key id equal to its own — the whole point is independence.
    """

    def __init__(self, signer: Ed25519VerdictSigner) -> None:
        self._signer = signer

    @classmethod
    def generate(cls) -> "BootstrapCertifier":
        return cls(Ed25519VerdictSigner.generate())

    @classmethod
    def from_private_pem(cls, private_key_pem: bytes, password: bytes | None = None) -> "BootstrapCertifier":
        return cls(Ed25519VerdictSigner.from_private_pem(private_key_pem, password))

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    @property
    def public_key_pem(self) -> str:
        return self._signer.public_key_pem

    def certify(
        self,
        claims: list[BootstrapClaim],
        *,
        run_signer_key_id: str,
        issued_at: datetime,
    ) -> SignedVerdictEnvelope:
        """Emit a signed bootstrap attestation.

        Verdict is CERTIFIED only if there is at least one claim and every claim is satisfied
        (default-deny: no claims → NOT_CERTIFIED). Raises BootstrapError if the bootstrap key is
        not independent of the supplied run-verdict signer key id.
        """
        if not run_signer_key_id:
            raise BootstrapError("run_signer_key_id is required to prove signer independence")
        if run_signer_key_id == self.key_id:
            raise BootstrapError(
                "bootstrap signer must be independent of the run-verdict signer "
                f"(both are {self.key_id})"
            )
        certified = len(claims) > 0 and all(claim.satisfied for claim in claims)
        payload = {
            "schema_version": BOOTSTRAP_SCHEMA_VERSION,
            "subject": BOOTSTRAP_SUBJECT,
            "attestation_type": "independent_bootstrap",
            "bootstrap_verdict": "CERTIFIED" if certified else "NOT_CERTIFIED",
            "run_signer_key_id": run_signer_key_id,
            "claims": [claim.to_dict() for claim in claims],
            "unsatisfied_claims": [c.name for c in claims if not c.satisfied],
            "signing_key_id": self.key_id,
            "issued_at": to_utc_iso(issued_at),
        }
        return self._signer.sign_payload(payload)
