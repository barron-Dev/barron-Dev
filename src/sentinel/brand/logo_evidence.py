from __future__ import annotations

"""Evidence-grade logo matching for suspicious public web pages."""

from dataclasses import dataclass
from typing import Iterable

from sentinel.brand.logo import LogoMatcher
from sentinel.brand.page_scraper import ImageArtifact, PageArtifact, fetch_image, fetch_page


@dataclass(frozen=True, slots=True)
class LogoMatch:
    source_url: str
    source_page: str
    relation: str
    alt: str | None
    image_sha256: str
    ahash_similarity: float
    dhash_similarity: float
    similarity: float


@dataclass(frozen=True, slots=True)
class LogoEvidence:
    page: PageArtifact
    matches: tuple[LogoMatch, ...]
    strongest_similarity: float


class LogoEvidenceScanner:
    """Fetch a public page, inspect declared image assets, and compare them to a trusted logo.

    Matching is deliberately multi-hash: dHash is useful for structural similarity while
    aHash provides a second independent signal. A match is evidence, not proof of ownership.
    """

    def __init__(self, *, matcher: LogoMatcher | None = None, threshold: float = 0.80) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        self._matcher = matcher or LogoMatcher()
        self._threshold = threshold

    async def scan(self, page_url: str, trusted_logo: bytes) -> LogoEvidence:
        if not trusted_logo:
            raise ValueError("trusted_logo must not be empty")
        trusted_a = self._matcher.ahash(trusted_logo)
        trusted_d = self._matcher.dhash(trusted_logo)
        if not trusted_a or not trusted_d:
            raise ValueError("trusted_logo is not a supported raster image")

        page = await fetch_page(page_url)
        matches: list[LogoMatch] = []
        for candidate in page.images:
            try:
                artifact = await fetch_image(candidate.url, page.final_url)
                match = self._score(trusted_a, trusted_d, artifact, candidate.relation, candidate.alt)
            except (OSError, ValueError):
                continue
            if match.similarity >= self._threshold:
                matches.append(match)

        matches.sort(key=lambda item: item.similarity, reverse=True)
        strongest = matches[0].similarity if matches else 0.0
        return LogoEvidence(page=page, matches=tuple(matches), strongest_similarity=strongest)

    def _score(self, trusted_a: str, trusted_d: str, artifact: ImageArtifact, relation: str, alt: str | None) -> LogoMatch:
        candidate_a = self._matcher.ahash(artifact.body)
        candidate_d = self._matcher.dhash(artifact.body)
        a_score = self._matcher.similarity(trusted_a, candidate_a)
        d_score = self._matcher.similarity(trusted_d, candidate_d)
        # Equal weighting avoids over-trusting either luminance or edge structure alone.
        combined = (a_score + d_score) / 2.0
        return LogoMatch(
            source_url=artifact.url,
            source_page=artifact.source_page,
            relation=relation,
            alt=alt,
            image_sha256=artifact.sha256,
            ahash_similarity=a_score,
            dhash_similarity=d_score,
            similarity=combined,
        )

    @staticmethod
    def strongest(matches: Iterable[LogoMatch]) -> LogoMatch | None:
        return max(matches, key=lambda item: item.similarity, default=None)
