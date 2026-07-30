# SkillsMP scientific security-skill retrieval design

Snapshot protocol for the improved marketplace audit.

## Technical constraint established by pilot

The documented SkillsMP search endpoint requires a query containing at least one letter or number. A category-wide wildcard request using `q=*` was rejected with `INVALID_QUERY`. Therefore, SkillsMP does not provide an unrestricted category listing through this API, and the study does not claim a full category census or a probability sample.

## Retrieval frames

A preregistered, equal-budget ontology of 25 security domains was derived from OWASP, CWE, NIST, MITRE ATT&CK, CIS, CSA, SLSA and related security frameworks. Each domain receives exactly two API calls under the `testing-security` category filter:

1. **Popularity frame:** the 50 top-star-ranked matches for the stratum query.
2. **Recency frame:** the 50 most-recent matches for the same query.

The 25 strata cover general security, vulnerability assessment, application review, web/API security, access control, injection, penetration testing, fuzzing, SAST, taint/data flow, dependency/SBOM, supply chain, secrets, cloud, IaC/container/Kubernetes, network/host, mobile, binary/firmware/memory, smart contracts, malware, threat detection, forensics, AI/LLM/agent/MCP, detection engineering and vulnerability intelligence.

A third, earlier high-recall ontology-query frame is integrated locally as a sensitivity supplement. The final SkillsMP corpus is the deduplicated union of all three frames.

## Source review

Every unique listing returned by the new paired frames is resolved to its actual GitHub `SKILL.md` and reviewed. Keyword screening is measured diagnostically but does not remove a ranked-frame record before source review. Included candidates receive file-history checks, adjacent-file inspection, evidence excerpts, dual classification and conservative duplicate detection.

## Diagnostics

The run records raw API responses, query parameters, standards justification, per-stratum marginal yield, cumulative saturation, popularity/recency overlap, source resolution, description-screen false negatives, inclusion/exclusion decisions, classifications and local evidence.
