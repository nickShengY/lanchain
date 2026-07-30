# SkillsMP scientific security-skill retrieval design

Snapshot protocol for the improved marketplace audit.

## Retrieval frames

1. **Popularity frame:** `q=*`, category `testing-security`, `sortBy=stars`, pages 1–25, limit 50. This deterministically captures the top 1,250 category-ranked results by GitHub repository stars returned by the documented SkillsMP API.
2. **Recency frame:** the same category-wide wildcard query with `sortBy=recent`, pages 1–25, limit 50. This captures the 1,250 most recently updated category results.
3. **Ontology frame:** the previously collected, preregistered security/vulnerability search-query union is integrated locally after the ranked-frame run. It covers security domains and techniques that may not appear in the popularity or recency frames.

The union is not called a full SkillsMP Security-category census or a probability sample. It is a reproducible multi-frame coverage study designed to represent popularity, recency, and domain terminology separately.

## Source review

Every unique record in the two category-ranked frames is source-resolved and reviewed; keyword screening is measured diagnostically but does not remove records before GitHub source review. The audit retrieves the real `SKILL.md`, reviews adjacent implementation/reference files for included candidates, records GitHub file history, removes inactive sources and deduplicates translations, aliases, mirrors, and conservative near-copies.

## Diagnostics

The run records API request parameters and raw responses, frame overlap, page-level marginal yield, saturation, source-resolution rates, source-level decisions, description-screen false negatives, classification counts, duplicate groups, and local evidence for every reviewed record.
