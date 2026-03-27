"""
Advanced evaluation metrics for measuring LLM response quality.

This module provides sophisticated evaluation methods including citation accuracy,
factual accuracy checking, and domain-specific criteria evaluation.
"""

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class EvaluationResult:
    """Result of evaluating an LLM response."""

    elements_found: list[str]
    accuracy_score: float
    detailed_scores: dict[str, Any]


class AdvancedEvaluator:
    """Advanced evaluation system for LLM responses."""

    def __init__(self, quiet_mode: bool = False):
        self.quiet_mode = quiet_mode

    def evaluate_response(
        self, test_case, response: str, context_data: dict[str, Any], system_type: str
    ) -> dict[str, Any]:
        """Advanced evaluation of LLM responses using research-friendly metrics."""
        if not self.quiet_mode:
            print(f"    🔍 Advanced evaluation for {system_type}...")
        try:
            # Focus on ID Citation Quality (precision/recall/F1) - primary metric
            citation_metrics = self._evaluate_id_citation_metrics(
                response, context_data, system_type
            )
            if not self.quiet_mode:
                print(
                    f"      ✓ ID Citations: P={citation_metrics['precision']:.2%}, R={citation_metrics['recall']:.2%}, F1={citation_metrics['f1']:.2%}, F1.5={citation_metrics['f1_5']:.2%}"
                )

            # Response Quality Assessment (simple, honest metrics)
            quality_score = self._evaluate_response_quality(response, test_case)
            if not self.quiet_mode:
                print(f"      ✓ Response quality: {quality_score:.2%}")

            # Return individual metrics instead of weighted combination
            if not self.quiet_mode:
                print(f"      → Primary metric (F-1.5): {citation_metrics['f1_5']:.2%}")

            return {
                "precision": citation_metrics["precision"],
                "recall": citation_metrics["recall"],
                "f1_score": citation_metrics["f1"],
                "f1_5_score": citation_metrics["f1_5"],
                "citation_metrics": citation_metrics,
                "detailed_scores": {
                    "citation_precision": citation_metrics["precision"],
                    "citation_recall": citation_metrics["recall"],
                    "citation_f1": citation_metrics["f1"],
                    "citation_f1_5": citation_metrics["f1_5"],
                    "citation_correct": citation_metrics["correct"],
                    "citation_incorrect": citation_metrics["incorrect"],
                    "citation_total": citation_metrics["total"],
                    "citation_correct_ids": citation_metrics["correct_ids"],
                    "citation_incorrect_ids": citation_metrics["incorrect_ids"],
                    "response_quality": quality_score,
                },
            }
        except Exception as e:
            if not self.quiet_mode:
                print(f"      ❌ Advanced evaluation failed: {e}")
                import traceback

                traceback.print_exc()
            return {
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "f1_5_score": 0.0,
                "citation_metrics": {
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "f1_5": 0.0,
                    "f_beta": 0.0,  # Keep for backward compatibility
                    "correct": 0,
                    "incorrect": 0,
                    "total": 0,
                    "correct_ids": [],
                    "incorrect_ids": [],
                },
                "detailed_scores": {
                    "citation_precision": 0.0,
                    "citation_recall": 0.0,
                    "citation_f1": 0.0,
                    "citation_f1_5": 0.0,
                    "citation_correct": 0,
                    "citation_incorrect": 0,
                    "citation_total": 0,
                    "citation_correct_ids": [],
                    "citation_incorrect_ids": [],
                    "response_quality": 0.0,
                },
            }

    def _evaluate_response_quality(self, response: str, test_case) -> float:
        """Evaluate basic response quality with simple, honest metrics."""
        score = 0.0
        checks = 0

        # Check 1: Response is substantial (not just a few words)
        if len(response.split()) >= 30:
            score += 1
        checks += 1

        # Check 2: Response contains security-relevant content
        security_terms = [
            "vulnerability",
            "security",
            "risk",
            "attack",
            "exploit",
            "cve",
            "component",
        ]
        if any(term in response.lower() for term in security_terms):
            score += 1
        checks += 1

        # Check 3: Response attempts to analyze rather than just list
        analysis_terms = [
            "analysis",
            "finding",
            "evidence",
            "because",
            "therefore",
            "indicates",
        ]
        if any(term in response.lower() for term in analysis_terms):
            score += 1
        checks += 1

        # Check 4: Response contains some form of structured presentation
        if any(marker in response for marker in [":", "-", "[", "Key", "Evidence", "Analysis"]):
            score += 1
        checks += 1

        return score / checks if checks > 0 else 0.0

    # Remove the old methods that were causing issues
    def _check_factual_accuracy(
        self, response: str, context_data: dict[str, Any], system_type: str
    ) -> float:
        """Deprecated - replaced with citation metrics."""
        return 0.5  # Neutral score since this method was unreliable

    def _evaluate_domain_criteria(
        self, test_case, response: str, context_data: dict[str, Any]
    ) -> float:
        """Deprecated - replaced with response quality assessment."""
        return 0.5  # Neutral score since this was just keyword matching

    def _has_structured_citation(self, response: str) -> bool:
        """Check if response has structured citations indicating use of function calls."""
        return any(
            pattern in response.lower()
            for pattern in [
                "data source:",
                "key finding:",
                "evidence:",
                "function:",
                "analysis shows",
                "according to",
                "citations:",
                "analysis:",
                "[1]",
                "[2]",
                "[3]",  # New formats
            ]
        )

    def _shows_progressive_reasoning(self, response: str) -> bool:
        """Check if response shows progressive, multi-step reasoning."""
        return (
            len(
                [
                    word
                    for word in [
                        "first",
                        "then",
                        "next",
                        "furthermore",
                        "additionally",
                        "consequently",
                    ]
                    if word in response.lower()
                ]
            )
            >= 2
        )

    def _demonstrates_graph_traversal(self, response: str) -> bool:
        """Check if response demonstrates understanding of graph relationships."""
        return any(
            term in response.lower()
            for term in [
                "path",
                "traverse",
                "connected",
                "relationship",
                "linked",
                "dependency chain",
            ]
        )

    def _shows_intelligence_synthesis(self, response: str) -> bool:
        """Check if response synthesizes multiple types of intelligence."""
        intelligence_types = [
            "cve",
            "cwe",
            "capec",
            "vulnerability",
            "dependency",
            "component",
        ]
        return len([itype for itype in intelligence_types if itype in response.lower()]) >= 3

    def _shows_risk_prioritization(self, response: str) -> bool:
        """Check if response demonstrates risk prioritization reasoning."""
        return any(
            term in response.lower()
            for term in [
                "prioritize",
                "critical",
                "highest risk",
                "most important",
                "should focus",
            ]
        )

    def _demonstrates_impact_analysis(self, response: str) -> bool:
        """Check if response demonstrates impact analysis thinking."""
        return any(
            term in response.lower()
            for term in [
                "impact",
                "affect",
                "consequence",
                "result",
                "cascade",
                "propagate",
            ]
        )

    def _shows_complex_reasoning(self, response: str) -> bool:
        """Check if response shows complex, multi-layered reasoning."""
        reasoning_indicators = [
            "because",
            "therefore",
            "since",
            "due to",
            "as a result",
            "leads to",
        ]
        return (
            len([indicator for indicator in reasoning_indicators if indicator in response.lower()])
            >= 2
        )

    def _demonstrates_strategic_thinking(self, response: str) -> bool:
        """Check if response demonstrates strategic security thinking."""
        return any(
            term in response.lower()
            for term in [
                "strategy",
                "approach",
                "recommend",
                "should",
                "priority",
                "focus",
                "plan",
            ]
        )

    def _has_specific_details(self, response: str) -> bool:
        """Check if response contains specific technical details."""
        return any(
            pattern in response for pattern in ["CVE-", "CVSS", "v", ".", "score", "severity"]
        )

    def _get_flexible_matches(self, keyword: str) -> list[str]:
        """Generate flexible variations of keywords for more robust matching."""
        variations = []

        # Common patterns and their variations
        patterns = {
            "cascade": ["cascading", "cascades", "cascade effect", "chain reaction"],
            "dependency": [
                "dependencies",
                "dependent",
                "depends",
                "dependant",
                "reliance",
            ],
            "impact": ["impacts", "affecting", "effect", "effects", "influence"],
            "attack": ["attacks", "attacking", "exploit", "exploits", "exploitation"],
            "vulnerability": [
                "vulnerabilities",
                "vuln",
                "vulns",
                "security flaw",
                "weakness",
            ],
            "critical": ["high severity", "severe", "high risk", "major"],
            "risk": ["risks", "risky", "threat", "threats", "danger"],
            "security": ["secure", "securing", "safety", "protection"],
            "supply chain": [
                "supply-chain",
                "software supply chain",
                "dependency chain",
            ],
            "blast radius": ["impact radius", "scope of impact", "affected scope"],
        }

        # Add exact keyword
        variations.append(keyword)

        # Add predefined patterns
        if keyword in patterns:
            variations.extend(patterns[keyword])

        # Add simple plural/singular variations
        if keyword.endswith("s") and len(keyword) > 3:
            variations.append(keyword[:-1])  # Remove 's'
        elif not keyword.endswith("s"):
            variations.append(keyword + "s")  # Add 's'

        # Add 'ing' variations for verbs
        if keyword.endswith("e"):
            variations.append(keyword[:-1] + "ing")
        else:
            variations.append(keyword + "ing")

        return list(set(variations))  # Remove duplicates

    def _evaluate_id_citation_metrics(
        self, response: str, context_data: dict[str, Any], system_type: str
    ) -> dict[str, Any]:
        """Compute precision, recall, F1, and ID lists for CVE/CWE/CAPEC citations.

        RELEVANCE-BASED: Rewards focused, accurate citations over broad coverage.
        """

        # Extract all cited IDs
        cve_citations = set(re.findall(r"CVE-\d{4}-\d{4,7}", response, re.IGNORECASE))
        cwe_citations = set(re.findall(r"CWE-\d{1,4}", response, re.IGNORECASE))
        capec_citations = set(re.findall(r"CAPEC-\d{1,4}", response, re.IGNORECASE))
        cited_ids = {id.upper() for id in cve_citations | cwe_citations | capec_citations}

        # Get all available IDs from knowledge graph - USE SAME GROUND TRUTH FOR ALL SYSTEMS
        if context_data and context_data.get("nodes"):
            # Use knowledge graph as single source of truth for ALL systems including standalone
            kg_nodes = {node["id"].upper() for node in context_data.get("nodes", [])}
            available_ids = {
                nid
                for nid in kg_nodes
                if nid.startswith("CVE-") or nid.startswith("CWE-") or nid.startswith("CAPEC-")
            }

            # Get vulnerable components to understand scale
            vulnerable_components = [
                node
                for node in context_data.get("nodes", [])
                if node.get("type") == "Version" and node.get("is_vulnerable", False)
            ]
            num_vulnerable_components = len(vulnerable_components)
        else:
            # No knowledge graph available - cannot validate citations
            print(
                f"      ⚠️  No knowledge graph available for {system_type} - citation validation disabled"
            )
            available_ids = set()
            num_vulnerable_components = 1

        # Calculate correct and incorrect citations
        correct_ids = cited_ids & available_ids
        incorrect_ids = cited_ids - available_ids

        # **PRECISION**: What percentage of cited IDs are valid? (This should be high)
        precision = len(correct_ids) / len(cited_ids) if cited_ids else 1.0

        # **RELEVANCE-BASED RECALL**: Reward focused, coherent citations
        # Determine optimal citation range based on response focus and complexity
        response_word_count = len(response.split())

        # **COHERENCE ANALYSIS**: Check if citations are thematically related
        citation_coherence = self._analyze_citation_coherence(correct_ids, response)

        # **QUESTION-SPECIFIC EXPECTATIONS**: Different questions need different citation patterns
        question_keywords = ["pattern", "correlat", "attack technique", "feasible"]
        is_pattern_question = any(keyword in response.lower() for keyword in question_keywords)

        if is_pattern_question:
            # Pattern analysis questions benefit from focused, thematic citations
            optimal_range = (3, 6)  # 3-6 citations for pattern questions
        else:
            # General security questions can have broader citation ranges
            if num_vulnerable_components <= 2:
                optimal_range = (2, 4)  # Simple systems
            elif num_vulnerable_components <= 5:
                optimal_range = (4, 7)  # Medium complexity
            else:
                optimal_range = (6, 9)  # Complex systems

        # Adjust for response length
        if response_word_count > 400:
            optimal_range = (optimal_range[0], optimal_range[1] + 2)
        elif response_word_count < 200:
            optimal_range = (max(1, optimal_range[0] - 1), optimal_range[1] - 1)

        # **QUALITY-BASED RECALL**: Reward being within optimal range
        num_correct = len(correct_ids)
        min_expected, max_expected = optimal_range

        if num_correct >= min_expected and num_correct <= max_expected:
            # Perfect recall for being in optimal range
            recall = 1.0
        elif num_correct < min_expected:
            # Partial recall for under-citing
            recall = num_correct / min_expected
        else:
            # Penalty for over-citing (diminishing returns)
            excess = num_correct - max_expected
            recall = 1.0 - (excess * 0.1)  # 10% penalty per excess citation
            recall = max(0.0, recall)

        # **COHERENCE BONUS**: Reward thematically related citations
        recall_with_coherence = min(1.0, recall + citation_coherence * 0.1)

        # **HALLUCINATION PENALTY**: Heavily penalize incorrect citations
        hallucination_penalty = len(incorrect_ids) * 0.15  # 15% penalty per false citation

        # Calculate both F1 (β=1.0) and F-1.5 (β=1.5) scores
        def calculate_f_score(beta_value: float) -> float:
            if (precision + recall_with_coherence) > 0:
                return ((1 + beta_value**2) * precision * recall_with_coherence) / (
                    (beta_value**2 * precision) + recall_with_coherence
                )
            else:
                return 0.0

        # Calculate base scores
        base_f1 = calculate_f_score(1.0)  # F1 score (balanced)
        base_f1_5 = calculate_f_score(1.5)  # F-1.5 score (recall-focused)

        # Apply penalties to both scores
        penalized_f1 = max(0.0, base_f1 - hallucination_penalty)
        penalized_f1_5 = max(0.0, base_f1_5 - hallucination_penalty)

        # **DIVERSITY BONUS**: Reward citing different types of IDs (CVE + CWE + CAPEC)
        citation_types = 0
        if len(cve_citations) > 0:
            citation_types += 1
        if len(cwe_citations) > 0:
            citation_types += 1
        if len(capec_citations) > 0:
            citation_types += 1

        # Apply diversity bonus (up to 8% boost) to both scores
        diversity_bonus = min(0.08, citation_types * 0.03)
        final_f1 = min(1.0, penalized_f1 + diversity_bonus)
        final_f1_5 = min(1.0, penalized_f1_5 + diversity_bonus)

        return {
            "precision": precision,
            "recall": recall_with_coherence,
            "f1": final_f1,  # F1 score (beta=1.0) for balanced comparison
            "f1_5": final_f1_5,  # F-1.5 score (beta=1.5) for recall-focused evaluation
            "f_beta": final_f1_5,  # Keep f_beta for backward compatibility (points to F-1.5)
            "correct": len(correct_ids),
            "incorrect": len(incorrect_ids),
            "total": len(cited_ids),
            "correct_ids": sorted(correct_ids),
            "incorrect_ids": sorted(incorrect_ids),
            "optimal_range": optimal_range,
            "citation_coherence": citation_coherence,
            "hallucination_penalty": hallucination_penalty,
            "diversity_bonus": diversity_bonus,
            "base_f1": base_f1,  # Base F1 score (before penalties)
            "base_f1_5": base_f1_5,  # Base F-1.5 score (before penalties)
            "num_vulnerable_components": num_vulnerable_components,
            "is_pattern_question": is_pattern_question,
        }

    def _analyze_citation_coherence(self, correct_ids: set, response: str) -> float:
        """Analyze if citations are thematically coherent and relevant to the response.

        Returns a coherence score between 0.0 and 1.0.
        """
        if not correct_ids:
            return 0.0

        # Extract themes from response
        response_lower = response.lower()

        # Define thematic clusters
        theme_clusters = {
            "injection": ["inject", "command", "code", "script", "execute"],
            "web_attacks": ["http", "xss", "csrf", "request", "response", "cookie"],
            "input_validation": ["input", "validation", "sanitize", "filter", "encode"],
            "access_control": [
                "access",
                "authorization",
                "authentication",
                "privilege",
                "permission",
            ],
            "dos": ["denial", "service", "resource", "exhaust", "flood", "dos"],
            "info_disclosure": [
                "disclosure",
                "information",
                "leak",
                "exposure",
                "sensitive",
            ],
        }

        # Find dominant themes in response
        dominant_themes = []
        for theme, keywords in theme_clusters.items():
            theme_count = sum(1 for keyword in keywords if keyword in response_lower)
            if theme_count >= 2:  # Theme must appear at least twice
                dominant_themes.append(theme)

        if not dominant_themes:
            return 0.5  # Neutral coherence if no clear theme

        # Map citation IDs to likely themes (simplified heuristic)
        citation_themes = set()
        for _citation in correct_ids:
            if any(keyword in response_lower for keyword in ["inject", "command", "code"]):
                citation_themes.add("injection")
            if any(keyword in response_lower for keyword in ["http", "request", "cookie"]):
                citation_themes.add("web_attacks")
            if any(keyword in response_lower for keyword in ["input", "validation"]):
                citation_themes.add("input_validation")
            if any(keyword in response_lower for keyword in ["access", "authorization"]):
                citation_themes.add("access_control")
            if any(keyword in response_lower for keyword in ["denial", "resource"]):
                citation_themes.add("dos")
            if any(keyword in response_lower for keyword in ["disclosure", "leak"]):
                citation_themes.add("info_disclosure")

        # Calculate coherence as overlap between dominant themes and citation themes
        if not citation_themes:
            return 0.5

        overlap = len(set(dominant_themes) & citation_themes)
        total_citation_themes = len(citation_themes)

        # High coherence when citations align with response themes
        coherence = overlap / total_citation_themes if total_citation_themes > 0 else 0.0

        return min(1.0, coherence)
