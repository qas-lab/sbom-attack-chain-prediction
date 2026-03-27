"""
Report generation module for performance test results.

This module handles generation of human-readable reports and summaries
from performance comparison data.
"""

import json
from datetime import datetime
from pathlib import Path
from textwrap import dedent
from typing import Any

from ...shared.models import PerformanceComparison
from ...shared.output import OutputManager


class PerformanceReporter:
    """Generates reports and summaries from performance comparison data."""

    def __init__(self, output_manager: OutputManager):
        self.output_manager = output_manager

    def save_results(self, comparison: PerformanceComparison) -> Path:
        """Save performance comparison results to JSON file."""
        results_dir = self.output_manager.base_dir / "performance_tests"
        results_dir.mkdir(exist_ok=True)

        results_file = results_dir / f"performance_test_{comparison.test_session_id}.json"

        with open(results_file, "w") as f:
            # Convert to dict with proper serialization
            from dataclasses import asdict

            results_data = asdict(comparison)
            json.dump(results_data, f, indent=2)

        return results_file

    def generate_report(self, comparison: PerformanceComparison) -> str:
        """Generate human-readable performance report."""
        mcp_stats = comparison.summary_stats["mcp_enhanced"]
        legacy_rag_stats = comparison.summary_stats["legacy_rag"]
        standalone_stats = comparison.summary_stats["standalone"]

        report = (
            dedent(
                f"""
            # SBOM Toolkit Performance Test Report

            **Test Session:** {comparison.test_session_id}
            **Timestamp:** {comparison.timestamp}
            **Repository:** {comparison.repository_url}
            **Total Test Cases:** {comparison.total_test_cases}

            ## Summary Results

            ### MCP-Enhanced RAG System
            - **Precision:** {mcp_stats.get("avg_precision", 0):.2%}
            - **Recall:** {mcp_stats.get("avg_recall", 0):.2%}
            - **F1 Score:** {mcp_stats.get("avg_f1_score", 0):.2%}
            - **F1.5 Score:** {mcp_stats.get("avg_f1_5_score", 0):.2%} (primary metric)
            - **Average Response Time:** {mcp_stats.get("avg_response_time", 0):.2f}s
            - **Success Rate:** {mcp_stats.get("success_rate", 0):.2%}
            - **Total Function Calls:** {mcp_stats.get("total_function_calls", 0)}

            ### Legacy RAG System
            - **Precision:** {legacy_rag_stats.get("avg_precision", 0):.2%}
            - **Recall:** {legacy_rag_stats.get("avg_recall", 0):.2%}
            - **F1 Score:** {legacy_rag_stats.get("avg_f1_score", 0):.2%}
            - **F1.5 Score:** {legacy_rag_stats.get("avg_f1_5_score", 0):.2%} (primary metric)
            - **Average Response Time:** {legacy_rag_stats.get("avg_response_time", 0):.2f}s
            - **Success Rate:** {legacy_rag_stats.get("success_rate", 0):.2%}

            ### Standalone LLM System
            - **Precision:** {standalone_stats.get("avg_precision", 0):.2%}
            - **Recall:** {standalone_stats.get("avg_recall", 0):.2%}
            - **F1 Score:** {standalone_stats.get("avg_f1_score", 0):.2%}
            - **F1.5 Score:** {standalone_stats.get("avg_f1_5_score", 0):.2%} (primary metric)
            - **Average Response Time:** {standalone_stats.get("avg_response_time", 0):.2f}s
            - **Success Rate:** {standalone_stats.get("success_rate", 0):.2%}

            ## Performance Comparison

            **Knowledge Augmentation Value (F1.5 Score):**
            - MCP vs Standalone: {(mcp_stats.get("avg_f1_5_score", 0) - standalone_stats.get("avg_f1_5_score", 0)) * 100:+.1f} percentage points
            - Legacy RAG vs Standalone: {(legacy_rag_stats.get("avg_f1_5_score", 0) - standalone_stats.get("avg_f1_5_score", 0)) * 100:+.1f} percentage points

            **Retrieval Method Comparison (F1.5 Score):**
            - MCP vs Legacy RAG: {(mcp_stats.get("avg_f1_5_score", 0) - legacy_rag_stats.get("avg_f1_5_score", 0)) * 100:+.1f} percentage points

            **Response Time Analysis:**
            - MCP vs Standalone: {mcp_stats.get("avg_response_time", 0) - standalone_stats.get("avg_response_time", 0):+.2f}s
            - Legacy RAG vs Standalone: {legacy_rag_stats.get("avg_response_time", 0) - standalone_stats.get("avg_response_time", 0):+.2f}s
            - MCP vs Legacy RAG: {mcp_stats.get("avg_response_time", 0) - legacy_rag_stats.get("avg_response_time", 0):+.2f}s
        """
            ).strip()
            + "\n\n"
        )

        # Enhanced conclusion with 3-way analysis using F1.5 as primary metric
        best_system = max(
            ("MCP", mcp_stats.get("avg_f1_5_score", 0)),
            ("Legacy RAG", legacy_rag_stats.get("avg_f1_5_score", 0)),
            ("Standalone", standalone_stats.get("avg_f1_5_score", 0)),
            key=lambda x: x[1],
        )[0]

        knowledge_augmentation_benefit = max(
            mcp_stats.get("avg_f1_5_score", 0), legacy_rag_stats.get("avg_f1_5_score", 0)
        ) - standalone_stats.get("avg_f1_5_score", 0)

        report += dedent(
            f"""
            ## Conclusion

            **Best Overall System:** {best_system} with {max(mcp_stats.get("avg_f1_5_score", 0), legacy_rag_stats.get("avg_f1_5_score", 0), standalone_stats.get("avg_f1_5_score", 0)):.2%} F1.5 score

            **Knowledge Augmentation Analysis:**
            - Both knowledge-augmented systems (MCP and Legacy RAG) {"outperformed" if knowledge_augmentation_benefit > 0 else "underperformed compared to"} the standalone LLM
            - Knowledge augmentation provided a {knowledge_augmentation_benefit * 100:+.1f} percentage point F1.5 benefit on average
            - This demonstrates the value of external knowledge integration for cybersecurity analysis

            **Retrieval Method Analysis:**
            - MCP (structured function calls): {mcp_stats.get("avg_f1_5_score", 0):.2%} F1.5 score, {mcp_stats.get("total_function_calls", 0)} function calls
            - Legacy RAG (embedding similarity): {legacy_rag_stats.get("avg_f1_5_score", 0):.2%} F1.5 score, vector search
            - The {"structured" if mcp_stats.get("avg_f1_5_score", 0) > legacy_rag_stats.get("avg_f1_5_score", 0) else "embedding-based"} approach proved more effective for this domain

            This 3-way comparison provides clear evidence of how different knowledge integration strategies perform relative to baseline LLM capabilities.
        """
        ).strip()

        return report

    def generate_summary_text(self, comparison: PerformanceComparison) -> str:
        """Generate summary text that can be used in both console output and detailed logs."""
        mcp_stats = comparison.summary_stats["mcp_enhanced"]
        legacy_rag_stats = comparison.summary_stats["legacy_rag"]
        standalone_stats = comparison.summary_stats["standalone"]

        summary = "=" * 80 + "\n"
        summary += "📊 3-WAY PERFORMANCE COMPARISON RESULTS\n"
        summary += "=" * 80 + "\n"

        # Citation Analysis - Most Important for Academic Paper
        mcp_citation_score = mcp_stats.get("total_citation_points", 0)
        rag_citation_score = legacy_rag_stats.get("total_citation_points", 0)
        standalone_citation_score = standalone_stats.get("total_citation_points", 0)
        max_possible_citations = mcp_stats["tests_completed"] * 100  # 100 points per test max

        summary += "🎯 CITATION ACCURACY ANALYSIS (Primary Research Metric):\n"
        summary += f"   MCP Citation Score:        {mcp_citation_score:.1f} / {max_possible_citations:.0f} ({mcp_citation_score / max_possible_citations * 100:.1f}%)\n"
        summary += f"   Legacy RAG Citation Score: {rag_citation_score:.1f} / {max_possible_citations:.0f} ({rag_citation_score / max_possible_citations * 100:.1f}%)\n"
        summary += f"   Standalone Citation Score: {standalone_citation_score:.1f} / {max_possible_citations:.0f} ({standalone_citation_score / max_possible_citations * 100:.1f}%)\n"

        # Determine best performer for citations
        best_citation_score = max(mcp_citation_score, rag_citation_score, standalone_citation_score)
        best_citation_system = (
            "MCP"
            if mcp_citation_score == best_citation_score
            else "Legacy RAG"
            if rag_citation_score == best_citation_score
            else "Standalone"
        )
        summary += f"   🏆 Best Citation Performance: {best_citation_system} ({best_citation_score / max_possible_citations * 100:.1f}%)\n"

        # Handle partial results display
        if comparison.summary_stats.get("interrupted", False):
            summary += "\n⚠️  RESULTS ARE PARTIAL DUE TO INTERRUPTION\n"
            summary += f"   Tests completed: {comparison.summary_stats['tests_completed']} of {comparison.summary_stats['tests_attempted']}\n"

        summary += "\n📈 KNOWLEDGE AUGMENTATION ANALYSIS:\n"
        mcp_vs_standalone = mcp_stats.get("avg_f1_5_score", 0) - standalone_stats.get(
            "avg_f1_5_score", 0
        )
        rag_vs_standalone = legacy_rag_stats.get("avg_f1_5_score", 0) - standalone_stats.get(
            "avg_f1_5_score", 0
        )
        best_augmented = max(
            mcp_stats.get("avg_f1_5_score", 0), legacy_rag_stats.get("avg_f1_5_score", 0)
        )
        knowledge_benefit = best_augmented - standalone_stats.get("avg_f1_5_score", 0)

        summary += f"   Standalone LLM Baseline:   {standalone_stats.get('avg_f1_5_score', 0):.2%} F1.5 score\n"
        summary += (
            f"   MCP Knowledge Benefit:     {mcp_vs_standalone * 100:+.1f} percentage points\n"
        )
        summary += (
            f"   Legacy RAG Knowledge Benefit: {rag_vs_standalone * 100:+.1f} percentage points\n"
        )
        summary += f"   🎯 Overall Knowledge Value: {knowledge_benefit * 100:.1f} percentage points benefit\n"

        summary += "\n🔄 RETRIEVAL METHOD COMPARISON:\n"
        mcp_vs_rag = mcp_stats.get("avg_f1_5_score", 0) - legacy_rag_stats.get("avg_f1_5_score", 0)
        summary += f"   MCP (Structured Calls):    {mcp_stats.get('avg_f1_5_score', 0):.2%} F1.5 score, {mcp_stats.get('total_function_calls', 0)} function calls\n"
        summary += f"   Legacy RAG (Vector Search): {legacy_rag_stats.get('avg_f1_5_score', 0):.2%} F1.5 score, top-5 similarity\n"
        summary += f"   📊 Retrieval Method Advantage: {'MCP' if mcp_vs_rag > 0 else 'Legacy RAG'} by {abs(mcp_vs_rag) * 100:.1f} points\n"

        summary += "\n" + "=" * 80 + "\n"

        return summary

    def save_detailed_logs(
        self,
        test_session_id: str,
        detailed_logs: list[dict[str, Any]],
        comparison: PerformanceComparison | None = None,
    ) -> Path | None:
        """Save detailed test logs to a markdown file with full tool call details."""
        if not detailed_logs:
            return None

        results_dir = self.output_manager.base_dir / "performance_tests"
        results_dir.mkdir(exist_ok=True)
        logs_file = results_dir / f"detailed_logs_{test_session_id}.md"

        with open(logs_file, "w") as f:
            f.write("# DETAILED PERFORMANCE TEST LOGS\n\n")
            f.write(f"**Test Session:** `{test_session_id}`\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
            f.write("---\n\n")

            for i, log_entry in enumerate(detailed_logs, 1):
                f.write(f"## Test {i}: {log_entry['category'].replace('_', ' ').title()}\n\n")
                f.write(f"**System:** {log_entry['system_type']}\n")
                f.write(f"**Category:** {log_entry['category']}\n")
                f.write(f"**Difficulty:** {log_entry['difficulty']}\n\n")
                f.write("### Question\n\n")
                f.write(f"{log_entry['question']}\n\n")

                if log_entry.get("function_calls"):
                    f.write("### Tool Calls\n\n")
                    for j, call in enumerate(log_entry["function_calls"], 1):
                        f.write(f"{j}. `{call}`\n")
                    f.write("\n")

                    # Also show the actual results from function calls for debugging
                    if log_entry.get("function_call_results"):
                        f.write("### Tool Call Results\n\n")
                        for j, result_data in enumerate(log_entry["function_call_results"], 1):
                            f.write(f"**Call {j}: {result_data['function']}**\n")
                            result = result_data.get("result", {})
                            # Truncate large results for readability
                            result_str = json.dumps(result, indent=2)
                            if len(result_str) > 1000:
                                result_preview = result_str[:1000] + "...\n(truncated)"
                            else:
                                result_preview = result_str
                            f.write(f"```json\n{result_preview}\n```\n\n")
                else:
                    # For legacy RAG, show retrieved documents
                    if log_entry["system_type"] == "legacy_rag" and log_entry.get(
                        "retrieved_documents"
                    ):
                        f.write("### Retrieved Documents\n\n")
                        retrieved_docs = log_entry.get("retrieved_documents", [])
                        similarities = log_entry.get("similarities", [])

                        for j, doc in enumerate(retrieved_docs, 1):
                            similarity = similarities[j - 1] if j - 1 < len(similarities) else 0.0
                            f.write(f"**Document {j}** (Similarity: {similarity:.3f})\n")
                            # Truncate long documents for readability
                            doc_preview = doc[:500] + "..." if len(doc) > 500 else doc
                            f.write(f"```\n{doc_preview}\n```\n\n")
                    else:
                        f.write("### Tool Calls\n\n")
                        f.write("*No tool calls (Standalone LLM)*\n\n")

                f.write("### LLM Response\n\n")
                f.write(f"{log_entry['response']}\n\n")

                f.write("### Evaluation\n\n")
                eval_result = log_entry.get("evaluation_result", {})
                f.write(f"**Precision:** {eval_result.get('precision', 0.0):.2%}\n")
                f.write(f"**Recall:** {eval_result.get('recall', 0.0):.2%}\n")
                f.write(f"**F1 Score:** {eval_result.get('f1_score', 0.0):.2%}\n")
                f.write(
                    f"**F1.5 Score:** {eval_result.get('f1_5_score', 0.0):.2%} (primary metric)\n\n"
                )

                if eval_result.get("citation_metrics"):
                    cm = eval_result["citation_metrics"]
                    f.write(f"**Citation Precision:** {cm.get('precision', 0):.2%}\n")
                    f.write(f"**Citation Recall:** {cm.get('recall', 0):.2%}\n")
                    f.write(f"**Citation F1:** {cm.get('f1', 0):.2%}\n")
                    f.write(f"**Correct Citations:** {cm.get('correct', 0)}\n")
                    f.write(f"**Incorrect Citations:** {cm.get('incorrect', 0)}\n")
                    f.write(f"**Total Citations:** {cm.get('total', 0)}\n\n")

                f.write("---\n\n")

            # Add summary at the end if comparison data is available
            if comparison is not None:
                f.write("\n")
                summary_text = self.generate_summary_text(comparison)
                f.write(summary_text)
                f.write("\n")

        return logs_file
