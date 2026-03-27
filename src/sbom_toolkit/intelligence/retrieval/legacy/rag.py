import os
from collections import defaultdict
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from openai import OpenAI

try:
    from openai import OpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None  # type: ignore[misc,assignment]

from sbom_toolkit.intelligence.prompts import get_rag_system_prompt, get_rag_user_prompt
from sbom_toolkit.shared.streaming import progress_manager, stream_openai_response


class RAGSystem:
    """
    A simple RAG (Retrieval-Augmented Generation) pipeline that demonstrates:
    1. Document ingestion and embedding
    2. Similarity search for retrieval
    3. Context augmentation for generation
    """

    def __init__(
        self, api_key: str | None = None, require_openai: bool = True, embedding_cache=None
    ):
        """Initialize the RAG system with OpenAI client"""
        self.documents: list[str] = []
        self.embeddings: list[np.ndarray] = []
        self.embedding_model = "text-embedding-3-small"
        self.chat_model = "gpt-4o"
        self.client: Any | None = None
        self.embedding_cache = embedding_cache  # Optional embedding cache for performance

        if not OPENAI_AVAILABLE:
            if require_openai:
                raise Exception("OpenAI package not installed. Install with: pip install openai")
            else:
                print("Warning: OpenAI not available. RAG system will work in KG-only mode")
                return

        try:
            provided_key = api_key or os.getenv("OPENAI_API_KEY")
            if provided_key and OpenAI is not None:
                self.client = OpenAI(api_key=provided_key)
            elif require_openai:
                raise Exception("OpenAI API key required but not provided")
        except Exception as e:
            if require_openai:
                print(f"Error initializing RAG system: {e}")
                raise
            else:
                print(f"Warning: OpenAI client not initialized: {e}")
                print("RAG system will work in KG-only mode")

    def add_documents(self, documents: list[str]):
        """Add documents to the RAG system."""
        self.documents.extend(documents)

    def generate_embeddings(self, kg_data: dict[str, Any] | None = None):
        """Generate embeddings for all documents and optionally cache them.

        Args:
            kg_data: Knowledge graph data to use for caching key (optional)
        """
        if self.client is None:
            raise Exception("OpenAI client not available. Cannot generate embeddings.")

        progress_manager.update_progress(
            f"Generating embeddings for {len(self.documents)} documents..."
        )

        try:
            for i, doc in enumerate(self.documents):
                try:
                    response = self.client.embeddings.create(model=self.embedding_model, input=doc)
                    embedding = response.data[0].embedding
                    self.embeddings.append(np.array(embedding, dtype=np.float32))

                    if (i + 1) % 10 == 0:
                        print(f"  Generated {i + 1}/{len(self.documents)} embeddings")

                except KeyboardInterrupt:
                    print("\\n")
                    print(f"Embedding generation interrupted by user at document {i + 1}")
                    print(f"Generated {len(self.embeddings)} embeddings before interruption")
                    raise
                except Exception as e:
                    print(f"Warning: Could not generate embedding for document {i + 1}: {e}")
                    continue

            print(f"Generated {len(self.embeddings)} embeddings")

            # Save to cache if available and KG data provided
            if self.embedding_cache and kg_data and len(self.embeddings) == len(self.documents):
                try:
                    self.embedding_cache.save_embeddings_to_cache(
                        kg_data, self.documents, self.embeddings
                    )
                    print("✓ Embeddings saved to cache for future use")
                except Exception as e:
                    print(f"⚠️  Failed to save embeddings to cache: {e}")

        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"Error in embedding generation: {e}")
            raise

    @staticmethod
    def cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            Cosine similarity score between -1 and 1
        """
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot_product / (norm1 * norm2)

    def retrieve_documents(
        self, query: str, top_k: int = 3, verbose: bool = False
    ) -> tuple[list[str], list[float]]:
        """Retrieve the most relevant documents for a query

        Args:
            query: The search query
            top_k: Number of documents to retrieve
            verbose: Whether to display detailed retrieval information

        Returns:
            Tuple of (retrieved_documents, similarity_scores)
        """
        if self.client is None:
            raise Exception("OpenAI client not available. Cannot generate query embedding.")

        if not self.embeddings:
            raise Exception("No document embeddings available. Call generate_embeddings() first.")

        # Generate embedding for the query
        query_response = self.client.embeddings.create(model=self.embedding_model, input=query)
        query_embedding = np.array(query_response.data[0].embedding, dtype=np.float32)

        # Calculate similarities with all documents
        similarities = []
        for doc_embedding in self.embeddings:
            similarity = self.cosine_similarity(query_embedding, doc_embedding)
            similarities.append(similarity)

        # Get top-k most similar documents
        top_indices = np.argsort(similarities)[-top_k:][::-1]

        retrieved_docs = [self.documents[i] for i in top_indices]
        retrieved_similarities = [similarities[i] for i in top_indices]

        # Display retrieval information if verbose
        if verbose:
            print("🔍 Vector similarity search completed:")
            print(f"   ✓ Generated query embedding using {self.embedding_model}")
            print(f"   ✓ Computed similarity against {len(self.documents)} documents")
            print(f"   ✓ Retrieved top {len(retrieved_docs)} most relevant documents:")
            for i, (doc, sim) in enumerate(
                zip(retrieved_docs, retrieved_similarities, strict=False)
            ):
                doc_preview = (
                    doc[:100].replace("\n", " ") + "..."
                    if len(doc) > 100
                    else doc.replace("\n", " ")
                )
                print(f"      {i + 1}. Similarity: {sim:.4f} - {doc_preview}")

        return retrieved_docs, retrieved_similarities

    def generate_response(
        self,
        query: str,
        context_docs: list[str],
        sbom_context: str = "",
        stream: bool = False,
    ) -> str:
        """Generate a response using the retrieved context

        Args:
            query: The user's question
            context_docs: Retrieved documents to use as context
            sbom_context: SBOM component inventory context
            stream: Whether to stream the response

        Returns:
            Generated response
        """
        if self.client is None:
            raise Exception("OpenAI client not available. Cannot generate response.")

        # Combine retrieved knowledge graph documents
        kg_context = "\\n\\n".join(context_docs)

        # Get prompts from centralized management
        system_prompt = get_rag_system_prompt()
        user_prompt = get_rag_user_prompt(sbom_context, kg_context, query)

        # Generate response using OpenAI
        if stream:
            try:
                completion_params = {
                    "model": self.chat_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": True,
                }

                # Some models like o3-mini don't support certain parameters
                if not self.chat_model.startswith("o3"):
                    completion_params["temperature"] = 0.7
                    completion_params["max_tokens"] = 1000

                response = self.client.chat.completions.create(**completion_params)

                # Enhanced streaming with better o3-mini compatibility
                return stream_openai_response(response, "🤖", enable_streaming=True)

            except Exception as e:
                # Fallback to non-streaming if streaming fails
                print(
                    f"⚠️  Streaming failed with {self.chat_model}, falling back to non-streaming: {str(e)[:100]}..."
                )
                stream = False

        # Non-streaming response (also used as fallback)
        if not stream:
            try:
                completion_params = {
                    "model": self.chat_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                }

                # Some models like o3-mini don't support certain parameters
                if not self.chat_model.startswith("o3"):
                    completion_params["temperature"] = 0.7
                    completion_params["max_tokens"] = 1000

                response = self.client.chat.completions.create(**completion_params)
                return response.choices[0].message.content or "No response generated."
            except Exception as e:
                return f"Error generating response with {self.chat_model}: {str(e)}"

    def load_knowledge_graph(self, graph_data: dict[str, Any]):
        """Load a knowledge graph into the RAG system and create embeddings for retrieval.

        Args:
            graph_data: Dictionary containing 'nodes' and 'edges' of the knowledge graph
        """
        self.kg_nodes = {node["id"]: node for node in graph_data.get("nodes", [])}
        self.kg_edges = graph_data.get("edges", [])

        # Build node type indices for faster lookups
        self.kg_nodes_by_type = defaultdict(dict)
        for node_id, node in self.kg_nodes.items():
            node_type = node.get("type", "unknown")
            self.kg_nodes_by_type[node_type][node_id] = node

        print(
            f"RAG: Loaded knowledge graph with {len(self.kg_nodes)} nodes and {len(self.kg_edges)} edges."
        )
        print(f"Node types: {list(self.kg_nodes_by_type.keys())}")

        # Try to load from cache first
        if self.embedding_cache:
            cached_data = self.embedding_cache.get_cached_embeddings(graph_data)
            if cached_data is not None:
                self.documents, self.embeddings = cached_data
                print(
                    f"🚀 Loaded {len(self.documents)} cached embeddings (saved ~30s generation time)"
                )
                return

        # Create structured documents from KG data for embedding-based retrieval
        kg_documents = self._create_kg_documents()
        self.add_documents(kg_documents)
        progress_manager.update_progress(
            f"RAG: Created {len(kg_documents)} knowledge graph documents for embedding"
        )

    def _create_kg_documents(self) -> list[str]:
        """Create structured documents from knowledge graph data for embedding-based retrieval."""
        documents = []

        # Debug: Print node type breakdown
        for node_type, nodes in self.kg_nodes_by_type.items():
            print(f"  - {node_type}: {len(nodes)} nodes")

        # Group related information for better retrieval
        # Document 1: CVE vulnerability details
        cve_docs = []
        for node_id, node in self.kg_nodes_by_type.get("CVE", {}).items():
            cve_doc = f"CVE Vulnerability: {node_id}\n"
            cve_doc += f"Description: {node.get('description', 'No description available')}\n"

            # Add CVSS score if available
            if node.get("cvss_score"):
                cve_doc += f"CVSS Score: {node.get('cvss_score')} ({node.get('cvss_severity', 'Unknown')} severity)\n"

            # Find related CWEs and CAPECs
            related_cwes = []
            related_capecs = []

            for edge in self.kg_edges:
                if edge.get("source_id") == node_id and edge.get("type") == "HAS_CWE":
                    cwe_id = edge.get("target_id", "")
                    if cwe_id in self.kg_nodes:
                        cwe_node = self.kg_nodes[cwe_id]
                        related_cwes.append(f"{cwe_id}: {cwe_node.get('name', 'Unknown')}")

                        # Find CAPECs for this CWE
                        for cwe_edge in self.kg_edges:
                            if (
                                cwe_edge.get("source_id") == cwe_id
                                and cwe_edge.get("type") == "EXPLOITS_CWE"
                            ):
                                capec_id = cwe_edge.get("target_id", "")
                                if capec_id in self.kg_nodes:
                                    capec_node = self.kg_nodes[capec_id]
                                    related_capecs.append(
                                        f"{capec_id}: {capec_node.get('name', 'Unknown')}"
                                    )

            if related_cwes:
                cve_doc += f"Related Weaknesses (CWE): {'; '.join(related_cwes)}\n"
            if related_capecs:
                cve_doc += f"Attack Patterns (CAPEC): {'; '.join(related_capecs)}\n"

            # Find affected components
            affected_components = []
            for edge in self.kg_edges:
                if edge.get("target_id") == node_id and edge.get("type") == "HAS_VULNERABILITY":
                    comp_id = edge.get("source_id", "")
                    if comp_id in self.kg_nodes:
                        comp_node = self.kg_nodes[comp_id]
                        comp_name = comp_node.get("name", comp_id)
                        comp_version = comp_node.get("version", "unknown")
                        affected_components.append(f"{comp_name} v{comp_version}")

            if affected_components:
                cve_doc += f"Affected Components: {'; '.join(affected_components)}\n"

            cve_docs.append(cve_doc)

        # Combine CVE documents into chunks for better retrieval
        chunk_size = 3  # Smaller chunks for better granularity
        cve_chunks_created = 0
        for i in range(0, len(cve_docs), chunk_size):
            chunk = cve_docs[i : i + chunk_size]
            combined_doc = "\n\n".join(chunk)
            documents.append(combined_doc)
            cve_chunks_created += 1
        progress_manager.update_progress(
            f"  → Created {cve_chunks_created} CVE document chunks from {len(cve_docs)} individual CVEs"
        )

        # Document 2: CWE weakness classifications
        cwe_docs = []
        for node_id, node in self.kg_nodes_by_type.get("CWE", {}).items():
            cwe_doc = f"Weakness Classification: {node_id}\n"
            cwe_doc += f"Name: {node.get('name', 'Unknown')}\n"
            cwe_doc += f"Description: {node.get('description', 'No description available')}\n"

            # Find related CVEs
            related_cves = []
            for edge in self.kg_edges:
                if edge.get("target_id") == node_id and edge.get("type") == "HAS_CWE":
                    cve_id = edge.get("source_id", "")
                    if cve_id in self.kg_nodes:
                        related_cves.append(cve_id)

            if related_cves:
                cwe_doc += f"Related CVEs: {', '.join(related_cves[:10])}\n"  # Limit to avoid token overflow

            cwe_docs.append(cwe_doc)

        # Combine CWE documents
        cwe_chunks_created = 0
        for i in range(0, len(cwe_docs), chunk_size):
            chunk = cwe_docs[i : i + chunk_size]
            combined_doc = "\n\n".join(chunk)
            documents.append(combined_doc)
            cwe_chunks_created += 1
        progress_manager.update_progress(
            f"  → Created {cwe_chunks_created} CWE document chunks from {len(cwe_docs)} individual CWEs"
        )

        # Document 3: CAPEC attack patterns
        capec_docs = []
        for node_id, node in self.kg_nodes_by_type.get("CAPEC", {}).items():
            capec_doc = f"Attack Pattern: {node_id}\n"
            capec_doc += f"Name: {node.get('name', 'Unknown')}\n"
            capec_doc += f"Description: {node.get('description', 'No description available')}\n"

            # Find related CWEs
            related_cwes = []
            for edge in self.kg_edges:
                if edge.get("source_id") == node_id and edge.get("type") == "EXPLOITS_CWE":
                    cwe_id = edge.get("target_id", "")
                    if cwe_id in self.kg_nodes:
                        cwe_node = self.kg_nodes[cwe_id]
                        related_cwes.append(f"{cwe_id}: {cwe_node.get('name', 'Unknown')}")

            if related_cwes:
                capec_doc += f"Exploits Weaknesses: {'; '.join(related_cwes[:5])}\n"

            capec_docs.append(capec_doc)

        # Combine CAPEC documents
        capec_chunks_created = 0
        for i in range(0, len(capec_docs), chunk_size):
            chunk = capec_docs[i : i + chunk_size]
            combined_doc = "\n\n".join(chunk)
            documents.append(combined_doc)
            capec_chunks_created += 1
        progress_manager.update_progress(
            f"  → Created {capec_chunks_created} CAPEC document chunks from {len(capec_docs)} individual CAPECs"
        )

        # Document 4: Component dependency relationships
        component_docs = []
        for node_id, node in self.kg_nodes_by_type.get("Component", {}).items():
            comp_doc = f"Component: {node.get('name', node_id)}\n"
            comp_doc += f"Type: {node.get('component_type', 'library')}\n"
            comp_doc += f"Ecosystem: {node.get('ecosystem', 'unknown')}\n"

            if node.get("purl_base"):
                comp_doc += f"Package URL: {node.get('purl_base')}\n"

            # Find dependencies (base component level)
            dependencies = []
            for edge in self.kg_edges:
                if edge.get("source_id") == node_id and edge.get("type") == "DEPENDS_ON":
                    dep_id = edge.get("target_id", "")
                    if dep_id in self.kg_nodes:
                        dep_node = self.kg_nodes[dep_id]
                        dependencies.append(f"{dep_node.get('name', dep_id)}")

            if dependencies:
                comp_doc += (
                    f"Dependencies: {'; '.join(dependencies[:10])}\n"  # Limit to avoid overflow
                )

            component_docs.append(comp_doc)

        # Combine component documents
        component_chunks_created = 0
        for i in range(0, len(component_docs), chunk_size):
            chunk = component_docs[i : i + chunk_size]
            combined_doc = "\n\n".join(chunk)
            documents.append(combined_doc)
            component_chunks_created += 1
        progress_manager.update_progress(
            f"  → Created {component_chunks_created} Component document chunks from {len(component_docs)} individual Components"
        )

        # Document 5: Version-specific vulnerability information
        version_docs = []
        for node_id, node in self.kg_nodes_by_type.get("Version", {}).items():
            version_doc = f"Component Version: {node_id}\n"
            version_doc += f"Version: {node.get('version', 'unknown')}\n"
            version_doc += f"Component ID: {node.get('component_id', 'unknown')}\n"

            if node.get("purl"):
                version_doc += f"Package URL: {node.get('purl')}\n"

            # Vulnerability status
            is_vulnerable = node.get("is_vulnerable", False)
            vuln_count = node.get("vulnerability_count", 0)
            max_cvss = node.get("max_cvss_score", 0)

            version_doc += f"Vulnerable: {is_vulnerable}\n"
            if is_vulnerable:
                version_doc += f"Vulnerability Count: {vuln_count}\n"
                version_doc += f"Max CVSS Score: {max_cvss}\n"

            # Find specific vulnerabilities via edges
            vulnerabilities = []
            for edge in self.kg_edges:
                if edge.get("source_id") == node_id and edge.get("type") == "HAS_VULNERABILITY":
                    vuln_id = edge.get("target_id", "")
                    if vuln_id in self.kg_nodes:
                        vuln_node = self.kg_nodes[vuln_id]
                        cvss_score = vuln_node.get("cvss_score", "Unknown")
                        severity = vuln_node.get("cvss_severity", "Unknown")
                        vulnerabilities.append(
                            f"{vuln_id} (CVSS: {cvss_score}, Severity: {severity})"
                        )

            if vulnerabilities:
                version_doc += f"Specific Vulnerabilities: {'; '.join(vulnerabilities[:10])}\n"  # Limit to avoid overflow

            version_docs.append(version_doc)

        # Combine version documents
        version_chunks_created = 0
        for i in range(0, len(version_docs), chunk_size):
            chunk = version_docs[i : i + chunk_size]
            combined_doc = "\n\n".join(chunk)
            documents.append(combined_doc)
            version_chunks_created += 1
        progress_manager.update_progress(
            f"  → Created {version_chunks_created} Version document chunks from {len(version_docs)} individual Versions"
        )

        # Summary
        total_individual_items = (
            len(cve_docs)
            + len(cwe_docs)
            + len(capec_docs)
            + len(component_docs)
            + len(version_docs)
        )
        total_chunks = (
            cve_chunks_created
            + cwe_chunks_created
            + capec_chunks_created
            + component_chunks_created
            + version_chunks_created
        )
        progress_manager.update_progress(
            f"  → Total: {total_chunks} document chunks from {total_individual_items} individual security items"
        )

        return documents

    def query(
        self,
        question: str,
        top_k: int = 3,
        output_file: str | None = None,
        sbom_context: str = "",
        stream: bool = False,
        verbose: bool = False,
    ) -> dict:
        """Complete RAG pipeline: retrieve relevant docs and generate response

        Args:
            question: The user's question
            top_k: Number of documents to retrieve for context
            output_file: Optional path to markdown file for streaming output
            sbom_context: SBOM component inventory context
            stream: Whether to stream the response
            verbose: Whether to display detailed retrieval information

        Returns:
            Dictionary containing question, answer, retrieved documents, and similarities
        """
        if not self.documents:
            return {
                "question": question,
                "answer": "No documents available. Please add documents first.",
                "retrieved_documents": [],
                "similarities": [],
            }

        try:
            # Retrieve relevant documents
            retrieved_docs, similarities = self.retrieve_documents(question, top_k, verbose=verbose)

            # Generate response using both SBOM context and retrieved knowledge
            answer = self.generate_response(question, retrieved_docs, sbom_context, stream=stream)

            result = {
                "question": question,
                "answer": answer,
                "retrieved_documents": retrieved_docs,
                "similarities": similarities,
            }

            # Save to markdown file if specified
            if output_file:
                try:
                    output_dir = os.path.dirname(output_file)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)

                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write("# Security Analysis\\n\\n")
                        f.write(f"**Query:** {question}\\n\\n")
                        f.write(
                            f"**Generated:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n\\n"
                        )
                        f.write("## Analysis\\n\\n")
                        f.write(answer)
                        f.write("\\n\\n## Retrieved Context\\n\\n")
                        for i, doc in enumerate(retrieved_docs):
                            f.write(
                                f"### Document {i + 1} (Similarity: {similarities[i]:.3f})\\n\\n"
                            )
                            f.write(doc)
                            f.write("\\n\\n")

                    print(f"Results saved to: {output_file}")
                except Exception as e:
                    print(f"Warning: Could not save to markdown file {output_file}: {e}")

            return result

        except Exception as e:
            print(f"Error in RAG query: {e}")
            return {
                "question": question,
                "answer": f"Sorry, I encountered an error while processing your question: {e}",
                "retrieved_documents": [],
                "similarities": [],
            }
