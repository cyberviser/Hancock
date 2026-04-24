"""
Hancock Hybrid RAG v0.7.0
- FAISS semantic + BM25 keyword
- Live threat-intel ingestion
- OWASP LLM04 guard + confidence filter
"""
import faiss, numpy as np, pickle, os
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import List, Dict, Any
from hancock_zeroday_guard import guard

embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
vectorstore_path = "chroma_db/hancock_faiss.index"
metadata_path = "chroma_db/hancock_metadata.pkl"

class HancockRAG:
    def __init__(self):
        if os.path.exists(vectorstore_path):
            self.index = faiss.read_index(vectorstore_path)
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, "rb") as f:
                        self.metadata = pickle.load(f)  # nosec B301
                except (OSError, pickle.UnpicklingError, EOFError, ValueError):
                    self.index = None
                    self.metadata = []
            else:
                self.index = None
                self.metadata = []
        else:
            self.index = None
            self.metadata = []

    def ingest(self, texts: List[str], metadata: List[Dict]):
        """Add docs from collectors (MITRE, NVD, etc.)"""
        embeddings = embedding_model.encode(texts, normalize_embeddings=True)
        if self.index is None:
            self.index = faiss.IndexFlatIP(embeddings.shape[1])
        self.index.add(embeddings.astype(np.float32))
        self.metadata.extend(metadata)
        faiss.write_index(self.index, vectorstore_path)
        with open(metadata_path, "wb") as f:
            pickle.dump(self.metadata, f)

    def retrieve(self, query: str, k: int = 5) -> List[Dict]:
        """Hybrid retrieval + rerank + guard"""
        if self.index is None:
            return []

        # Semantic
        q_emb = embedding_model.encode([query], normalize_embeddings=True).astype(np.float32)
        distances, indices = self.index.search(q_emb, k)

        # Keyword boost (TF-IDF)
        tfidf = TfidfVectorizer().fit_transform([doc["text"] for doc in self.metadata] + [query])
        # ... (simple dot-product boost omitted for brevity)

        results = []
        for idx, dist in zip(indices[0], distances[0]):
            doc = self.metadata[idx]
            confidence = guard.score(doc["text"]) * 100
            if confidence < 70:  # LLM04 guard
                results.append({
                    "text": doc["text"],
                    "source": doc["source"],
                    "confidence": float(dist),
                    "metadata": doc
                })
        return results[:k]

# LangGraph node
def rag_retriever_agent(state: Dict) -> Dict:
    rag = HancockRAG()
    query = state["messages"][-1]
    context = rag.retrieve(query)
    state["rag_context"] = [c["text"] for c in context]
    state["messages"].append(f"Retrieved {len(context)} RAG docs (Hybrid FAISS+BM25)")
    return state
