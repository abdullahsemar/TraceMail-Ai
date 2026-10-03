"""
Research Baseline: TF-IDF + KNN Text Classifier
Reference: Asaf Cidon et al., "High Precision Detection of Business Email Compromise",
USENIX Security Symposium, 2019, Section 4.4.

NOTE: This is a NON-PRODUCTION experimental reference implementation provided for
comparative evaluation and research documentation. TraceMail's production engine
uses transformer-based contextual embeddings (DistilBERT) and behavioral fusion.
"""

import re
import math
from typing import List, Dict, Any, Tuple
from collections import Counter

class ResearchTFIDFTextClassifier:
    """
    Experimental baseline implementing Cidon et al. 2019 §4.4:
    - Text preprocessing: stripping salutations, footers, stopwords
    - TF-IDF unigram and bigram feature vector extraction
    - K-Nearest Neighbors (KNN) distance-based classification
    """

    STOPWORDS = {
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
        "any", "are", "as", "at", "be", "because", "been", "before", "being", "below",
        "between", "both", "but", "by", "could", "did", "do", "does", "doing", "down",
        "during", "each", "few", "for", "from", "further", "had", "has", "have", "having",
        "he", "her", "here", "hers", "herself", "him", "himself", "his", "how", "i",
        "if", "in", "into", "is", "it", "its", "itself", "me", "more", "most", "my",
        "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other",
        "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "she", "should",
        "so", "some", "such", "than", "that", "the", "their", "theirs", "them", "themselves",
        "then", "there", "these", "they", "this", "those", "through", "to", "too", "under",
        "until", "up", "very", "was", "we", "were", "what", "when", "where", "which",
        "while", "who", "whom", "why", "with", "would", "you", "your", "yours", "yourself",
        "yourselves"
    }

    # Reference top TF-IDF BEC phrases identified in Cidon et al. 2019 Table 4
    REFERENCE_BEC_PHRASES = [
        "got moment", "response", "moment need", "moment", "need",
        "need complete", "asap", "urgent response", "urgent", "complete task",
        "wire transfer", "payment request", "bank account", "w2 form", "direct deposit"
    ]

    def __init__(self, k: int = 5):
        self.k = k
        self.idf_dict: Dict[str, float] = {}
        self.training_vectors: List[Tuple[Dict[str, float], str]] = []

    def preprocess_text(self, text: str) -> List[str]:
        """
        Strips salutations, signatures, footers, numbers, and stopwords (Cidon et al. 2019 §4.4).
        """
        if not text:
            return []

        # Remove canned salutations and signatures
        t = re.sub(r'^(hi|hello|dear|hey)\s+[\w\s,]+', '', text, flags=re.IGNORECASE)
        t = re.sub(r'(best|regards|thanks|sincerely|cheers)[\w\s,.-]*$', '', t, flags=re.IGNORECASE)

        # Lowercase and clean non-alphanumeric
        tokens = re.findall(r'\b[a-z]{2,}\b', t.lower())
        filtered = [tok for tok in tokens if tok not in self.STOPWORDS]
        return filtered

    def extract_ngrams(self, tokens: List[str]) -> List[str]:
        """Extracts unigrams and bigrams."""
        unigrams = tokens
        bigrams = [f"{tokens[i]} {tokens[i+1]}" for i in range(len(tokens) - 1)]
        return unigrams + bigrams

    def compute_tf(self, ngrams: List[str]) -> Dict[str, float]:
        if not ngrams:
            return {}
        counts = Counter(ngrams)
        total = float(len(ngrams))
        return {gram: c / total for gram, c in counts.items()}

    def train(self, corpus: List[Tuple[str, str]]):
        """
        Trains TF-IDF dictionary and KNN index on labeled corpus: List[(text, label)].
        """
        num_docs = len(corpus)
        if num_docs == 0:
            return

        doc_ngrams = []
        df: Dict[str, int] = Counter()

        for text, _ in corpus:
            tokens = self.preprocess_text(text)
            ngrams = self.extract_ngrams(tokens)
            doc_ngrams.append(ngrams)
            unique_grams = set(ngrams)
            for g in unique_grams:
                df[g] += 1

        # Compute IDF
        self.idf_dict = {
            gram: math.log((1.0 + num_docs) / (1.0 + count)) + 1.0
            for gram, count in df.items()
        }

        # Build feature vectors
        self.training_vectors = []
        for i, (text, label) in enumerate(corpus):
            tf = self.compute_tf(doc_ngrams[i])
            tfidf = {g: tf[g] * self.idf_dict.get(g, 1.0) for g in tf}
            self.training_vectors.append((tfidf, label))

    def _cosine_similarity(self, vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        dot = sum(v * vec2.get(k, 0.0) for k, v in vec1.items())
        mag1 = math.sqrt(sum(v * v for v in vec1.values()))
        mag2 = math.sqrt(sum(v * v for v in vec2.values()))
        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Predicts label and probability using K-Nearest Neighbors.
        """
        tokens = self.preprocess_text(text)
        ngrams = self.extract_ngrams(tokens)
        tf = self.compute_tf(ngrams)
        query_tfidf = {g: tf[g] * self.idf_dict.get(g, 1.0) for g in tf if g in self.idf_dict}

        if not self.training_vectors:
            # Fallback to reference phrase matching if untargeted
            hits = [p for p in self.REFERENCE_BEC_PHRASES if p in text.lower()]
            prob = min(0.95, len(hits) * 0.30)
            return {
                "prediction": "BEC" if prob >= 0.5 else "LEGITIMATE",
                "probability": prob,
                "matched_reference_phrases": hits,
                "k_neighbors": 0,
                "note": "Research baseline reference evaluation"
            }

        # Compute similarity to all training vectors
        scored = []
        for train_vec, label in self.training_vectors:
            sim = self._cosine_similarity(query_tfidf, train_vec)
            scored.append((sim, label))

        scored.sort(key=lambda x: x[0], reverse=True)
        top_k = scored[:self.k]

        bec_votes = sum(1 for sim, lbl in top_k if lbl == "BEC")
        prob = bec_votes / float(len(top_k)) if top_k else 0.0

        return {
            "prediction": "BEC" if prob >= 0.5 else "LEGITIMATE",
            "probability": round(prob, 3),
            "top_k_similarities": [round(s, 3) for s, _ in top_k],
            "k": self.k
        }
