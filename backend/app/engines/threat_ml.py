import os
import re
import logging
from typing import Dict, Any, List, Optional
from app.core.evidence import Evidence

logger = logging.getLogger("tracemail.engines.threat_ml")

class DistilBERTThreatClassifier:
    """
    Singleton Pretrained Hugging Face DistilBERT Phishing Classifier.
    Model is loaded ONCE into memory at startup and reused for CPU-safe inference.
    Fails gracefully if offline or unconfigured, delegating to heuristic content engine.
    
    TraceMail Extension:
    - Pretrained contextual transformer embeddings (replaces historical TF-IDF/KNN from Cidon et al. 2019).
    """
    _instance: Optional['DistilBERTThreatClassifier'] = None
    _pipeline = None
    _is_loaded = False
    _load_error: Optional[str] = None
    
    PREFERRED_MODEL_NAME = "spotproject/spot-distilbert-phishing"

    @classmethod
    def get_instance(cls) -> 'DistilBERTThreatClassifier':
        if cls._instance is None:
            cls._instance = DistilBERTThreatClassifier()
        return cls._instance

    def __init__(self):
        self._load_classifier()

    def _load_classifier(self):
        if DistilBERTThreatClassifier._is_loaded:
            return

        model_name = os.getenv("DISTILBERT_MODEL_NAME", self.PREFERRED_MODEL_NAME)

        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
            
            # 1. Try loading from local Hugging Face cache first
            try:
                tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
                model = AutoModelForSequenceClassification.from_pretrained(model_name, local_files_only=True)
                DistilBERTThreatClassifier._pipeline = pipeline(
                    "text-classification",
                    model=model,
                    tokenizer=tokenizer,
                    device=-1, # CPU execution
                    top_k=None,
                    truncation=True,
                    max_length=512
                )
                DistilBERTThreatClassifier._is_loaded = True
                DistilBERTThreatClassifier._load_error = None
                logger.info(f"Loaded cached DistilBERT model '{model_name}'.")
                return
            except Exception:
                pass

            # 2. If online download is explicitly allowed
            if os.getenv("ENABLE_DISTILBERT_DOWNLOAD", "false").lower() == "true":
                try:
                    tokenizer = AutoTokenizer.from_pretrained(model_name)
                    model = AutoModelForSequenceClassification.from_pretrained(model_name)
                    DistilBERTThreatClassifier._pipeline = pipeline(
                        "text-classification",
                        model=model,
                        tokenizer=tokenizer,
                        device=-1,
                        top_k=None,
                        truncation=True,
                        max_length=512
                    )
                    DistilBERTThreatClassifier._is_loaded = True
                    DistilBERTThreatClassifier._load_error = None
                    logger.info(f"Successfully loaded DistilBERT model '{model_name}'.")
                    return
                except Exception as dl_err:
                    DistilBERTThreatClassifier._load_error = str(dl_err)
                    logger.info(f"DistilBERT online download skipped: {dl_err}")

            DistilBERTThreatClassifier._is_loaded = False
            DistilBERTThreatClassifier._load_error = "Model not cached locally; operating in heuristic fallback mode."

        except ImportError as ie:
            DistilBERTThreatClassifier._is_loaded = False
            DistilBERTThreatClassifier._load_error = f"Transformers/Torch not installed: {ie}"
        except Exception as e:
            DistilBERTThreatClassifier._is_loaded = False
            DistilBERTThreatClassifier._load_error = str(e)
            logger.info(f"DistilBERT initialization notice: {e}")

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Runs inference. If DistilBERT is unavailable, evaluates content heuristics smoothly.
        """
        sample_text = (text[:2000] if text else "").strip()
        if not sample_text:
            return {
                "status": "LOADED" if DistilBERTThreatClassifier._is_loaded else "HEURISTIC_FALLBACK",
                "phishing_probability": 0.0,
                "confidence": 0.90,
                "model": self.PREFERRED_MODEL_NAME if DistilBERTThreatClassifier._is_loaded else "HeuristicEngine"
            }

        if DistilBERTThreatClassifier._is_loaded and DistilBERTThreatClassifier._pipeline:
            try:
                outputs = DistilBERTThreatClassifier._pipeline(sample_text)
                if outputs and isinstance(outputs[0], list):
                    scores = outputs[0]
                elif outputs and isinstance(outputs, list):
                    scores = outputs
                else:
                    scores = []

                phishing_prob = 0.0
                confidence = 0.5

                for item in scores:
                    lbl = str(item.get("label", "")).upper()
                    score = float(item.get("score", 0.0))
                    if lbl in ["LABEL_1", "PHISHING", "SPAM", "MALICIOUS", "THREAT", "1"]:
                        phishing_prob = score
                        confidence = max(confidence, score)
                    elif lbl in ["LABEL_0", "HAM", "LEGITIMATE", "SAFE", "0"]:
                        if phishing_prob == 0.0:
                            phishing_prob = 1.0 - score
                        confidence = max(confidence, score)

                return {
                    "status": "LOADED",
                    "phishing_probability": round(phishing_prob, 4),
                    "confidence": round(confidence, 3),
                    "model": self.PREFERRED_MODEL_NAME,
                    "raw_scores": scores
                }
            except Exception as e:
                logger.warning(f"DistilBERT inference exception: {e}")

        # Heuristic fallback probability approximation
        phish_keywords = [
            r'password expire', r'verify your account', r'login to confirm', r'mailbox storage full',
            r'update payment details', r'wire transfer', r'bank account routing', r'click here to login',
            r'gift card', r'confidential transaction', r'immediate wire', r'w-?2 form'
        ]
        hits = sum(1 for p in phish_keywords if re.search(p, sample_text, re.IGNORECASE))
        approx_prob = min(0.95, hits * 0.35) if hits > 0 else 0.05
        
        return {
            "status": "HEURISTIC_FALLBACK",
            "phishing_probability": round(approx_prob, 2),
            "confidence": 0.85,
            "model": "DistilBERT-Heuristic-Fallback",
            "note": DistilBERTThreatClassifier._load_error
        }


class ContentAnalysisEngine:
    """
    Explainable Behavioral Content & Transformer NLP Engine:
    
    Combines Transformer contextual scoring (TraceMail extension) with research-informed
    BEC semantic cue categories (Cidon et al. 2019 Table 1, Table 4).
    """

    PATTERNS = {
        "PAYMENT_DIVERSION": {
            "group": "payment_diversion",
            "independence_group": "financial_lure",
            "severity": 0.90,
            "research_provenance": "CIDON_2019_TEXT_CLASSIFIER_CONCEPT",
            "patterns": [
                r'new bank account', r'update payment details', r'wire transfer instructions',
                r'updated routing number', r'new beneficiary', r'invoice payment due today',
                r'direct deposit change', r'change bank account', r'remittance instructions',
                r'update direct deposit', r'wire the funds', r'send a wire', r'wire transfer asap'
            ],
            "description": "Payment or banking routing modification request detected"
        },
        "RAPPORT_AVAILABILITY": {
            "group": "rapport_building",
            "independence_group": "social_engineering_intro",
            "severity": 0.60,
            "research_provenance": "CIDON_2019_TEXT_CLASSIFIER_CONCEPT",
            "patterns": [
                r'are you around', r'are you available', r'at your desk', r'got moment',
                r'quick favor', r'need you for a quick task', r'are you in the office'
            ],
            "description": "Rapport-building availability check typical of multi-stage BEC attacks"
        },
        "PII_THEFT_REQUEST": {
            "group": "pii_request",
            "independence_group": "sensitive_data_request",
            "severity": 0.88,
            "research_provenance": "CIDON_2019_TEXT_CLASSIFIER_CONCEPT",
            "patterns": [
                r'w-?2 form', r'w2s for all employees', r'social security numbers',
                r'employee tax forms', r'send employee records', r'w-?2s'
            ],
            "description": "Request for sensitive tax forms or Personally Identifiable Information (PII)"
        },
        "EXECUTIVE_PRESSURE": {
            "group": "executive_impersonation",
            "independence_group": "authority_pressure",
            "severity": 0.80,
            "research_provenance": "CIDON_2019_TEXT_CLASSIFIER_CONCEPT",
            "patterns": [
                r'confidential transaction', r'in a meeting right now', r'cannot take calls',
                r'handle this discreetly', r'need you to process', r'strictly confidential',
                r'sent from my iphone', r'keep this private'
            ],
            "description": "Executive authority pressure and urgency cues detected"
        },
        "CREDENTIAL_REQUEST": {
            "group": "credential_request",
            "independence_group": "credential_lure",
            "severity": 0.85,
            "research_provenance": "TRACEMAIL_TRANSFORMER_EXTENSION",
            "patterns": [
                r'password expire', r'verify your account', r'login to confirm',
                r'mailbox storage full', r'security notification', r'click here to login',
                r'session expired', r'update credentials', r'identity verification required',
                r're-authenticate', r'account suspended'
            ],
            "description": "Credential harvesting / password verification lure detected"
        },
        "URGENCY_PRESSURE": {
            "group": "urgency_pressure",
            "independence_group": "urgency_cues",
            "severity": 0.65,
            "research_provenance": "CIDON_2019_TEXT_CLASSIFIER_CONCEPT",
            "patterns": [
                r'urgent', r'immediately', r'act now', r'within 24 hours', r'within 2 hours',
                r'immediate response', r'do this today', r'by end of day', r'critical notice', r'asap'
            ],
            "description": "Urgency pressure inducing rapid unverified action"
        },
        "SECRECY_REQUEST": {
            "group": "secrecy_request",
            "independence_group": "channel_bypass",
            "severity": 0.75,
            "research_provenance": "CIDON_2019_TEXT_CLASSIFIER_CONCEPT",
            "patterns": [
                r'do not call', r'do not discuss with anyone', r'keep this between us',
                r'handle this confidentially', r'private matter', r'off the record'
            ],
            "description": "Explicit request to bypass standard communication or verification channels"
        },
        "GIFT_CARD_FRAUD": {
            "group": "financial_request",
            "independence_group": "gift_card_lure",
            "severity": 0.90,
            "research_provenance": "TRACEMAIL_TRANSFORMER_EXTENSION",
            "patterns": [
                r'apple gift card', r'google play card', r'steam gift card',
                r'purchase some gift cards', r'scratch the back', r'send the codes'
            ],
            "description": "Executive gift card purchase solicitation scam"
        }
    }

    @classmethod
    def evaluate(cls, full_text: str, email_context: Dict[str, Any]) -> Dict[str, Any]:
        evidence_list: List[Evidence] = []
        detected_behaviors: List[str] = []

        # 1. DistilBERT Phishing Classifier
        classifier = DistilBERTThreatClassifier.get_instance()
        distilbert_result = classifier.predict(full_text)
        phishing_prob = distilbert_result.get("phishing_probability", 0.0)
        distilbert_conf = distilbert_result.get("confidence", 0.85)

        if phishing_prob >= 0.50:
            evidence_list.append(Evidence(
                engine="CONTENT_NLP",
                type="DISTILBERT_PHISHING_PROBABILITY",
                semantic_group="nlp_classification",
                independence_group="transformer_nlp",
                value=phishing_prob,
                severity=round(phishing_prob, 2),
                confidence=distilbert_conf,
                reliability=0.88,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"DistilBERT deep NLP model flagged content with {round(phishing_prob * 100, 1)}% phishing probability",
                source=distilbert_result.get("model", "DistilBERT"),
                research_provenance="TRACEMAIL_TRANSFORMER_EXTENSION"
            ))
            detected_behaviors.append("DISTILBERT_PHISHING_FLAG")
        elif phishing_prob < 0.20:
            evidence_list.append(Evidence(
                engine="CONTENT_NLP",
                type="DISTILBERT_BENIGN_CONTENT",
                semantic_group="nlp_classification",
                independence_group="transformer_nlp",
                value=phishing_prob,
                severity=round(1.0 - phishing_prob, 2),
                confidence=distilbert_conf,
                reliability=0.85,
                freshness=1.0,
                direction="MITIGATING",
                description=f"DistilBERT deep NLP evaluated message content as typical benign communication ({round((1.0 - phishing_prob) * 100, 1)}% legitimate)",
                source=distilbert_result.get("model", "DistilBERT"),
                research_provenance="TRACEMAIL_TRANSFORMER_EXTENSION"
            ))

        # 2. Heuristic Semantic Cues
        for behavior_key, conf in cls.PATTERNS.items():
            matched = [p for p in conf["patterns"] if re.search(p, full_text, re.IGNORECASE)]
            if matched:
                detected_behaviors.append(behavior_key)
                evidence_list.append(Evidence(
                    engine="CONTENT_NLP",
                    type=behavior_key,
                    semantic_group=conf["group"],
                    independence_group=conf.get("independence_group"),
                    value=matched[0],
                    severity=conf["severity"],
                    confidence=0.92,
                    reliability=0.90,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"{conf['description']} (Pattern: '{matched[0]}')",
                    source="CONTENT_HEURISTICS",
                    research_provenance=conf.get("research_provenance", "CIDON_2019_TEXT_CLASSIFIER_CONCEPT")
                ))

        return {
            "distilbert": distilbert_result,
            "detected_behaviors": detected_behaviors,
            "evidence": evidence_list
        }


class HybridThreatEngine:
    """
    Unified Content NLP Interface facade.
    """
    @classmethod
    def get_model_status(cls) -> str:
        if DistilBERTThreatClassifier._is_loaded:
            return "loaded"
        elif DistilBERTThreatClassifier._load_error:
            return "heuristic_fallback"
        return "ready"

    def evaluate(self, email_context: Dict[str, Any]) -> Dict[str, Any]:
        body_text = email_context.get("body_text", "")
        subject = email_context.get("subject", "")
        combined_text = f"{subject}\n{body_text}".strip()
        
        res = ContentAnalysisEngine.evaluate(combined_text, email_context)
        return {
            "model_version": "TraceMail-Transformer-v2.0",
            "distilbert": res["distilbert"],
            "detected_behaviors": res["detected_behaviors"],
            "evidence": res["evidence"]
        }
