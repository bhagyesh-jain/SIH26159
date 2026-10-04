import math
import random
import json
import datetime
from typing import List, Dict, Tuple, Optional, Any
from sqlalchemy.orm import Session as DBSession

from backend.app.models.database import (
    Session as SessionModel,
    SecurityEvent,
    Finding,
    AnomalyResult,
)
from backend.app.schemas.anomaly import (
    AnomalyResultItem,
    AnomalySummary,
    InvestigationAnomaliesResponse,
)
from backend.app.services.ml_feature_service import (
    FEATURE_NAMES,
    FEATURE_DESCRIPTIONS,
    SessionFeatureVector,
    extract_session_features,
)


MODEL_VERSION = "isolation-forest-v1"
FEATURE_VERSION = "features-v1"


def bst_avg_path_length(n: float) -> float:
    """Calculates average path length of unsuccessful search in a BST c(n)."""
    if n <= 1.0:
        return 0.0
    if n == 2.0:
        return 1.0
    # Euler-Mascheroni constant = 0.5772156649
    return 2.0 * (math.log(n - 1.0) + 0.5772156649) - (2.0 * (n - 1.0) / n)


class IsolationTreeNode:
    def __init__(
        self,
        feature_idx: Optional[int] = None,
        split_val: Optional[float] = None,
        left: Optional["IsolationTreeNode"] = None,
        right: Optional["IsolationTreeNode"] = None,
        size: int = 0,
        is_leaf: bool = False,
    ):
        self.feature_idx = feature_idx
        self.split_val = split_val
        self.left = left
        self.right = right
        self.size = size
        self.is_leaf = is_leaf


class PurePythonIsolationForest:
    """
    100% Deterministic Pure-Python Isolation Forest engine.
    - Zero external C-extension/DLL dependencies (prevents OS AppLocker/AppControl blocks).
    - Reproducible random_state (RNG seed = 42).
    - Calculates average isolation depth E(h(x)) and normalizes against BST expectation c(n).
    """

    def __init__(self, n_estimators: int = 100, max_samples: int = 256, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.trees: List[IsolationTreeNode] = []
        self.n_train: int = 0

    def fit(self, X: List[List[float]]):
        self.n_train = len(X)
        if self.n_train == 0:
            return self

        rng = random.Random(self.random_state)
        n_samples = min(self.max_samples, self.n_train)
        max_depth = int(math.ceil(math.log2(max(n_samples, 2))))

        self.trees = []
        for _ in range(self.n_estimators):
            # Sample subset
            indices = rng.sample(range(self.n_train), n_samples)
            sub_X = [X[i] for i in indices]
            tree = self._build_tree(sub_X, 0, max_depth, rng)
            self.trees.append(tree)

        return self

    def _build_tree(
        self, sub_X: List[List[float]], current_depth: int, max_depth: int, rng: random.Random
    ) -> IsolationTreeNode:
        n = len(sub_X)
        if current_depth >= max_depth or n <= 1:
            return IsolationTreeNode(size=n, is_leaf=True)

        n_features = len(sub_X[0])
        # Find features with range > 0
        valid_features = []
        feature_ranges = {}
        for feat_idx in range(n_features):
            vals = [row[feat_idx] for row in sub_X]
            min_v, max_v = min(vals), max(vals)
            if max_v > min_v:
                valid_features.append(feat_idx)
                feature_ranges[feat_idx] = (min_v, max_v)

        if not valid_features:
            return IsolationTreeNode(size=n, is_leaf=True)

        chosen_feat = rng.choice(valid_features)
        min_v, max_v = feature_ranges[chosen_feat]
        split_val = rng.uniform(min_v, max_v)

        left_X = [row for row in sub_X if row[chosen_feat] < split_val]
        right_X = [row for row in sub_X if row[chosen_feat] >= split_val]

        if not left_X or not right_X:
            return IsolationTreeNode(size=n, is_leaf=True)

        left_child = self._build_tree(left_X, current_depth + 1, max_depth, rng)
        right_child = self._build_tree(right_X, current_depth + 1, max_depth, rng)

        return IsolationTreeNode(
            feature_idx=chosen_feat,
            split_val=split_val,
            left=left_child,
            right=right_child,
            size=n,
            is_leaf=False,
        )

    def _path_length(self, x: List[float], node: IsolationTreeNode, current_depth: int) -> float:
        if node.is_leaf or node.size <= 1:
            return current_depth + bst_avg_path_length(float(node.size))

        if x[node.feature_idx] < node.split_val:
            return self._path_length(x, node.left, current_depth + 1)
        else:
            return self._path_length(x, node.right, current_depth + 1)

    def compute_anomaly_score(self, x: List[float]) -> float:
        """
        Computes anomaly score s(x, n) in range [0.0, 1.0].
        Scores >= 0.65 represent high isolation risk (ANOMALY).
        """
        if not self.trees or self.n_train <= 1:
            return 0.5  # Neutral default score for single/empty dataset

        n_samples = float(min(self.max_samples, self.n_train))
        c_n = bst_avg_path_length(n_samples)

        if c_n == 0.0:
            return 0.5

        avg_path = sum([self._path_length(x, tree, 0) for tree in self.trees]) / len(self.trees)
        score = math.pow(2.0, -(avg_path / c_n))
        return max(0.0, min(1.0, score))


def generate_associated_features_and_explanation(
    vec: SessionFeatureVector,
    all_vectors: List[SessionFeatureVector],
    anomaly_score_int: int,
    anomaly_label: str,
) -> Tuple[List[str], str]:
    """
    Generates explainable associated features and deterministic natural language explanation.
    Calculates normalized feature deviation against baseline distribution without causal claims.
    """
    if not all_vectors:
        return [], "Session metrics evaluated against empty baseline."

    # Compute mean and standard deviation for each feature across investigation dataset
    deviations: List[Tuple[str, float, float]] = []  # (feature_name, normalized_dev, val)
    for feat_name in FEATURE_NAMES:
        vals = [v.features.get(feat_name, 0.0) for v in all_vectors]
        mean_v = sum(vals) / len(vals)
        variance = sum((x - mean_v) ** 2 for x in vals) / len(vals)
        std_v = math.sqrt(variance)

        curr_v = vec.features.get(feat_name, 0.0)
        norm_dev = abs(curr_v - mean_v) / (std_v + 1e-4) if std_v > 1e-6 else (1.0 if curr_v != mean_v else 0.0)
        deviations.append((feat_name, norm_dev, curr_v))

    # Sort features by highest normalized deviation
    deviations.sort(key=lambda item: item[1], reverse=True)

    # Filter top associated features where value is non-zero or notable
    associated_features: List[str] = []
    for feat_name, dev, val in deviations:
        if len(associated_features) >= 4:
            break
        if val > 0.0 or dev > 0.5:
            desc = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
            associated_features.append(desc)

    if not associated_features:
        associated_features = [FEATURE_DESCRIPTIONS["highest_risk_score"]]

    # Deterministic explanation construction
    explanations: List[str] = []
    f_map = vec.features

    if f_map.get("starttls_bypassed", 0.0) == 1.0:
        explanations.append("Session exhibited STARTTLS offered but unutilized cleartext transition.")
    if f_map.get("handshake_failed", 0.0) == 1.0:
        explanations.append("Session experienced TLS handshake negotiation failure.")
    if f_map.get("weak_rsa_observed", 0.0) == 1.0:
        explanations.append("Session selected legacy static RSA key exchange lacking forward secrecy.")
    if f_map.get("cert_alert_count", 0.0) > 0.0:
        explanations.append("Session observed TLS certificate validation alerts.")
    if f_map.get("tls_alert_count", 0.0) > 0.0 and f_map.get("cert_alert_count", 0.0) == 0.0:
        explanations.append("Session transmitted TLS warning or fatal alert records.")
    if f_map.get("highest_risk_score", 0.0) >= 50.0 and not explanations:
        explanations.append(f"Session associated with high risk findings (score: {int(f_map['highest_risk_score'])}).")

    if anomaly_label == "ANOMALY":
        lead = "Statistically anomalous session."
    elif anomaly_label == "ELEVATED":
        lead = "Session exhibits elevated deviation from baseline profile."
    else:
        lead = "Session metrics conform to normal protocol baseline characteristics."

    if explanations:
        body = " " + " ".join(explanations)
    else:
        top_descs = ", ".join(associated_features[:2])
        body = f" Anomaly is associated with unusual values for {top_descs}."

    explanation_text = (lead + body).strip()
    return associated_features, explanation_text


def compute_investigation_anomalies(
    db: DBSession, investigation_id: str
) -> InvestigationAnomaliesResponse:
    """
    Computes or retrieves ML anomaly detection results for an investigation.
    Deterministic, explainable, and fully integrated with existing persisted evidence.
    """
    # 1. Fetch sessions
    sessions = (
        db.query(SessionModel)
        .join(SessionModel.capture)
        .filter(SessionModel.capture.has(investigation_id=investigation_id))
        .all()
    )

    now_iso = datetime.datetime.utcnow().isoformat() + "Z"

    if not sessions:
        summary = AnomalySummary(
            total_sessions_analyzed=0,
            anomalous_sessions_count=0,
            elevated_sessions_count=0,
            normal_sessions_count=0,
            highest_anomaly_score=0,
            model_version=MODEL_VERSION,
            feature_version=FEATURE_VERSION,
        )
        return InvestigationAnomaliesResponse(
            investigation_id=investigation_id,
            generated_at=now_iso,
            model_version=MODEL_VERSION,
            feature_version=FEATURE_VERSION,
            summary=summary,
            results=[],
        )

    # 2. Extract feature vectors for all sessions
    vectors: List[SessionFeatureVector] = []
    session_map: Dict[str, SessionModel] = {s.id: s for s in sessions}

    for session in sessions:
        security_events = (
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session.id).all()
        )
        findings = db.query(Finding).filter(Finding.session_id == session.id).all()
        vec = extract_session_features(session, security_events, findings, investigation_id)
        vectors.append(vec)

    # 3. Fit Pure-Python Isolation Forest
    X = [vec.to_numeric_array() for vec in vectors]
    model = PurePythonIsolationForest(n_estimators=100, max_samples=256, random_state=42)
    model.fit(X)

    # 4. Generate anomaly results
    anomalous_count = 0
    elevated_count = 0
    normal_count = 0
    max_score = 0
    results: List[AnomalyResultItem] = []

    # Clear previous anomaly results for this investigation to maintain idempotency
    db.query(AnomalyResult).filter(AnomalyResult.investigation_id == investigation_id).delete()
    db.commit()

    db_records = []
    is_small_baseline = len(sessions) <= 2

    for vec in vectors:
        raw_score = model.compute_anomaly_score(vec.to_numeric_array())
        score_int = int(round(raw_score * 100.0))

        if score_int > max_score:
            max_score = score_int

        if score_int >= 65:
            label = "ANOMALY"
            is_anomalous = True
            anomalous_count += 1
            confidence_band = "LOW" if is_small_baseline else "HIGH"
        elif score_int >= 50:
            label = "ELEVATED"
            is_anomalous = True
            elevated_count += 1
            confidence_band = "LOW" if is_small_baseline else "MEDIUM"
        else:
            label = "NORMAL"
            is_anomalous = False
            normal_count += 1
            confidence_band = "LOW"

        assoc_features, explanation = generate_associated_features_and_explanation(
            vec, vectors, score_int, label
        )

        item = AnomalyResultItem(
            id=f"anom_{vec.session_id}",
            investigation_id=investigation_id,
            session_id=vec.session_id,
            tcp_stream=vec.tcp_stream,
            protocol=vec.protocol,
            src=vec.src,
            dst=vec.dst,
            src_port=vec.src_port,
            dst_port=vec.dst_port,
            model_version=MODEL_VERSION,
            feature_version=FEATURE_VERSION,
            anomaly_score=score_int,
            anomaly_label=label,
            is_anomalous=is_anomalous,
            confidence_band=confidence_band,
            evidence_state=vec.evidence_state,
            contributing_features=assoc_features,
            supporting_finding_ids=vec.supporting_finding_ids,
            supporting_event_ids=vec.supporting_event_ids,
            supporting_frame_numbers=vec.supporting_frame_numbers,
            explanation=explanation,
            created_at=now_iso,
        )
        results.append(item)

        # Persist to database
        record = AnomalyResult(
            id=item.id,
            investigation_id=investigation_id,
            session_id=vec.session_id,
            model_version=MODEL_VERSION,
            feature_version=FEATURE_VERSION,
            anomaly_score=score_int,
            anomaly_label=label,
            is_anomalous=1 if is_anomalous else 0,
            confidence_band=confidence_band,
            evidence_state=vec.evidence_state,
            contributing_features_json=json.dumps(assoc_features),
            supporting_finding_ids=json.dumps(vec.supporting_finding_ids),
            supporting_event_ids=json.dumps(vec.supporting_event_ids),
            supporting_frame_numbers=json.dumps(vec.supporting_frame_numbers),
            explanation=explanation,
        )
        db_records.append(record)

    db.add_all(db_records)
    db.commit()

    # Sort results by anomaly score descending
    results.sort(key=lambda r: (r.anomaly_score, r.tcp_stream), reverse=True)

    summary = AnomalySummary(
        total_sessions_analyzed=len(sessions),
        anomalous_sessions_count=anomalous_count,
        elevated_sessions_count=elevated_count,
        normal_sessions_count=normal_count,
        highest_anomaly_score=max_score,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
    )

    training_context = (
        "Statistical anomaly score relative to investigation model baseline (n <= 2 sessions; limited baseline volume). Scores represent relative feature observation and are not attack probabilities."
        if is_small_baseline
        else "Statistical anomaly score relative to investigation model baseline dataset. Scores represent relative statistical unusualness and are not attack probabilities."
    )

    return InvestigationAnomaliesResponse(
        investigation_id=investigation_id,
        generated_at=now_iso,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
        training_context=training_context,
        summary=summary,
        results=results,
    )
