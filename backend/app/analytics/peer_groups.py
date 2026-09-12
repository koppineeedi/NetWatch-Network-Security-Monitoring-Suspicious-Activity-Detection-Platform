from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.analytics.models import BehaviorBaseline

class PeerGroupEngine:
    def evaluate_peer_deviation(
        self, db: Session, entity_id: str, feature_name: str, entity_type: str = "IP"
    ) -> Dict[str, Any]:
        """
        Compares an entity's feature baseline against peers of the same entity_type.
        Returns INSUFFICIENT_DATA if fewer than 3 peers exist.
        """
        # Fetch active baselines for all entities for this feature
        peer_baselines = db.query(BehaviorBaseline).filter(
            BehaviorBaseline.entity_type == entity_type,
            BehaviorBaseline.feature_name == feature_name,
            BehaviorBaseline.status == "ACTIVE"
        ).all()

        if len(peer_baselines) < 3:
            return {
                "status": "INSUFFICIENT_DATA",
                "message": "Insufficient peer group sample count for comparative analysis"
            }

        target_b = next((b for b in peer_baselines if b.entity_id == entity_id), None)
        if not target_b:
            return {
                "status": "INSUFFICIENT_DATA",
                "message": f"Entity '{entity_id}' has no baseline for feature '{feature_name}'"
            }

        peer_means = [b.mean_value for b in peer_baselines]
        peer_means.sort()
        
        peer_median = peer_means[len(peer_means) // 2]
        target_val = target_b.mean_value
        
        # Percentile rank among peers
        rank = sum(1 for x in peer_means if target_val >= x)
        percentile_rank = round((rank / len(peer_means)) * 100.0, 1)

        diff = target_val - peer_median
        diff_pct = round((diff / peer_median * 100.0) if peer_median > 0 else 0.0, 1)

        return {
            "status": "ACTIVE",
            "entity_id": entity_id,
            "feature_name": feature_name,
            "entity_mean": target_val,
            "peer_median": peer_median,
            "peer_count": len(peer_means),
            "percentile_rank": percentile_rank,
            "deviation_from_peer_median_pct": diff_pct,
            "explanation": f"Entity '{entity_id}' feature '{feature_name}' ({target_val}) is at the {percentile_rank}th percentile of its peer group (median: {peer_median})."
        }

peer_group_engine = PeerGroupEngine()

def get_peer_group_comparison(
    db: Session, entity_id: str, entity_type: str = "IP"
) -> Dict[str, Any]:
    """
    Convenience wrapper for comparing entity risk and baselines against peer cohort.
    """
    from app.analytics.models import Entity
    
    entities = db.query(Entity).filter(Entity.entity_type == entity_type).all()
    target = next((e for e in entities if e.entity_id == entity_id), None)
    
    subnet_prefix = ".".join(entity_id.split(".")[:3]) + ".0/24" if "." in entity_id else "DEFAULT_COHORT"
    
    if not entities or len(entities) < 2:
        return {
            "entity_id": entity_id,
            "peer_group_id": subnet_prefix,
            "peer_count": len(entities),
            "peer_group_average_risk": target.current_risk_score if target else 0.0,
            "risk_deviation_from_peer": 0.0
        }
        
    avg_risk = sum(e.current_risk_score for e in entities) / len(entities)
    target_risk = target.current_risk_score if target else 0.0
    
    return {
        "entity_id": entity_id,
        "peer_group_id": subnet_prefix,
        "peer_count": len(entities),
        "peer_group_average_risk": round(avg_risk, 1),
        "risk_deviation_from_peer": round(target_risk - avg_risk, 1)
    }

