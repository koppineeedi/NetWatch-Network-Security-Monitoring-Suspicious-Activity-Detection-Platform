import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.sigma.models import SigmaRule, SigmaRuleVersion

def create_rule_version(db: Session, rule: SigmaRule, author: str = "system", change_summary: str = "Rule updated") -> SigmaRuleVersion:
    """
    Creates a historical snapshot version record for a Sigma rule.
    """
    version_record = SigmaRuleVersion(
        rule_id=rule.rule_id,
        version=rule.version,
        raw_yaml=rule.raw_yaml,
        normalized_rule=rule.normalized_rule,
        author=author,
        change_summary=change_summary,
        created_at=datetime.utcnow()
    )
    db.add(version_record)
    db.commit()
    db.refresh(version_record)
    return version_record

def get_rule_versions(db: Session, rule_id: str):
    """
    Returns version history for a given rule_id.
    """
    return db.query(SigmaRuleVersion).filter(SigmaRuleVersion.rule_id == rule_id).order_by(SigmaRuleVersion.version.desc()).all()
