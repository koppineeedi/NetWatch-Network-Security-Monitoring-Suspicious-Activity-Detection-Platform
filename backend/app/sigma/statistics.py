from sqlalchemy.orm import Session
from sqlalchemy import func
from app.sigma.models import SigmaRule, SigmaRuleExecution, SigmaRuleMatch

def get_sigma_statistics(db: Session):
    """
    Computes aggregated engine statistics for all Sigma rules.
    Returns 0/null metrics accurately without manufacturing fake data.
    """
    total_rules = db.query(SigmaRule).count()
    enabled_rules = db.query(SigmaRule).filter(SigmaRule.enabled == True).count()
    valid_rules = db.query(SigmaRule).filter(SigmaRule.status == "VALID").count()
    invalid_rules = db.query(SigmaRule).filter(SigmaRule.status == "INVALID").count()

    total_executions = db.query(SigmaRuleExecution).count()
    total_matches = db.query(SigmaRuleMatch).count()

    avg_exec = db.query(func.avg(SigmaRuleExecution.execution_time_ms)).scalar()
    avg_exec_ms = round(float(avg_exec), 2) if avg_exec else 0.0

    return {
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "valid_rules": valid_rules,
        "invalid_rules": invalid_rules,
        "total_executions": total_executions,
        "total_matches": total_matches,
        "average_execution_ms": avg_exec_ms
    }
