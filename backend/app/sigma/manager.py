from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.sigma.models import SigmaRule, SigmaRuleVersion
from app.sigma.parser import parse_sigma_yaml
from app.sigma.validator import validate_sigma_rule
from app.sigma.versioning import create_rule_version
from app.models.audit import AuditLog

class SigmaManager:
    @staticmethod
    def import_rule(db: Session, raw_yaml: str, user_id: str = "system") -> Dict[str, Any]:
        """
        Imports single or multi-document Sigma rules from raw YAML content.
        Validates structure and records initial version in DB.
        """
        parsed_list = parse_sigma_yaml(raw_yaml)
        imported_rules = []
        errors = []

        for rule_dict in parsed_list:
            validation = validate_sigma_rule(rule_dict, db=db)
            if not validation["valid"]:
                errors.append(f"Validation failed for '{rule_dict.get('title')}': {', '.join(validation['errors'])}")
                continue

            rule_id = rule_dict["rule_id"]
            existing = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()

            if existing:
                # Update existing rule & create new version
                existing.version += 1
                existing.title = rule_dict["title"]
                existing.description = rule_dict["description"]
                existing.status = validation["status"]
                existing.level = rule_dict["level"]
                existing.author = rule_dict["author"]
                existing.date = rule_dict["date"]
                existing.modified = rule_dict["modified"]
                existing.logsource = rule_dict["logsource"]
                existing.detection = rule_dict["detection"]
                existing.tags = rule_dict["tags"]
                existing.references = rule_dict["references"]
                existing.falsepositives = rule_dict["falsepositives"]
                existing.raw_yaml = rule_dict["raw_yaml"]
                existing.normalized_rule = rule_dict
                existing.updated_at = datetime.utcnow()
                existing.updated_by = user_id

                db.commit()
                db.refresh(existing)
                create_rule_version(db, existing, author=user_id, change_summary="Rule updated via YAML import")
                imported_rules.append(existing)
            else:
                new_rule = SigmaRule(
                    rule_id=rule_id,
                    title=rule_dict["title"],
                    description=rule_dict["description"],
                    status=validation["status"],
                    level=rule_dict["level"],
                    author=rule_dict["author"],
                    date=rule_dict["date"],
                    modified=rule_dict["modified"],
                    logsource=rule_dict["logsource"],
                    detection=rule_dict["detection"],
                    tags=rule_dict["tags"],
                    references=rule_dict["references"],
                    falsepositives=rule_dict["falsepositives"],
                    raw_yaml=rule_dict["raw_yaml"],
                    normalized_rule=rule_dict,
                    enabled=False,  # Rules default to disabled upon import for safety
                    version=1,
                    created_by=user_id,
                    updated_by=user_id
                )
                db.add(new_rule)
                db.commit()
                db.refresh(new_rule)
                create_rule_version(db, new_rule, author=user_id, change_summary="Initial import")
                imported_rules.append(new_rule)

            # Record Audit Log
            db.add(AuditLog(
                user=user_id,
                action="SIGMA_RULE_IMPORTED",
                resource_type="SIGMA_RULE",
                resource_id=rule_id,
                details=f"Imported Sigma Rule '{rule_dict['title']}' ({rule_id})"
            ))
            db.commit()

        return {
            "imported_count": len(imported_rules),
            "errors": errors,
            "rule_ids": [r.rule_id for r in imported_rules]
        }

    @staticmethod
    def toggle_rule(db: Session, rule_id: str, enable: bool, user_id: str = "system") -> SigmaRule:
        """
        Enables or disables a Sigma rule for production evaluation.
        Only VALID rules may be enabled.
        """
        rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
        if not rule:
            raise ValueError(f"Rule '{rule_id}' not found.")

        if enable and rule.status not in ["VALID", "UNSUPPORTED"]:
            raise ValueError(f"Cannot enable rule '{rule_id}' with status '{rule.status}'. Rule must be VALID.")

        rule.enabled = enable
        rule.status = "ENABLED" if enable else "DISABLED"
        rule.updated_at = datetime.utcnow()
        rule.updated_by = user_id
        db.commit()
        db.refresh(rule)

        action_name = "SIGMA_RULE_ENABLED" if enable else "SIGMA_RULE_DISABLED"
        db.add(AuditLog(
            user=user_id,
            action=action_name,
            resource_type="SIGMA_RULE",
            resource_id=rule_id,
            details=f"{'Enabled' if enable else 'Disabled'} Sigma Rule '{rule.title}' ({rule_id})"
        ))
        db.commit()

        return rule
