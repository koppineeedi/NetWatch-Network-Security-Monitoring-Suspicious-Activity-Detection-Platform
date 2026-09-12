import os
import datetime
import math
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.event import NetworkEvent
from app.analytics.models import BehaviorBaseline, Entity
from app.analytics.feature_engineering import calculate_entity_features

MIN_EVENTS_DEFAULT = 20
BASELINE_HOURS_DEFAULT = 168

class BaselineEngine:
    def __init__(self):
        self.min_events = int(os.getenv("NETWATCH_UEBA_MIN_EVENTS", str(MIN_EVENTS_DEFAULT)))
        self.baseline_hours = int(os.getenv("NETWATCH_UEBA_BASELINE_HOURS", str(BASELINE_HOURS_DEFAULT)))

    def calculate_baselines_for_entity(
        self, db: Session, entity_id: str, entity_type: str = "IP"
    ) -> List[BehaviorBaseline]:
        """
        Calculates statistical baselines for an entity from real historical NetworkEvent records.
        Sets status to INSUFFICIENT_DATA if total sample events < min_events.
        """
        now = datetime.datetime.utcnow()
        window_start = now - datetime.timedelta(hours=self.baseline_hours)

        # Query real historical events for this entity within window
        events = db.query(NetworkEvent).filter(
            (NetworkEvent.source_ip == entity_id) | (NetworkEvent.dest_ip == entity_id),
            NetworkEvent.timestamp >= window_start
        ).order_by(NetworkEvent.timestamp.asc()).all()

        sample_count = len(events)
        
        # Ensure Entity record exists
        entity = db.query(Entity).filter(
            Entity.entity_id == entity_id, Entity.entity_type == entity_type
        ).first()
        if not entity:
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=events[0].timestamp if events and events[0].timestamp else now,
                last_seen=events[-1].timestamp if events and events[-1].timestamp else now,
                event_count=sample_count,
                baseline_status="ACTIVE" if sample_count >= self.min_events else "INSUFFICIENT_DATA"
            )
            db.add(entity)
        else:
            entity.event_count = sample_count
            entity.last_seen = events[-1].timestamp if events and events[-1].timestamp else now
            entity.baseline_status = "ACTIVE" if sample_count >= self.min_events else "INSUFFICIENT_DATA"
            entity.updated_at = now

        db.commit()

        if sample_count < self.min_events:
            # Mark existing baselines as INSUFFICIENT_DATA
            existing_baselines = db.query(BehaviorBaseline).filter(
                BehaviorBaseline.entity_type == entity_type,
                BehaviorBaseline.entity_id == entity_id
            ).all()
            for b in existing_baselines:
                b.status = "INSUFFICIENT_DATA"
                b.sample_count = sample_count
                b.last_updated = now
            db.commit()
            return existing_baselines

        # Divide historical events into hourly chunks to compute feature samples
        chunks = {}
        for evt in events:
            if not evt.timestamp:
                continue
            hour_key = evt.timestamp.strftime("%Y-%m-%d %H:00")
            chunks.setdefault(hour_key, []).append(evt)

        feature_samples: Dict[str, List[float]] = {}
        for hour_key, chunk_events in chunks.items():
            feat_dict = calculate_entity_features(chunk_events, entity_id, entity_type)
            for fname, val in feat_dict.items():
                feature_samples.setdefault(fname, []).append(val)

        baselines = []
        for fname, samples in feature_samples.items():
            if not samples:
                continue
            
            n = len(samples)
            mean_val = sum(samples) / n
            variance = sum((x - mean_val) ** 2 for x in samples) / n if n > 1 else 0.0
            std_dev = math.sqrt(variance)
            
            sorted_samples = sorted(samples)
            min_val = sorted_samples[0]
            max_val = sorted_samples[-1]
            median_val = sorted_samples[n // 2]
            p95_idx = int(math.ceil(0.95 * n)) - 1
            p95_val = sorted_samples[max(0, min(p95_idx, n - 1))]

            baseline_record = db.query(BehaviorBaseline).filter(
                BehaviorBaseline.entity_type == entity_type,
                BehaviorBaseline.entity_id == entity_id,
                BehaviorBaseline.feature_name == fname
            ).first()

            if not baseline_record:
                baseline_record = BehaviorBaseline(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    feature_name=fname
                )
                db.add(baseline_record)

            baseline_record.mean_value = float(round(mean_val, 2))
            baseline_record.standard_deviation = float(round(std_dev, 2))
            baseline_record.median_value = float(round(median_val, 2))
            baseline_record.percentile_95 = float(round(p95_val, 2))
            baseline_record.minimum_value = float(round(min_val, 2))
            baseline_record.maximum_value = float(round(max_val, 2))
            baseline_record.sample_count = sample_count
            baseline_record.baseline_window_start = window_start
            baseline_record.baseline_window_end = now
            baseline_record.last_updated = now
            baseline_record.status = "ACTIVE"

            baselines.append(baseline_record)

        db.commit()
        return baselines

baseline_engine = BaselineEngine()

def update_entity_baselines(
    db: Session, entity_id: str, entity_type: str = "IP", min_events: int = 20, window_hours: int = 168
) -> Dict[str, BehaviorBaseline]:
    """
    Convenience wrapper for updating entity baselines and returning a feature-mapped dictionary.
    """
    baseline_engine.min_events = min_events
    baseline_engine.baseline_hours = window_hours
    baselines_list = baseline_engine.calculate_baselines_for_entity(db, entity_id, entity_type)
    return {b.feature_name: b for b in baselines_list}

