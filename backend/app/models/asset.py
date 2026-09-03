from sqlalchemy import Column, Integer, String, Float
from app.database.connection import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    ip_address = Column(String, unique=True, index=True)
    asset_type = Column(String)  # FIREWALL, CORE_SWITCH, WEB_SERVER, DB_SERVER, WORKSTATION, DOMAIN_CONTROLLER
    status = Column(String, default="HEALTHY")  # HEALTHY, WARNING, CRITICAL, ISOLATED
    risk_score = Column(Float, default=15.0)  # 0 to 100
    risk_level = Column(String, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    events_count = Column(Integer, default=0)
    alerts_count = Column(Integer, default=0)
    description = Column(String, nullable=True)
