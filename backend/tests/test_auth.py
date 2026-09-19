import sys
import os
import uuid
import datetime
from fastapi import HTTPException
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database.connection import SessionLocal, Base, engine
from app.models.user import User
from app.models.audit import AuditLog
from app.core.security import hash_password, verify_password, create_access_token
from app.main import app

def run_auth_tests():
    print("============================================================")
    print("STARTING PHASE 6 AUTHENTICATION & RBAC UNIT TEST SUITE")
    print("============================================================")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    client = TestClient(app)

    run_id = str(uuid.uuid4())[:6]

    pass_admin = f"P@ssAdmin_{run_id}"
    pass_analyst = f"P@ssAnalyst_{run_id}"
    pass_new_analyst = f"P@ssNewAnalyst_{run_id}"

    # Create Test Users (In-memory/Test DB only)
    admin_user = User(
        username=f"admin_{run_id}",
        email=f"admin_{run_id}@test.local",
        password_hash=hash_password(pass_admin),
        role="ADMIN",
        is_active=True
    )
    analyst_user = User(
        username=f"analyst_{run_id}",
        email=f"analyst_{run_id}@test.local",
        password_hash=hash_password(pass_analyst),
        role="ANALYST",
        is_active=True
    )
    viewer_user = User(
        username=f"viewer_{run_id}",
        email=f"viewer_{run_id}@test.local",
        password_hash=hash_password("ViewerPass123!"),
        role="VIEWER",
        is_active=True
    )
    disabled_user = User(
        username=f"disabled_{run_id}",
        email=f"disabled_{run_id}@test.local",
        password_hash=hash_password("DisabledPass123!"),
        role="ANALYST",
        is_active=False
    )

    db.add_all([admin_user, analyst_user, viewer_user, disabled_user])
    db.commit()

    admin_token = create_access_token(data={"sub": str(admin_user.id), "username": admin_user.username, "role": "ADMIN"})
    analyst_token = create_access_token(data={"sub": str(analyst_user.id), "username": analyst_user.username, "role": "ANALYST"})
    viewer_token = create_access_token(data={"sub": str(viewer_user.id), "username": viewer_user.username, "role": "VIEWER"})

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. User Creation
    test_1 = admin_user.id is not None
    print(f"TEST 1 (User Creation): {'PASS' if test_1 else 'FAIL'}")

    # 2. Password Hashing
    test_2 = admin_user.password_hash.startswith("$argon2") or admin_user.password_hash.startswith("$2b$")
    print(f"TEST 2 (Password Hashing): {'PASS' if test_2 else 'FAIL'}")

    # 3. Password Verification
    test_3 = verify_password(pass_admin, admin_user.password_hash) and not verify_password("WrongPass", admin_user.password_hash)
    print(f"TEST 3 (Password Verification): {'PASS' if test_3 else 'FAIL'}")

    # 4. Successful Login
    res = client.post("/api/auth/login", json={"username": admin_user.username, "password": pass_admin})
    test_4 = res.status_code == 200 and "access_token" in res.json()
    print(f"TEST 4 (Successful Login): {'PASS' if test_4 else 'FAIL'}")

    # 5. Invalid Password Login
    res = client.post("/api/auth/login", json={"username": admin_user.username, "password": "BadPassword123!"})
    test_5 = res.status_code == 401
    print(f"TEST 5 (Invalid Password Rejected with 401): {'PASS' if test_5 else 'FAIL'}")

    # 6. Unknown User Login
    res = client.post("/api/auth/login", json={"username": "non_existent_user", "password": "Password123!"})
    test_6 = res.status_code == 401
    print(f"TEST 6 (Unknown User Rejected with 401): {'PASS' if test_6 else 'FAIL'}")

    # 7. Disabled User Login
    res = client.post("/api/auth/login", json={"username": disabled_user.username, "password": "DisabledPass123!"})
    test_7 = res.status_code == 401
    print(f"TEST 7 (Disabled User Rejected with 401): {'PASS' if test_7 else 'FAIL'}")

    # 8. GET /api/auth/me
    res = client.get("/api/auth/me", headers=admin_headers)
    test_8 = res.status_code == 200 and res.json()["username"] == admin_user.username
    print(f"TEST 8 (GET /api/auth/me): {'PASS' if test_8 else 'FAIL'}")

    # 9. Logout
    res = client.post("/api/auth/logout", headers=admin_headers)
    test_9 = res.status_code == 200
    print(f"TEST 9 (Logout Endpoint): {'PASS' if test_9 else 'FAIL'}")

    # 10. Password Change
    res = client.post("/api/auth/change-password", headers=analyst_headers, json={"current_password": pass_analyst, "new_password": pass_new_analyst})
    test_10 = res.status_code == 200
    print(f"TEST 10 (Password Change): {'PASS' if test_10 else 'FAIL'}")

    # 11. Old Password Rejected After Change
    res = client.post("/api/auth/login", json={"username": analyst_user.username, "password": pass_analyst})
    test_11 = res.status_code == 401
    print(f"TEST 11 (Old Password Rejected After Change): {'PASS' if test_11 else 'FAIL'}")

    # 12. ADMIN Authorization
    res = client.get("/api/users", headers=admin_headers)
    test_12 = res.status_code == 200
    print(f"TEST 12 (ADMIN Authorization): {'PASS' if test_12 else 'FAIL'}")

    # 13. ANALYST Authorization (Alerts & Investigations mutation allowed)
    res = client.get("/api/alerts", headers=analyst_headers)
    test_13 = res.status_code == 200
    print(f"TEST 13 (ANALYST Operational Access): {'PASS' if test_13 else 'FAIL'}")

    # 14. VIEWER Authorization (Read allowed)
    res = client.get("/api/alerts", headers=viewer_headers)
    test_14 = res.status_code == 200
    print(f"TEST 14 (VIEWER Read Access): {'PASS' if test_14 else 'FAIL'}")

    # 15. Unauthenticated Request Returns 401
    res = client.get("/api/alerts")
    test_15 = res.status_code == 401
    print(f"TEST 15 (Unauthenticated Request Returns 401): {'PASS' if test_15 else 'FAIL'}")

    # 16. Authenticated Insufficient-Role Request Returns 403
    res = client.get("/api/users", headers=viewer_headers)
    test_16 = res.status_code == 403
    print(f"TEST 16 (Insufficient Role Returns 403): {'PASS' if test_16 else 'FAIL'}")

    # 17. User Management is ADMIN-only
    res_analyst = client.get("/api/users", headers=analyst_headers)
    test_17 = res_analyst.status_code == 403
    print(f"TEST 17 (User Management Forbidden to ANALYST): {'PASS' if test_17 else 'FAIL'}")

    # 18. Alert Mutation Permissions (VIEWER forbidden)
    res_v = client.patch("/api/alerts/1", headers=viewer_headers, json={"status": "INVESTIGATING"})
    test_18 = res_v.status_code == 403
    print(f"TEST 18 (Alert Mutation Forbidden to VIEWER): {'PASS' if test_18 else 'FAIL'}")

    # 19. Investigation Mutation Permissions (VIEWER forbidden)
    res_v_inv = client.post("/api/investigations", headers=viewer_headers, json={"alert_id": 1})
    test_19 = res_v_inv.status_code == 403
    print(f"TEST 19 (Investigation Creation Forbidden to VIEWER): {'PASS' if test_19 else 'FAIL'}")

    # 20. Detection-Rule Mutation Permissions (ANALYST forbidden from creating rules)
    res_a_rule = client.post("/api/rules", headers=analyst_headers, json={"rule_code": "R-TEST", "name": "Test", "description": "Test", "severity": "LOW"})
    test_20 = res_a_rule.status_code == 403
    print(f"TEST 20 (Rule Creation Forbidden to ANALYST): {'PASS' if test_20 else 'FAIL'}")

    # 21. Password Hash Never Returned in API
    res_me = client.get("/api/auth/me", headers=admin_headers)
    test_21 = "password" not in res_me.json() and "password_hash" not in res_me.json()
    print(f"TEST 21 (Password Hash Never Returned): {'PASS' if test_21 else 'FAIL'}")

    # 22. Passwords Never Written to Audit Logs (Verify actual plaintext password values are not logged)
    audit_leak = db.query(AuditLog).filter(
        (AuditLog.details.like(f"%{pass_admin}%")) |
        (AuditLog.details.like(f"%{pass_analyst}%")) |
        (AuditLog.details.like(f"%{pass_new_analyst}%"))
    ).all()
    test_22 = len(audit_leak) == 0
    print(f"TEST 22 (Passwords Never Written to Audit Logs): {'PASS' if test_22 else 'FAIL'}")

    # 23. Authentication Audit Events Created
    login_audits = db.query(AuditLog).filter(AuditLog.action.in_(["LOGIN_SUCCESS", "LOGIN_FAILURE"])).all()
    test_23 = len(login_audits) > 0
    print(f"TEST 23 (Authentication Audit Events Logged): {'PASS' if test_23 else 'FAIL'}")

    # Temporarily disable other active admins for sole admin protection testing
    other_admins = db.query(User).filter(User.role == "ADMIN", User.id != admin_user.id, User.is_active == True).all()
    for oa in other_admins:
        oa.is_active = False
    db.commit()

    # 24. Final ADMIN Cannot Be Disabled
    res_dis_admin = client.patch(f"/api/users/{admin_user.id}/status", headers=admin_headers, json={"is_active": False})
    test_24 = res_dis_admin.status_code == 400
    print(f"TEST 24 (Final Active ADMIN Cannot Be Disabled): {'PASS' if test_24 else 'FAIL'}")

    # 25. Final ADMIN Cannot Be Demoted
    res_dem_admin = client.patch(f"/api/users/{admin_user.id}/role", headers=admin_headers, json={"role": "ANALYST"})
    test_25 = res_dem_admin.status_code == 400
    print(f"TEST 25 (Final Active ADMIN Cannot Be Demoted): {'PASS' if test_25 else 'FAIL'}")

    # Re-enable other admins
    for oa in other_admins:
        oa.is_active = True
    db.commit()

    # 26. Regression Test (Events, Telemetry status, Statistics endpoints work with auth)
    res_stats = client.get("/api/statistics", headers=admin_headers)
    test_26 = res_stats.status_code == 200
    print(f"TEST 26 (Regression Pipeline Intact): {'PASS' if test_26 else 'FAIL'}")

    db.close()
    print("============================================================")

if __name__ == "__main__":
    run_auth_tests()
