import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def test_api():
    print("=== Testing FastAPI Endpoints via HTTP ===")
    
    # 1. Test GET / (Dashboard HTML)
    r_root = requests.get(f"{BASE_URL}/")
    print(f"\n1. GET / -> Status {r_root.status_code} | Content-Type: {r_root.headers.get('content-type')}")
    assert r_root.status_code == 200
    assert "<!DOCTYPE html>" in r_root.text
    
    # 2. Test GET /health
    r_health = requests.get(f"{BASE_URL}/health")
    print(f"\n2. GET /health -> Status {r_health.status_code}")
    print("Response:", r_health.json())
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"
    
    # 3. Test GET /docs & /openapi.json
    r_docs = requests.get(f"{BASE_URL}/docs")
    r_openapi = requests.get(f"{BASE_URL}/openapi.json")
    print(f"\n3. Docs Check -> /docs Status: {r_docs.status_code} | /openapi.json Status: {r_openapi.status_code}")
    assert r_docs.status_code == 200
    assert r_openapi.status_code == 200

    # 4. Test POST /analyze with 4 required security scenarios
    test_domains = [
        ("google.com", "ALLOW", "Benign domain"),
        ("bnet.playm8ru.win", "BLOCK", "URLhaus Threat Intelligence indicator"),
        ("chanceregretclubsurveyreport.com", "BLOCK", "DGA malware domain"),
        ("dnscat.0a1b2c3d4e5f.tunnel-domain.net", "BLOCK", "DNS Tunnelling payload domain")
    ]
    
    print("\n4. Testing POST /analyze Security Scenarios:")
    for domain, expected_status, note in test_domains:
        r = requests.post(f"{BASE_URL}/analyze", json={"domain": domain})
        print(f"\n--- Scenario: {note} ---")
        print(f"Request: {{'domain': '{domain}'}}")
        print(f"HTTP Status: {r.status_code}")
        res = r.json()
        print("Response JSON:")
        print(json.dumps(res, indent=2))
        assert r.status_code == 200
        assert res["final_status"] == expected_status, f"Expected {expected_status}, got {res['final_status']}"

    # 5. Test Invalid Inputs
    print("\n5. Testing Invalid Input Handling:")
    
    # Empty string
    r_empty = requests.post(f"{BASE_URL}/analyze", json={"domain": "   "})
    print(f"Empty domain status: {r_empty.status_code} | Detail: {r_empty.json()}")
    assert r_empty.status_code == 400
    
    # Missing domain field
    r_missing = requests.post(f"{BASE_URL}/analyze", json={})
    print(f"Missing domain field status: {r_missing.status_code} | Detail: {r_missing.json()}")
    assert r_missing.status_code in (400, 422)

    print("\nALL HTTP API TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_api()
