import requests

BASE_URL = "http://127.0.0.1:8000"

def test_dashboard_serving():
    print("=== Testing Web Dashboard Serving & HTTP Integration ===")
    
    # 1. Test GET / (Dashboard HTML)
    r_index = requests.get(f"{BASE_URL}/")
    print(f"1. GET / Status: {r_index.status_code} | Content-Type: {r_index.headers.get('content-type')}")
    assert r_index.status_code == 200
    assert "<!DOCTYPE html>" in r_index.text
    assert "AI-Based DNS Filtering" in r_index.text
    
    # 2. Test GET /static/style.css
    r_css = requests.get(f"{BASE_URL}/static/style.css")
    print(f"2. GET /static/style.css Status: {r_css.status_code}")
    assert r_css.status_code == 200
    assert ".status-allow" in r_css.text
    
    # 3. Test GET /static/script.js
    r_js = requests.get(f"{BASE_URL}/static/script.js")
    print(f"3. GET /static/script.js Status: {r_js.status_code}")
    assert r_js.status_code == 200
    assert "fetch('/analyze'" in r_js.text

    # 4. Test GET /health & GET /docs
    r_health = requests.get(f"{BASE_URL}/health")
    r_docs = requests.get(f"{BASE_URL}/docs")
    print(f"4. GET /health Status: {r_health.status_code} | GET /docs Status: {r_docs.status_code}")
    assert r_health.status_code == 200
    assert r_docs.status_code == 200

    print("\nWEB DASHBOARD SERVING TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_dashboard_serving()
