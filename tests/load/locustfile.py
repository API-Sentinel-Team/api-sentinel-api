from locust import HttpUser, task, between
import random


class APISecurityUser(HttpUser):
    wait_time = between(1, 5)
    token = None
    headers = None

    def on_start(self):
        # Password meets policy: 12+ chars, digit, letter, special char
        email = f"loadtest_{random.randint(10000, 99999)}@loadtest.io"
        password = "L0adTest!Pass#2024"

        resp = self.client.post(
            "/api/auth/signup",
            json={"email": email, "password": password, "account_name": "LoadTestCorp"},
            name="/api/auth/signup",
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            self.token = data.get("access_token")
        else:
            # Try login in case account already exists
            resp = self.client.post(
                "/api/auth/login",
                json={"email": email, "password": password},
                name="/api/auth/login",
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("access_token")

        if self.token:
            self.headers = {"Authorization": f"Bearer {self.token}"}

    @task(10)
    def get_dashboard(self):
        if self.headers:
            self.client.get("/api/dashboard/", headers=self.headers, name="/api/dashboard/")

    @task(5)
    def get_endpoints(self):
        if self.headers:
            self.client.get("/api/endpoints/", headers=self.headers, name="/api/endpoints/")

    @task(3)
    def list_vulnerabilities(self):
        if self.headers:
            self.client.get(
                "/api/vulnerabilities/?limit=50",
                headers=self.headers,
                name="/api/vulnerabilities/",
            )

    @task(2)
    def get_alerts(self):
        if self.headers:
            self.client.get("/api/alerts/", headers=self.headers, name="/api/alerts/")

    @task(1)
    def trigger_test_run(self):
        if self.headers:
            self.client.post(
                "/api/tests/run",
                headers=self.headers,
                json={"template_ids": ["bola_user_id"], "endpoint_ids": ["some-uuid"]},
                name="/api/tests/run",
            )
