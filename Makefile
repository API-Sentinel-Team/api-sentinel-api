test-unit:
	pytest tests/unit/ -v --cov=server --cov-report=term-missing

test-integration:
	pytest tests/integration/ -v --asyncio-mode=auto

test-e2e:
	# Note: This assumes the vulnerable-target is running or managed via docker
	pytest tests/e2e/ -v

test-load:
	locust -f tests/load/locustfile.py --headless -u 50 -r 5 \
	       --run-time 30s --host http://localhost:8000 \
	       --only-summary

test-security:
	pytest tests/security/ -v

test-all: test-unit test-integration test-e2e test-security
	@echo "✅ All layers passed — production ready"
