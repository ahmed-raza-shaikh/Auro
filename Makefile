# ─────────────────────────────────────────────────────────────────────────────
# Auro — Automated Cloud Compliance Engine
# Makefile: Development, packaging, and deployment helpers
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   make install    — Install dependencies locally for development
#   make test       — Run full unit test suite with coverage
#   make layer      — Build the Lambda Layer ZIP (reportlab + requests)
#   make package    — Bundle Lambda function code into a deployment ZIP
#   make deploy     — Deploy/update via CloudFormation
#   make invoke     — Manually trigger the Lambda for smoke testing
#   make logs       — Tail the Lambda CloudWatch logs
#   make lint       — Run flake8 and mypy static analysis
#   make clean      — Remove build artifacts
# ─────────────────────────────────────────────────────────────────────────────

STACK_NAME        := auro-compliance-engine
FUNCTION_NAME     := auro-compliance-engine
REGION            := us-east-1
LAYER_NAME        := auro-deps
BUILD_DIR         := .build
LAYER_DIR         := $(BUILD_DIR)/layer
PACKAGE_DIR       := $(BUILD_DIR)/package
LAYER_ZIP         := $(BUILD_DIR)/auro-layer.zip
PACKAGE_ZIP       := $(BUILD_DIR)/auro-function.zip
PYTHON            := python3
PIP               := pip3

.PHONY: all install test layer package deploy invoke logs lint clean

all: test package

# ── Install local development dependencies ────────────────────────────────────
install:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov flake8 mypy boto3-stubs

# ── Run tests with coverage report ────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short \
	  --cov=. \
	  --cov-report=term-missing \
	  --cov-report=html:.coverage_html \
	  --cov-omit="tests/*,$(BUILD_DIR)/*"
	@echo "\nCoverage HTML report: .coverage_html/index.html"

# ── Static analysis ────────────────────────────────────────────────────────────
lint:
	flake8 lambda_function.py cis_checks.py pdf_generator.py \
	  --max-line-length=100 \
	  --ignore=E501,W503
	mypy lambda_function.py cis_checks.py pdf_generator.py \
	  --ignore-missing-imports

# ── Build Lambda Layer (reportlab + requests — NOT boto3, provided by runtime) ─
layer:
	@echo "Building Lambda Layer..."
	rm -rf $(LAYER_DIR)
	mkdir -p $(LAYER_DIR)/python
	$(PIP) install -r requirements.txt -t $(LAYER_DIR)/python \
	  --no-deps --quiet
	cd $(LAYER_DIR) && zip -r ../../$(LAYER_ZIP) python/ -x "*.pyc" -x "*__pycache__*"
	@echo "Layer ZIP: $(LAYER_ZIP)"
	@echo "Size: $$(du -sh $(LAYER_ZIP) | cut -f1)"

# ── Publish the Layer to AWS ──────────────────────────────────────────────────
publish-layer: layer
	aws lambda publish-layer-version \
	  --layer-name $(LAYER_NAME) \
	  --description "Auro dependencies: reportlab, requests" \
	  --zip-file fileb://$(LAYER_ZIP) \
	  --compatible-runtimes python3.12 \
	  --region $(REGION)

# ── Build Lambda function deployment package ──────────────────────────────────
package:
	@echo "Building Lambda deployment package..."
	rm -rf $(PACKAGE_DIR)
	mkdir -p $(PACKAGE_DIR)
	cp lambda_function.py cis_checks.py pdf_generator.py $(PACKAGE_DIR)/
	cd $(PACKAGE_DIR) && zip -r ../../$(PACKAGE_ZIP) . -x "*.pyc" -x "*__pycache__*"
	@echo "Package ZIP: $(PACKAGE_ZIP)"
	@echo "Size: $$(du -sh $(PACKAGE_ZIP) | cut -f1)"

# ── Deploy via CloudFormation ─────────────────────────────────────────────────
deploy: package
	@echo "Deploying CloudFormation stack: $(STACK_NAME)..."
	aws cloudformation deploy \
	  --template-file cloudformation.yaml \
	  --stack-name $(STACK_NAME) \
	  --parameter-overrides \
	    SlackWebhookUrl=$(SLACK_WEBHOOK_URL) \
	    ReportsBucketName=$(S3_REPORTS_BUCKET) \
	  --capabilities CAPABILITY_NAMED_IAM \
	  --region $(REGION)
	@echo "Updating Lambda function code..."
	aws lambda update-function-code \
	  --function-name $(FUNCTION_NAME) \
	  --zip-file fileb://$(PACKAGE_ZIP) \
	  --region $(REGION)

# ── Manual Lambda invocation (smoke test) ─────────────────────────────────────
invoke:
	aws lambda invoke \
	  --function-name $(FUNCTION_NAME) \
	  --payload '{"source":"manual-test","detail-type":"Manual Invocation"}' \
	  --cli-binary-format raw-in-base64-out \
	  --log-type Tail \
	  --region $(REGION) \
	  /tmp/auro-response.json | \
	  python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d.get('LogResult','')).decode())"
	@echo "\nResponse:"
	@cat /tmp/auro-response.json | python3 -m json.tool

# ── Tail CloudWatch Logs ──────────────────────────────────────────────────────
logs:
	aws logs tail /aws/lambda/$(FUNCTION_NAME) \
	  --follow \
	  --region $(REGION)

# ── Clean build artifacts ─────────────────────────────────────────────────────
clean:
	rm -rf $(BUILD_DIR) .coverage .coverage_html __pycache__ \
	  **/__pycache__ *.pyc **/*.pyc .mypy_cache
	@echo "Build artifacts cleaned."
