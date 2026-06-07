FROM python:3.11-slim
WORKDIR /app

# Copy shared modules from sibling services
# (Build context is the repo root — see docker-compose.yml)
COPY capture/flow_extractor.py /app/
COPY identity/identity_store.py /app/
COPY identity/oui_lookup.py /app/
COPY fingerprint/app_classifier.py /app/
COPY fingerprint/ja3_database.json /app/
COPY pipeline/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pipeline/ .

CMD ["python", "-u", "pipeline.py"]
