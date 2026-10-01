FROM python:3.12-slim

WORKDIR /app
COPY threatlens-backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY threatlens-backend/app ./app
COPY threatlens-backend/tests ./tests
COPY threatlens-frontend ./threatlens-frontend

# Optional enrichment API keys are provided at runtime:
# ABUSEIPDB_KEY, VIRUSTOTAL_KEY, OTX_KEY, SHODAN_KEY, GREYNOISE_KEY,
# PHISHTANK_KEY, MALWAREBAZAAR_KEY. Without them the deterministic
# reference enrichers keep every view functional.
ENV CONSOLE_DIR=/app/threatlens-frontend

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
