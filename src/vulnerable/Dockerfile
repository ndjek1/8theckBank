# Vulnerable build image. Intentionally simple; this image is NOT hardened
# (sandbox/hardening is demonstrated in src/secure/Dockerfile).
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["sh", "-c", "python seed.py && python app.py"]
