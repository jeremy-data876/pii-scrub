FROM python:3.11-alpine

LABEL maintainer="pii-scrub core team"
LABEL description="Zero-retention streaming PII redaction utility"

# Run as non-root user (essential for SOC 2 / HIPAA compliance)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy the standalone scrubber script and entrypoint
COPY pii_scrub.py /app/pii_scrub.py
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/pii_scrub.py /app/entrypoint.sh && chown -R appuser:appgroup /app

USER appuser

ENTRYPOINT ["/app/entrypoint.sh"]
