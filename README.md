# pii-scrub 🛡️

> High-throughput, zero-retention streaming PII redaction and schema-safe synthetic data utility designed for engineering teams sanitizing production dumps for local staging, analytics, and LLM pipelines.

[[https://img.shields.io/badge/License-Apache_2.0-blue.svg]](LICENSE)
[[https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white]](Dockerfile)
[[https://img.shields.io/badge/Throughput-40k%2B%20lines%2Fsec-success]](#benchmarks)

---

## ⚡ Instant Time-to-Value (30-Second Quickstart)

No servers to provision. No databases to configure. Stream directly through UNIX pipes:

```bash
# Sanitize a PostgreSQL database dump in real time (Zero Disk Writes)
pg_dump -Fc prod_db | docker run -i --rm ghcr.io/yourusername/pii-scrub:v1 --mode synthetic > staging.sql

# Sanitize an LLM training JSONL dataset
cat dirty_prompts.jsonl | docker run -i --rm ghcr.io/yourusername/pii-scrub:v1 --format jsonl > clean_prompts.jsonl

# Target specific CSV columns from a data warehouse export
cat raw_export.csv | docker run -i --rm ghcr.io/yourusername/pii-scrub:v1 --format csv --columns email,notes > clean_export.csv
