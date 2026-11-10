# StepCheck Cloud. Build from the repository root:
#   docker build -f cloud/Dockerfile -t stepcheck-cloud .
# The engine comes from PyPI (stepcheck-dev, pinned in requirements.txt); only cloud/ is copied.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STEPCHECK_CLOUD_DB=/data/stepcheck-cloud.db \
    STEPCHECK_REQUIRE_SIGNING_KEY=1 \
    STEPCHECK_HOOK_AUTOSTART=0

WORKDIR /app
COPY cloud/requirements.txt /app/cloud/requirements.txt
RUN pip install --no-cache-dir -r /app/cloud/requirements.txt
COPY cloud/__init__.py cloud/app.py cloud/github_app.py cloud/signing.py cloud/billing.py cloud/store.py /app/cloud/

RUN useradd --system --uid 10001 stepcheck && mkdir /data && chown stepcheck /data
USER stepcheck
VOLUME /data
EXPOSE 8080

# One process: SQLite and the installation-token cache live in it.
CMD ["uvicorn", "cloud.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
