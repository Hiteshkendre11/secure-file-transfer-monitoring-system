FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000

WORKDIR /app

# The cloud container installs only API dependencies. Windows-only pywin32
# is intentionally installed on the auditor's Windows machine, not in Docker.
COPY cloud/requirements.txt /app/cloud-requirements.txt
RUN pip install --no-cache-dir -r /app/cloud-requirements.txt

COPY cloud /app/cloud
COPY src /app/src
COPY config /app/config
COPY windows_agent /app/windows_agent
COPY requirements.txt /app/requirements.txt
COPY README.md /app/README.md

EXPOSE 10000
CMD ["sh", "-c", "uvicorn cloud.app:app --host 0.0.0.0 --port ${PORT:-10000}"]
