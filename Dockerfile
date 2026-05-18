# HoneyCow — NS-squatter DNS + HTTP catch-all on a single asyncio process.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r requirements.lock

# Non-root user. Port 53 / port 80 inside the container do not require root;
# Docker maps the privileged host ports from the daemon side.
RUN useradd -r -s /bin/false -d /app honey \
 && mkdir -p /var/log/honeycow /etc/honeycow \
 && chown honey:honey /var/log/honeycow /etc/honeycow

# Source. squatter/, static/, and tools/ are separate COPYs to preserve
# directory structure.
COPY honey_ns.py honey_logging.py honey_http.py /app/
COPY squatter/ /app/squatter/
COPY static/ /app/static/
COPY tools/healthcheck.py /app/tools/healthcheck.py

USER honey

# DNS-native healthcheck — confirms parser + dispatch + socket bind all work.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=5s \
    CMD python /app/tools/healthcheck.py

CMD ["python", "honey_ns.py"]
