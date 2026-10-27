# Optional: run the shop server in the cloud (any host that runs Docker).
# IMPORTANT: attach a PERSISTENT DISK/VOLUME mounted at /data, otherwise the
# database is erased every time the host redeploys or restarts the container.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py shop_db.py policy.py ./
ENV SHOPTRACKER_DB=/data/shop_tracker.db \
    SHOP_TIMEZONE=Asia/Kolkata \
    SHOPTRACKER_TRUST_PROXY=1
VOLUME /data
EXPOSE 8000
CMD ["python", "server.py"]
