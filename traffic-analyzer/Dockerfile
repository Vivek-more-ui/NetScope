FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install TShark for offline packet analysis.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies.
COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install --no-cache-dir \
    -r /app/backend/requirements.txt

# Copy only the NetScope backend and its sample captures.
COPY backend/ /app/backend/
COPY sample_captures/ /app/sample_captures/

WORKDIR /app/backend

EXPOSE 8000

CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
