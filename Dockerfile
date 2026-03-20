# Use a lightweight Python base image
FROM python:3.12-slim

# Install system dependencies needed for unpacking code
RUN apt-get update && apt-get install -y --no-install-recommends tar wget curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Download and install the Trivy binary
ARG TRIVY_VERSION=0.50.1
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    dpkg -i trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    rm trivy_${TRIVY_VERSION}_Linux-64bit.deb

# Create a non-root user and switch to it
RUN adduser --system --group appuser
USER appuser
WORKDIR /app

# Install Python web server dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code into the container
COPY main.py .
COPY app ./app

# Expose port and run the server
EXPOSE 8000

# Healthcheck for robust deployments
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
