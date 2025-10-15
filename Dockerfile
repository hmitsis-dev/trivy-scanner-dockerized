# Use a lightweight Python base image
FROM python:3.10-slim

# Install system dependencies needed for unpacking code
RUN apt-get update && apt-get install -y tar wget && rm -rf /var/lib/apt/lists/*

# Download and install the Trivy binary
ENV TRIVY_VERSION=0.50.1
RUN wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    dpkg -i trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    rm trivy_${TRIVY_VERSION}_Linux-64bit.deb

# Install Python web server dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code into the container
WORKDIR /app
COPY main.py .

# Expose port and run the server
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]