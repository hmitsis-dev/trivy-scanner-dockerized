# Trivy Docker API

A lightweight web service that scans code archives using Trivy and stores the reports in an S3 bucket.

## Setup

1.  **AWS S3**: Create an S3 bucket and an IAM user with `s3:PutObject` permissions for that bucket. Obtain the Access Key ID and Secret Access Key.
2.  **Environment Variables**: Set the following environment variables for the service:
    *   `SCANNER_API_KEY`: A secret key for API authentication.
    *   `S3_BUCKET_NAME`: The name of your S3 bucket.
    *   `AWS_ACCESS_KEY_ID`: Your AWS Access Key ID.
    *   `AWS_SECRET_ACCESS_KEY`: Your AWS Secret Access Key.
3.  **Build & Deploy**:
    *   Build the Docker image: `docker build -t your-image-name .`
    *   Push to a container registry.
    *   Deploy to a cloud service (e.g., AWS App Runner, Google Cloud Run), configuring the environment variables.

## Usage

### Local Testing

1.  Run the Docker container locally:
    ```bash
    docker run -d --name scanner-app -p 8000:8000 \
      -e SCANNER_API_KEY="..." \
      -e S3_BUCKET_NAME="..." \
      -e AWS_ACCESS_KEY_ID="..." \
      -e AWS_SECRET_ACCESS_KEY="..." \
      your-image-name
    ```
2.  Simulate a scan request:
    ```bash
    tar -czf test-app.tar.gz .
    curl -X POST -H "X-API-Key:..." -F "file=@test-app.tar.gz" http://localhost:8000/scan-and-store
    ```
3.  Verify the JSON report appears in your S3 bucket.

### CI/CD Integration

Integrate this service into your CI/CD pipeline by packaging your repository (e.g., `tar -czf`) and sending it to the `/scan-and-store` endpoint via an API call (e.g., `curl`). The service will return a 200 OK response, allowing your pipeline to continue.

## Core Components

*   **Scanner Service**: Dockerized Python (FastAPI) web service that runs Trivy scans.
*   **Data Store**: AWS S3 for storing raw JSON Trivy reports.

## Troubleshooting

*   **Environment Variable Errors**: Ensure all required environment variables (`SCANNER_API_KEY`, `S3_BUCKET_NAME`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) are correctly set.
*   **Invalid API Key**: Verify the `X-API-Key` header matches `SCANNER_API_KEY`.
*   **Scan/Upload Failures**: Check service logs for detailed errors from Trivy or S3.
*   **Docker Healthcheck**: Ensure the service is running and accessible on port 8000 if deploying with healthchecks.
