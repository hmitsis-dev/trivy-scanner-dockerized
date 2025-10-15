import subprocess
import tempfile
import shutil
import os
import json
import logging
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Security, HTTPException
from fastapi.security import APIKeyHeader
import boto3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration (from Environment Variables) ---
API_KEY = os.getenv("SCANNER_API_KEY")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# Add this check:
if not all([API_KEY, S3_BUCKET_NAME]):
    logger.error("One or more required environment variables are not set: SCANNER_API_KEY, S3_BUCKET_NAME")
    raise ValueError("One or more required environment variables are not set: SCANNER_API_KEY, S3_BUCKET_NAME")

api_key_header = APIKeyHeader(name="X-API-Key")
app = FastAPI()


# Initialize the S3 client. Boto3 will automatically use the
# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY_ID environment variables.
s3_client = boto3.client("s3")

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        logger.warning("Unauthorized access attempt with invalid API Key.")
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

@app.post("/scan-and-store")
async def scan_and_store(file: UploadFile = File(...), api_key: str = Security(get_api_key)):
    logger.info(f"Received scan request for file: {file.filename}")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = f"{temp_dir}/{file.filename}"
            logger.info(f"Saving uploaded file to {file_path}")
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            logger.info(f"Extracting {file.filename} to {temp_dir}")
            try:
                subprocess.run(["tar", "-xzf", file_path, "-C", temp_dir], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to extract tar.gz file: {e}")
                raise HTTPException(status_code=400, detail=f"Failed to extract archive: {e.stderr}")

            command = ["trivy", "fs", "--format", "json", temp_dir]
            logger.info(f"Running Trivy scan with command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Trivy scan failed with error: {result.stderr}")
                raise HTTPException(status_code=500, detail=f"Trivy scan failed: {result.stderr}")

            report_content = result.stdout
            logger.info("Trivy scan completed successfully.")

            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H%M%S")
            report_filename = f"reports/{timestamp}-{file.filename.replace('.tar.gz', '')}.json"
            
            logger.info(f"Uploading report to S3 bucket '{S3_BUCKET_NAME}' with key '{report_filename}'")
            s3_client.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=report_filename,
                Body=report_content,
                ContentType="application/json"
            )
            logger.info("Report uploaded to S3 successfully.")

            return {
                "status": "received",
                "message": "Scan data received and stored in S3.",
                "report_path": f"s3://{S3_BUCKET_NAME}/{report_filename}"
            }
    except HTTPException:
        raise # Re-raise HTTPException to be handled by FastAPI
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"An internal server error occurred: {e}")
