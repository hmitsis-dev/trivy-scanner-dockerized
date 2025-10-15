import subprocess
import tempfile
import shutil
import os
import json
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Security
from fastapi.security import APIKeyHeader
import boto3

# --- Configuration (from Environment Variables) ---
API_KEY = os.getenv("SCANNER_API_KEY")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# Add this check:
if not all([API_KEY, S3_BUCKET_NAME]):
    raise ValueError("One or more required environment variables are not set: SCANNER_API_KEY, S3_BUCKET_NAME")

api_key_header = APIKeyHeader(name="X-API-Key")
app = FastAPI()


# Initialize the S3 client. Boto3 will automatically use the
# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.
s3_client = boto3.client("s3")

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

@app.post("/scan-and-store")
async def scan_and_store(file: UploadFile = File(...), api_key: str = Security(get_api_key)):
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = f"{temp_dir}/{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        subprocess.run(["tar", "-xzf", file_path, "-C", temp_dir], check=True)

        command = ["trivy", "fs", "--format", "json", temp_dir]
        result = subprocess.run(command, capture_output=True, text=True)
        report_content = result.stdout

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H%M%S")
        report_filename = f"reports/{timestamp}-{file.filename}.json"
        
        # Upload the JSON report to AWS S3
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=report_filename,
            Body=report_content,
            ContentType="application/json"
        )

        # Always return a success message to the pipeline
        return {
            "status": "received",
            "message": "Scan data received and stored in S3.",
            "report_path": f"s3://{S3_BUCKET_NAME}/{report_filename}"
        }