"""Quick integration test: run inference pipeline end-to-end."""
import asyncio
import json
import os

from dotenv import load_dotenv

load_dotenv("passive_asset_intel/.env")

from passive_asset_intel.inference.engine import run_inference

dsn = "postgresql://{}:{}@{}:{}/{}".format(
    os.getenv("DB_USER"),
    os.getenv("DB_PASSWORD"),
    os.getenv("DB_HOST"),
    os.getenv("DB_PORT"),
    os.getenv("DB_NAME"),
)
subnets = os.getenv("LOCAL_SUBNETS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",")

result = asyncio.run(run_inference(dsn=dsn, dry_run=False, local_subnets=subnets))
print(json.dumps(result, indent=2))
