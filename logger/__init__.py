from loguru import logger
import os
from config import settings

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure logger
logger.add(
    "logs/app.log",
    rotation="1 day",  # Rotate daily
    retention="30 days",  # Keep logs for 30 days
    compression="zip",  # Compress rotated logs
    level=settings.log_level,  # Set log level
    format="{time:YYYY-MM-DD HH:mm:ss} | {module}.{function}:{line} | {level} | {message}"
)

# Expose logger for use in other modules
__all__ = ["logger"]