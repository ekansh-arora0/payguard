# Use an official Python runtime as a parent image
FROM python:3.9-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libgl1 \
    libglib2.0-0 \
    build-essential \
    python3-dev \
    libomp-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install dependencies in stages to better handle failures and caching
# We install torch first because it's the largest dependency
RUN pip install --no-cache-dir torch==2.0.1 torchvision==0.15.2
RUN pip install --no-cache-dir -r requirements.txt

# Install playwright browsers and their system dependencies
RUN playwright install chromium && playwright install-deps chromium

# Copy the current directory contents into the container at /app
COPY . /app/

# Expose the port the app runs on
EXPOSE 8002

# Command to run the application
CMD ["uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8002"]
