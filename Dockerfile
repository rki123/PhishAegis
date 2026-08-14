# Use the official Python 3.10 image from Docker Hub
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for compiling some ML libraries)
RUN apt-get update && apt-get install -y \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install gunicorn for production serving
RUN pip install gunicorn

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
# Limit TensorFlow memory
ENV TF_CPP_MIN_LOG_LEVEL=3
ENV TF_FORCE_GPU_ALLOW_GROWTH=true

# Expose the port (Hugging Face Spaces automatically assigns the PORT environment variable, usually 7860)
EXPOSE 7860

# Command to run the Flask app inside the webapp directory using gunicorn
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:7860", "webapp.app:app"]
