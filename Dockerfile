FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for LightGBM and network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Environment setup
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

EXPOSE 5000

# Start server using gunicorn with dynamic PORT
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120"]
