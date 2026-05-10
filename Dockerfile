FROM python:3.11-slim

LABEL maintainer="349100"
LABEL description="SecProbe - AI-Assisted Web Security Misconfiguration Scanner"
LABEL version="1.0.0"

 Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    openssl \
    && rm -rf /var/lib/apt/lists/*

 Set working directory
	WORKDIR /app

 Copy requirements first for layer caching
	COPY requirements.txt .
	RUN pip install --no-cache-dir -r requirements.txt

 Copy project
	COPY . .
	RUN pip install --no-cache-dir -e .
	
 Expose API port
	EXPOSE 5000

 Environment defaults
	ENV SECPROBE_HOST=0.0.0.0
	ENV SECPROBE_PORT=5000
	ENV SECPROBE_DEBUG=false

# Run API with unicorn
	CMD ["gunicorn", \
    	 "--workers", "2", \
    	 "--bind", "0.0.0.0:5000", \
    	 "--timeout", "120", \
    	 "secprobe.api:app"]
