FROM python:3.11-slim

WORKDIR /app

# Install ping utility
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Create flag file at startup
ENV FLAG="CTF{rce_through_ping}"

# Write flag on container start
CMD ["sh", "-c", "echo $FLAG > /flag.txt && python app.py"]
