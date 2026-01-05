FROM python:3.11-slim

WORKDIR /app

# Install libxml2 for lxml
RUN apt-get update && apt-get install -y libxml2-dev libxslt-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV FLAG="CTF{xxe_file_disclosure}"

# Write flag on container start
CMD ["sh", "-c", "echo $FLAG > /flag.txt && python app.py"]
