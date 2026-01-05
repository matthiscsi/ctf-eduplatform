FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV FLAG="CTF{ssrf_metadata_leak}"

CMD ["python", "app.py"]
