# Use slim Python base — smaller image, faster pull
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy only what we actually need — no venv, no garbage
COPY requirements.txt .
COPY main.py .
COPY modules/ ./modules/
COPY utils/ ./utils/

# Install dependencies — no cache bullshit
RUN pip install --no-cache-dir -r requirements.txt

# Default command — run main.py with arguments you pass
ENTRYPOINT ["python", "main.py"]