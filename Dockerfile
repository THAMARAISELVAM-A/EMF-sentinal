FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/sensor.py .

ENV PORT=8765
ENV WS_PORT=8766

EXPOSE 8765 8766

CMD ["python", "sensor.py"]
