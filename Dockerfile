
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data ./data
COPY scripts ./scripts
COPY streamlit_app.py .
COPY supervisord.conf .

EXPOSE 8000 8501

CMD ["supervisord", "-n", "-c", "/app/supervisord.conf"]
