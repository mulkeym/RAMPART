FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

RUN mkdir -p data logs

EXPOSE 8080

CMD ["uvicorn", "rampart.app.main:app", "--host", "0.0.0.0", "--port", "8080"]
