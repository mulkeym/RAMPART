FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

RUN mkdir -p data logs && cp -r policies policies-default

EXPOSE 8080 8443

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "rampart.app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
