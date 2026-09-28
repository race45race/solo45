FROM python:3.13-slim

# The pool and dashboard use only the standard library; the optional AI assistant needs anthropic, and
# tzdata gives the dashboard the world's time zones (the slim image has none).
RUN pip install --no-cache-dir anthropic==1.8.0 tzdata==2025.2

WORKDIR /app
COPY src/ /app/
RUN python -m compileall -q /app

ENV PYTHONUNBUFFERED=1
EXPOSE 3333 3380 8099
CMD ["python", "/app/pool.py"]
