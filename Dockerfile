FROM python:3.13-slim

# The pool and dashboard use only the standard library; the optional AI assistant needs anthropic, and
# tzdata gives the dashboard the world's time zones (the slim image has none).
RUN pip install --no-cache-dir anthropic==1.8.0 tzdata==2025.2

WORKDIR /app
COPY src/ /app/
RUN python -m compileall -q /app

# MALLOC_ARENA_MAX: glibc gives each thread its own memory pool, and the dashboard's many threads left
# ~150 MB of freed memory in them; two pools keep freed memory reused instead.
ENV PYTHONUNBUFFERED=1 MALLOC_ARENA_MAX=2
EXPOSE 3333 3380 8099
CMD ["python", "/app/pool.py"]
