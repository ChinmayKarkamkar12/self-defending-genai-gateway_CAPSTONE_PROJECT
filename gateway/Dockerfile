FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
# CPU-only torch first, so `torch==2.8.0` in requirements.txt is already satisfied.
# The default Linux PyPI wheel bundles CUDA (~2.5GB) that this image can't
# use without a GPU runtime anyway; CPU inference is ~160ms/request (see
# training/README.md).
# --retries/--timeout: the build pulls ~1GB from several hosts; a dropped
# connection should retry, not fail the whole build. The spaCy model comes
# in through requirements.txt as a pinned wheel (see the comment there).
RUN pip install --no-cache-dir --retries 10 --timeout 60 \
    torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
COPY scripts ./scripts

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
