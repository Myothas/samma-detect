# Base: python:3.13-slim-bookworm (3.13.17), pinned by the digest of its
# multi-arch index on 2026-10-24. All nine Dockerfiles carry the same pin. To
# bump it, run `docker buildx imagetools inspect python:3.13-slim-bookworm`
# and copy the top-level Digest into every FROM line (README, "Base image").
FROM python:3.13-slim-bookworm@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY http-headers-scanner/code/requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir -r /code/requirements.txt

# The code is owned by root and read-only to the scanner. The shared package
# is copied in next to it so `import samma_finding` resolves from /code.
COPY http-headers-scanner/code /code
COPY common/samma_finding /code/samma_finding
COPY VERSION /VERSION
COPY config.yaml /config.yaml

# The operator runs every scanner with runAsUser 1000, so the samma user is
# created with that uid and gid explicitly. /out is the only writable path
# besides the home directory.
RUN groupadd -g 1000 samma \
 && useradd -m -u 1000 -g 1000 -s /bin/bash samma \
 && install -d -o 1000 -g 1000 /out

ENV HOME=/home/samma
USER 1000:1000

CMD ["python3", "/code/scan.py"]
