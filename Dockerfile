# Test environment only: no display forwarding, scanning, or production service.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
RUN apt-get update && apt-get install -y --no-install-recommends libegl1 libgl1 libopengl0 libxkbcommon0 libxcb-cursor0 libdbus-1-3 libmagic1 libpango-1.0-0 libpangoft2-1.0-0 nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN python -m pip install uv==0.12.24 && uv sync --locked --extra dev --extra build
RUN python scripts/build_worker_wheel.py && python -m venv /opt/toolkit-scapy && cd worker && /opt/toolkit-scapy/bin/python -m pip install --require-hashes -r requirements-provision.txt
RUN useradd --create-home --uid 10001 toolkit && chown -R toolkit:toolkit /app
USER toolkit
ENV QT_QPA_PLATFORM=offscreen
ENV TOOLKIT_TEST_WORKER=/opt/toolkit-scapy/bin/python
CMD ["uv", "run", "--no-sync", "pytest", "-q"]
