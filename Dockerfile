# Test environment only: no display forwarding, scanning, or production service.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libegl1 libopengl0 libxkbcommon0 libxcb-cursor0 libdbus-1-3 libmagic1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN python -m pip install uv==0.12.24 && uv sync --locked --extra dev --extra build
ENV QT_QPA_PLATFORM=offscreen
CMD ["uv", "run", "--no-sync", "pytest", "-q"]
