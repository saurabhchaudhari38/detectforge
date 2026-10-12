FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 detectforge
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY rules /opt/detectforge/rules
USER detectforge
WORKDIR /data
ENTRYPOINT ["detectforge"]
CMD ["--help"]
