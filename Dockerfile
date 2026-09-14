FROM python:3.13-slim AS checked
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY rapido/ ./rapido/
COPY tests/ ./tests/
RUN python -m unittest discover -s tests -v

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=checked /app/rapido/ ./rapido/
USER 65532:65532
ENTRYPOINT ["python", "-m", "rapido"]
CMD ["demo"]
