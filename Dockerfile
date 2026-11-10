# docker build -t owltriage .
# docker run --rm -v "$PWD:/work" owltriage hunt --demo
# docker run --rm -v "$PWD:/work" -v /var/log:/logs:ro owltriage hunt /logs/auth.log
FROM python:3.12-slim
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY owltriage ./owltriage
RUN pip install --no-cache-dir ".[evtx]" && useradd --create-home --uid 10001 triage
USER triage
WORKDIR /work
ENTRYPOINT ["owltriage"]
CMD ["--help"]
