# docker build -t bluetriage .
# docker run --rm -v "$PWD:/work" bluetriage hunt --demo
# docker run --rm -v "$PWD:/work" -v /var/log:/logs:ro bluetriage hunt /logs/auth.log
FROM python:3.12-slim
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY bluetriage ./bluetriage
RUN pip install --no-cache-dir ".[evtx]" && useradd --create-home --uid 10001 triage
USER triage
WORKDIR /work
ENTRYPOINT ["bluetriage"]
CMD ["--help"]
