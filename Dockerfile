# docker build -t owltriage .
# docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" owltriage hunt --demo
# docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" owltriage hunt auth.log access.log
# --user lets the container write ./owltriage-output as you; logs are read from the current folder.
FROM python:3.12-slim
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY owltriage ./owltriage
RUN pip install --no-cache-dir ".[evtx]" && useradd --create-home --uid 10001 triage
USER triage
WORKDIR /work
ENTRYPOINT ["owltriage"]
CMD ["--help"]
