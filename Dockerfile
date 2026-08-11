FROM python:3.13-alpine

LABEL org.opencontainers.image.title="syslogcef" \
      org.opencontainers.image.description="Convert syslog events to ArcSight CEF" \
      org.opencontainers.image.source="https://github.com/allamiro/syslogcef" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="Tamir Suliman <allamiro@gmail.com>"

COPY . /src
RUN pip install --no-cache-dir /src && rm -rf /src

# 65534 is "nobody"; numeric so runtimes can verify non-root (DL3066)
USER 65534:65534
ENTRYPOINT ["syslogcef"]
