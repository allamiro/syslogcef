FROM gcr.io/oss-fuzz-base/base-builder-python
RUN git clone --depth 1 https://github.com/allamiro/syslogcef.git syslogcef
WORKDIR syslogcef
COPY build.sh $SRC/
