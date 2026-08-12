FROM gcr.io/oss-fuzz-base/base-builder-python
RUN git clone --depth 1 https://github.com/allamiro/syslog2cef.git syslog2cef
WORKDIR syslog2cef
COPY build.sh $SRC/
