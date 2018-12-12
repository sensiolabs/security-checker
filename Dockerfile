FROM composer:latest

# add unpriviledged user and 
# create directory for the code to be scanned
RUN addgroup -S tool && adduser -S -G tool tool && \
    mkdir -p /opt/mount/

# Install security-checker
WORKDIR /tmp
RUN wget https://get.sensiolabs.org/security-checker.phar && \
    chmod +x security-checker.phar

# change user
USER tool

ENTRYPOINT [ "/tmp/security-checker.phar", "security:check", "/opt/mount/"]
