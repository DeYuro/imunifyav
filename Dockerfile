FROM ubuntu:20.04

WORKDIR /home/install
ENV DEBIAN_FRONTEND noninteractive

RUN \
    apt-get update -y && \
    apt-get install -y wget && \
    apt-get install -y gnupg

RUN wget -O RPM-GPG-KEY-CloudLinux https://repo.imunify360.cloudlinux.com/defense360/RPM-GPG-KEY-CloudLinux
RUN apt-key add RPM-GPG-KEY-CloudLinux

RUN echo "deb [arch=amd64] https://repo.imunify360.cloudlinux.com/imunify360/ubuntu/20.04/ focal main" \
        > /etc/apt/sources.list.d/imunify360.list
RUN apt-get update -y

#alt python deps
RUN \
      apt-get install -y alt-curl && \
      apt-get install -y alt-python38  && \
      apt-get install -y alt-python38-aiohttp && \
      apt-get install -y alt-python38-cerberus && \
      apt-get install -y alt-python38-daemon && \
      apt-get install -y alt-python38-humanize && \
      apt-get install -y alt-python38-lockfile && \
      apt-get install -y alt-python38-peewee && \
      apt-get install -y alt-python38-peewee-migrate && \
      apt-get install -y alt-python38-psutil && \
      apt-get install -y alt-python38-yaml && \
      apt-get install -y alt-python38-sentry-sdk && \
      apt-get install -y alt-python38-setuptools && \
      apt-get install -y alt-python38-pam && \
      apt-get install -y alt-python38-pyjwt && \
      apt-get install -y alt-python38-urllib3 && \
      apt-get install -y alt-python38-urllib3 && \
      apt-get install -y alt-python38-distro && \
      apt-get install -y alt-sqlite && \
      apt-get install -y alt-tmpreaper && \
      apt-get install -y alt-sqlite

# common deps
RUN \
    apt-get install -y logrotate && \
    apt-get install -y psmisc && \
    apt-get install -y zip && \
    apt-get install -y lsof && \
    apt-get install -y openssl

# imunify stuff
RUN \
    apt-get install -y imunify-common && \
    apt-get install -y imunify-notifier

RUN wget https://repo.imunify360.cloudlinux.com/imunify360/ubuntu/20.04/pool/main/a/ai-bolit/ai-bolit_31.0.3-1_amd64.deb
RUN wget https://repo.imunify360.cloudlinux.com/imunify360/ubuntu/20.04/pool/main/i/imunify-antivirus/imunify-antivirus_5.10.1-2_amd64.deb


RUN dpkg -x ai-bolit_31.0.3-1_amd64.deb ./aibolit
RUN dpkg -x imunify-antivirus_5.10.1-2_amd64.deb ./imunify


RUN rm -rf ./aibolit/lib #remove systemd
RUN rm -rf ./imunify/lib #remove systemd

RUN cp -R ./aibolit/* /
RUN cp -R ./imunify/* /

RUN apt-get install -y php7.4
RUN imunify-antivirus update # get sigs

RUN cp /var/imunify360/files/sigs/v1/aibolit/ai-bolit-hoster-full.db /opt/ai-bolit/

ENTRYPOINT ["sleep", "infinity"]