FROM centos:7
RUN yum install -y wget
RUN mkdir -p /etc/sysconfig/imunify360/ \
    && printf '[paths]\nui_path = /var/www/html/i360\n' > /etc/sysconfig/imunify360/integration.conf \
    && wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh \
    && /bin/bash imav-deploy.sh -y --skip-version-check
ENTRYPOINT ["bash", "-c", "I360_SOCKET_ACTIVATION=0  /usr/bin/imunify-service"]