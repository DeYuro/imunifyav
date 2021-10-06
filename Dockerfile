FROM centos/systemd

WORKDIR /home/test
VOLUME /var/www/ /test/www


RUN \
    yum update -y && \
    yum install wget -y
RUN mkdir -p /etc/sysconfig/imunify360
ADD integration.conf /etc/sysconfig/imunify360/

ADD imav-deploy.sh .
RUN bash imav-deploy.sh


CMD ["/usr/sbin/init"]