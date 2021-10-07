FROM centos/systemd

WORKDIR /home/test

RUN mkdir -p /etc/sysconfig/imunify360
ADD integration.conf /etc/sysconfig/imunify360/

ADD imav-deploy.sh .
RUN bash imav-deploy.sh


CMD ["/usr/sbin/init"]