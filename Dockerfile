FROM php:7.4

COPY ./ai-bolit /opt/ai-bolit

WORKDIR /opt/ai-bolit

ENTRYPOINT ["sleep", "infinity"]