FROM python:3.7-stretch

RUN addgroup --system uwsgi \
    && adduser --system --disabled-password --home /var/cache/uwsgi \
    --shell /sbin/nologin --ingroup uwsgi uwsgi

WORKDIR /app

ADD requirements.txt /
RUN pip --no-cache-dir install -r /requirements.txt

ADD rootfs/ /

EXPOSE 8080
ENV UWSGI_THREADS=10
ENV UWSGI_PROCESSES=2
ENV UWSGI_OFFLOAD_THREADS=10
ENV UWSGI_MODULE=authorizer:app

CMD ["uwsgi", "--ini", "/etc/uwsgi/uwsgi.ini", "--pyargv", "-c /etc/jwt-authorizer/authorizer.cfg"]
