FROM python:3.7-stretch as build

RUN pip install mypy
WORKDIR /app
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD . /app
RUN mypy -m authorizer --strict

FROM python:3.7-stretch

RUN addgroup --system uwsgi \
    && adduser --system --disabled-password --home /var/cache/uwsgi \
    --shell /sbin/nologin --ingroup uwsgi uwsgi

WORKDIR /app
ADD requirements.txt .
RUN pip --no-cache-dir install -r requirements.txt
ADD rootfs/ /
ADD . /app

EXPOSE 8080
ENV UWSGI_THREADS=10
ENV UWSGI_PROCESSES=2
ENV UWSGI_OFFLOAD_THREADS=10
ENV UWSGI_MODULE=authorizer.wsgi:app

CMD ["uwsgi", "--ini", "/etc/uwsgi/uwsgi.ini"]
