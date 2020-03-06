FROM python:3.7-stretch

RUN addgroup --system uwsgi \
    && adduser --system --disabled-password --home /var/cache/uwsgi \
    --shell /sbin/nologin --ingroup uwsgi uwsgi

WORKDIR /app
RUN pip install --upgrade --no-cache-dir pip setuptools wheel
COPY requirements/main.txt ./requirements.txt
RUN pip --no-cache-dir install -r requirements.txt
COPY . /app
RUN pip install --no-cache-dir .
ADD rootfs/ /

EXPOSE 8080
ARG COMMIT=""
ARG COMMIT_DESCRIBE=""
ARG BRANCH=""

ENV COMMIT=$COMMIT
ENV COMMIT_DESCRIBE=$COMMIT_DESCRIBE
ENV BRANCH=$BRANCH

ENV UWSGI_THREADS=10
ENV UWSGI_PROCESSES=2
ENV UWSGI_OFFLOAD_THREADS=10
ENV UWSGI_MODULE=authorizer.wsgi:app

CMD ["uwsgi", "--ini", "/etc/uwsgi/uwsgi.ini"]
