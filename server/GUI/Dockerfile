FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y openssh-client
RUN apt-get update && apt-get install -y iputils-ping
RUN pip install --no-cache-dir -r requirements.txt

CMD ["gunicorn", "-w", "4", "-k", "gevent", "-b", "0.0.0.0:5000", "app:app", "--access-logfile", "-", "--timeout", "3600", "--keep-alive", "3600"]
