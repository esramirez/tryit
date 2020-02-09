from python:3.7.6

COPY . /app

RUN pip install
RUN python3 tryit.py