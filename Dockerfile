FROM python
RUN apt-get update
RUN apt-get install -y nmap
RUN pip install schedule requests
RUN mkdir /app
WORKDIR /app