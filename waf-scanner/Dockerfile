from ubuntu:latest

RUN apt-get update && apt-get install python3-pip -y
RUN pip3 install PyYAML nats-py --break-system-packages

RUN mkdir /out
COPY waf-scanner/code /code
COPY common/samma_finding /code/samma_finding
COPY VERSION /VERSION
COPY config.yaml /config.yaml

RUN useradd -ms /bin/bash samma
RUN chown samma:samma /out
RUN chown -R samma:samma /code
RUN chmod 664 /code/*.py

USER samma

RUN chmod +x /code/scan.py

CMD python3 /code/scan.py
