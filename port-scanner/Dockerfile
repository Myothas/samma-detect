from ubuntu:latest

RUN apt-get update && apt-get install python3-pip -y
RUN pip3 install PyYAML nats-py --break-system-packages

RUN mkdir /out
COPY port-scanner/code /code
COPY common/samma_finding /code/samma_finding
COPY VERSION /VERSION
COPY config.yaml /config.yaml

# The base image ships an "ubuntu" user at uid 1000, so an unpinned useradd
# would give samma uid 1001. The operator runs every scanner with runAsUser 1000.
RUN (userdel -r ubuntu || true) && (groupdel ubuntu || true) \
 && groupadd -g 1000 samma && useradd -m -u 1000 -g 1000 -s /bin/bash samma
RUN chown samma:samma /out
RUN chown -R samma:samma /code
RUN chmod 664 /code/*.py

ENV HOME=/home/samma
USER 1000:1000

RUN chmod +x /code/scan.py

CMD python3 /code/scan.py
