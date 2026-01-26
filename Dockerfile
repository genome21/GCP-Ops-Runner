FROM google/cloud-sdk:slim

RUN apt-get update && apt-get install -y jq python3-pip && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

# Install Python dependencies
RUN pip3 install --no-cache-dir flask gunicorn google-cloud-tasks

RUN chmod +x src/runner.sh runbooks/*.sh

ENV PORT=8080
ENV PYTHONUNBUFFERED=1

CMD ["/app/src/runner.sh"]
