FROM google/cloud-sdk:slim

RUN apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN chmod +x src/runner.sh runbooks/*.sh

ENV PORT=8080

CMD ["/app/src/runner.sh"]
