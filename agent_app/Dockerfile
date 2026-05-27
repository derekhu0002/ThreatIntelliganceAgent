FROM ghcr.io/anomalyco/opencode

RUN apk add --no-cache python3 \
    && python3 -m ensurepip \
    && python3 -m pip install --no-cache-dir neo4j \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

COPY start-opencode-with-warmup.sh /usr/local/bin/start-opencode-with-warmup.sh

RUN chmod +x /usr/local/bin/start-opencode-with-warmup.sh
