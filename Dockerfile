FROM golang:1.24-alpine3.22 AS build_container
ARG BUILD_NUMBER=SNAPSHOT
RUN apk add build-base

RUN mkdir /oauth2-bro /oauth2-bro-bin
COPY . /oauth2-bro/
WORKDIR /oauth2-bro

# Build the application from the oauth2-bro subdirectory
RUN cd oauth2-bro && go mod download

# Run tests for all modules (automatically discover all go.mod files)
RUN find . -name "go.mod" -type f | while read -r modfile; do \
        module_dir=$(dirname "$modfile"); \
        echo "Testing module: $module_dir"; \
        cd "$module_dir" && go test ./... && cd /oauth2-bro; \
    done

RUN cd oauth2-bro && go build -ldflags="-X 'main.version=${BUILD_NUMBER}'" -o /oauth2-bro-bin/oauth2-bro

FROM alpine:3.22
COPY --from=build_container /oauth2-bro-bin/** /oauth2-bro/

# curl for docker healthcheck
RUN apk add --update curl && rm -rf /var/cache/apk/*

RUN addgroup -g 990 app &&  \
    adduser -S -D -H -G app -u 990 app && \
    chown -R 990:990 /tmp  &&  \
    chmod -R u+rw,g+rw /tmp &&  \
    chmod g+s /tmp
USER 990

ENV OAUTH2_BRO_BIND_HOST=0.0.0.0

EXPOSE 8077
ENTRYPOINT ["/oauth2-bro/oauth2-bro"]
