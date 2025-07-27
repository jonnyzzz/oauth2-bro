FROM golang:1.24-alpine3.22 AS BUILD_CONTAINER
ARG BUILD_NUMBER=SNAPSHOT
RUN apk add build-base

RUN mkdir /oauth2-bro /oauth2-bro-bin
COPY ./* /oauth2-bro/
WORKDIR /oauth2-bro

RUN cd /oauth2-bro && ls -lah . && go get
RUN cd /oauth2-bro && ls -lah . && go test
RUN cd /oauth2-bro && ls -lah . && go build -ldflags="-X 'main.version=${BUILD_NUMBER}'" -o /oauth2-bro-bin/oauth2-bro

FROM alpine:3.22
COPY --from=BUILD_CONTAINER /oauth2-bro-bin/** /oauth2-bro/

# curl for docker healthcheck
RUN apk add --update curl && rm -rf /var/cache/apk/*

RUN addgroup -g 990 app &&  \
    adduser -S -D -H -G app -u 990 app && \
    chown -R 990:990 /tmp  &&  \
    chmod -R u+rw,g+rw /tmp &&  \
    chmod g+s /tmp
USER 990

ENV OAUTH2_BRO_ADDR 0.0.0.0:8077
EXPOSE 8077
ENTRYPOINT ["/oauth2-bro/oauth2-bro"]
