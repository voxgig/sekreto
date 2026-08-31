# A real boru vault, served over boru's own wire protocol.
#
# There is no boru mock anywhere in this repository and there should not
# be one: boru's wire protocol ships inside the same binary its CLI does,
# so a mock would test the imitation. That rule is why this file exists -
# to run the real thing, the binary is built from source here.
#
# The build needs network access to fetch boru and its Go dependencies.
# Where that is not available, the boru checks skip rather than fake.

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build

ARG BORU_REF=main

RUN apk add --no-cache git

WORKDIR /src
# No fallback to the default branch. A BORU_REF that does not resolve is a
# typo or a tag that moved, and quietly building main instead would make a
# targeted compatibility run green against code nobody asked about.
RUN git init -q . \
  && git remote add origin https://github.com/boru-lang/boru \
  && git fetch --depth 1 origin "${BORU_REF}" \
  && git checkout -q FETCH_HEAD

# The CLI is its own Go module under cmd/go; the repository root is not one.
RUN go build -o /out/boru ./cmd/go/boru

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=build /out/boru /usr/local/bin/boru
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh

# The vault, the capability token, and the readiness marker all live here.
# The harness reads the token back out with `docker compose exec`.
WORKDIR /work

EXPOSE 8308

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
