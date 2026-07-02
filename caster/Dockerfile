FROM gcc:14-bookworm AS builder

RUN apt update && apt install cmake libcyaml-dev libjson-c-dev libevent-dev libyaml-dev libssl-dev libzstd-dev -y

COPY . /app
WORKDIR /app

RUN mkdir -p log && touch log/caster.log
RUN cmake -S . -B $(pwd)/build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON
RUN cmake --build $(pwd)/build


FROM scratch

USER 1000

ENTRYPOINT ["/app/caster"]
COPY --from=builder --chown=1000 /app/log/caster.log /var/log/millipede/caster.log
COPY --from=builder --chown=1000 /app/sample-config/ /usr/local/etc/millipede/
COPY --from=builder /app/build/caster /app/caster
