ARG IMAGE_NAME_EHSM_BASE
ARG EHSM_VERSION_STR

FROM ${DOCKER_REPO}${DOCKER_REPO:+/}$IMAGE_NAME_EHSM_BASE:$EHSM_VERSION_STR

# Install go package
WORKDIR /usr/local
RUN wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    && tar -zxf go1.22.0.linux-amd64.tar.gz \
    && rm -rf go1.22.0.linux-amd64.tar.gz \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc \
    && echo 'export GOPATH=$HOME/go' >> /root/.bashrc \
    && echo 'export PATH=$PATH:$GOPATH/bin' >> /root/.bashrc \
    && . /root/.bashrc
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=$HOME/go
ENV PATH=$PATH:$GOPATH/bin

WORKDIR /home/ehsm/ehsm_grpc_service/service
RUN go build
# COPY start_grpc-server.sh /home/
# RUN chmod 744 /home/start_grpc-server.sh

EXPOSE 50051

CMD [ "./service" ]
# CMD ["sh", "/home/start_grpc-server.sh"]