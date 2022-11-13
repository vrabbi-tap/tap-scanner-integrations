FROM ubuntu
RUN apt-get update && \
    apt-get install -y wget curl git && \
    rm -rf /var/lib/apt/lists/*

RUN wget "http://stedolan.github.io/jq/download/linux64/jq" && chmod 755 jq && mv jq /usr/local/bin/jq \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && mkdir /workspace
COPY --from=registry.tanzu.vmware.com/tanzu-application-platform/tap-packages@sha256:60ce084d6d6fbfd83f642399a97ca329aa97d551dfdf9482e919eaa2f6d5c988 /usr/local/bin/krane /usr/local/bin/krane
COPY scan-image.sh scan-source.sh /usr/local/bin/
USER 65534:65533

