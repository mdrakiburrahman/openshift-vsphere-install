
#-------------------------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
#-------------------------------------------------------------------------------------------------------------

# Note: You can use any Debian/Ubuntu based image you want. Using the microsoft base Ubuntu image.
FROM mcr.microsoft.com/vscode/devcontainers/base:focal

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Version lists: 
# Terraform: https://github.com/hashicorp/terraform/releases

ARG TF_Version="1.1.5"
ARG GO_VERSION="1.16.7"
ARG HELM_VERSION=3.6.3
ARG OC_VERSION="4.10.17"

# Configure apt and install packages
RUN apt-get update \
    && apt-get -y install --no-install-recommends apt-utils dialog 2>&1 \
    && apt-get -y install git iproute2 procps bash-completion

# Install the Azure CLI && aks-preview extension
RUN apt-get install -y apt-transport-https gnupg2 lsb-release \
    && echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/azure-cli.list \
    && curl -sL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - 2>/dev/null \
    && apt-get update \
    && apt-get install -y azure-cli=2.35.0-1~focal \
    && az extension add -n aks-preview

# Add Azure CLI extensions
RUN az config set extension.use_dynamic_install=yes_without_prompt

# Install Helm
RUN mkdir -p /tmp/downloads/helm \
    && curl -sL -o /tmp/downloads/helm.tar.gz https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz \
    && tar -C /tmp/downloads/helm -zxvf /tmp/downloads/helm.tar.gz \
    && mv /tmp/downloads/helm/linux-amd64/helm /usr/local/bin

# Install Golang
# https://www.digitalocean.com/community/tutorials/how-to-install-go-on-ubuntu-20-04
RUN curl -OL https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin  

# Install Terraform
RUN apt-get install -y \
    wget \
    unzip \
  && rm -rf /var/lib/apt/lists/*
RUN wget --quiet https://releases.hashicorp.com/terraform/${TF_Version}/terraform_${TF_Version}_linux_amd64.zip \
  && unzip terraform_${TF_Version}_linux_amd64.zip \
  && mv terraform /usr/bin \
  && rm terraform_${TF_Version}_linux_amd64.zip

# Install Linux stuff
RUN apt-get update \
    && apt-get install tree -y \
    && apt-get install make -y \
    && apt-get install asciinema -y \
    && apt-get install tmux -y \
    && apt-get install graphviz -y \
    && apt-get install dnsutils -y \
    && apt-get install ldap-utils -y

# Install yq
# Latest on https://launchpad.net/~rmescandon/+archive/ubuntu/yq is v4.25.1
ARG VERSION=v4.25.1
ARG BINARY=yq_linux_386
RUN wget https://github.com/mikefarah/yq/releases/download/${VERSION}/${BINARY} -O /usr/bin/yq \ 
    && chmod +x /usr/bin/yq

# Install OpenShift CLI
RUN apt-get install ca-certificates -y
RUN wget https://rakirahman.blob.core.windows.net/public/binaries/oc-${OC_VERSION}-linux.tar.gz && \
    mkdir -p /opt/oc && \
    mv oc-${OC_VERSION}-linux.tar.gz /opt/oc/release.tar.gz && \
    tar xvzf /opt/oc/release.tar.gz -C /opt/oc && \
    mv /opt/oc/oc /usr/local/bin/ && \
    mv /opt/oc/kubectl /usr/local/bin/ && \
    rm -rf /opt/oc && \
    chmod +x /usr/local/bin/oc && \
    chmod +x /usr/local/bin/kubectl

# Install VMWare govc
RUN curl -L -o - "https://github.com/vmware/govmomi/releases/latest/download/govc_$(uname -s)_$(uname -m).tar.gz" | tar -C /usr/local/bin -xvzf - govc

# Install ArgoCD CLI
RUN curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64 && \
    chmod +x /usr/local/bin/argocd

# Install Kubeseal
RUN wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.14.1/kubeseal-linux-amd64 -O kubeseal && \
    sudo install -m 755 kubeseal /usr/local/bin/kubeseal

# Clean up
RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/downloads

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Startup
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD [ "sleep", "infinity" ]