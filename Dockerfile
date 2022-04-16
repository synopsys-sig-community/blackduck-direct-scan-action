FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

# Install python3 & pip
RUN apt-get update && apt-get upgrade -y && apt-get install -y python3-pip

# Install bdscanaction
# RUN pip3 install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple blackduck-scan-action
COPY dist/*.whl /root/dist/
RUN pip3 install /root/dist/*.whl

# Install npm & Java
RUN apt install -y npm && apt install -y openjdk-8-jre-headless curl

# Install Maven
ARG MAVEN_VERSION=3.6.3
ARG USER_HOME_DIR="/root"
ARG BASE_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries
RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
 && curl -fsSL -o /tmp/apache-maven.tar.gz ${BASE_URL}/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
 && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
 && rm -f /tmp/apache-maven.tar.gz \
 && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn
ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

# Install Dotnet
RUN curl https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb --output /tmp/packages-microsoft-prod.deb
RUN dpkg -i /tmp/packages-microsoft-prod.deb && apt-get install -y libc6 libgcc1 libgssapi-krb5-2 libicu66 libssl1.1 libstdc++6 zlib1g
RUN apt-get update \
 && apt-get install -y apt-transport-https \
 && apt-get update \
 && apt-get install -y dotnet-sdk-5.0

# scan-action specific
WORKDIR /app
#
ENTRYPOINT ["blackduck-scan-directguidance"]
CMD ["--help"]
