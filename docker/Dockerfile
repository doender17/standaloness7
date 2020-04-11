FROM java:8-jdk-alpine
ENV MAVEN_VERSION 3.5.4
ENV MAVEN_HOME /usr/lib/mvn
ENV PATH $MAVEN_HOME/bin:$PATH

RUN apk update && apk add bash && apk add git && \
    mkdir /usr/buildenv && \
    cd /usr/buildenv && \
    git clone https://github.com/doender17/jss7.git && \
    git clone https://github.com/doender17/sctp.git && \
    git clone https://github.com/doender17/standaloness7.git && \
    wget http://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz && \
    tar -zxvf apache-maven-$MAVEN_VERSION-bin.tar.gz && \
    rm apache-maven-$MAVEN_VERSION-bin.tar.gz && \
    mv apache-maven-$MAVEN_VERSION /usr/lib/mvn
RUN cd /usr/buildenv/sctp && \
    mvn install -DskipTests && \
    cd /usr/buildenv/jss7 && \
    mvn install -DskipTests && \
    cd /usr/buildenv/standaloness7 && \
    mvn compile test package
ENTRYPOINT ["/bin/bash"]
