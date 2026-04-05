FROM gcr.io/oss-fuzz-base/base-builder-python

RUN apt-get update && apt-get install -y python3-dev

# Clone the project source (OSS-Fuzz builds from the oss-fuzz repo,
# not the project repo, so we must git-clone here).
RUN git clone --depth 1 https://github.com/0ai-Cyberviser/Hancock $SRC/hancock

WORKDIR $SRC/hancock

COPY build.sh $SRC/
