FROM ubuntu:20.04

# System upgrade and install hugo
RUN apt update && apt upgrade -y && apt install hugo -y

# Create the website boilerplate
WORKDIR /opt/
RUN hugo new site scannellme
WORKDIR /opt/scannellme

# Install the theme
#RUN git init && git submodule add https://github.com/lxndrblz/anatole.git themes/anatole
RUN git init && git submodule add https://github.com/uPagge/uBlogger.git themes/ublogger

# Copy the configuration
RUN rm config.toml
COPY config.toml config.toml

# Copy the actual site content
COPY ./static/ ./static/
COPY ./content/ ./content/

ENTRYPOINT hugo server --bind 0.0.0.0 --port 1337
