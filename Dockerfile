FROM ubuntu:20.04

# System upgrade and install hugo
RUN apt update && apt upgrade -y && apt install hugo -y

# Create the website boilerplate
WORKDIR /opt/
RUN hugo new site scannellme
WORKDIR /opt/scannellme

# Install the theme
RUN git init && git submodule add https://github.com/theNewDynamic/gohugo-theme-ananke.git themes/ananke



