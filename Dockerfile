FROM ubuntu:20.04

# Prevent timezone interaction
RUN apt update -y && apt upgrade -y && apt install tzdata -y && ln -fs /usr/share/zoneinfo/US/Pacific-New /etc/localtime && dpkg-reconfigure -f noninteractive tzdata

# System upgrade and install hugo and node
RUN apt install hugo npm vim -y

# Create the website boilerplate
WORKDIR /opt/
RUN hugo new site scannellio
WORKDIR /opt/scannellio

# Install the theme
RUN git init && git clone https://github.com/panr/hugo-theme-terminal.git themes/terminal 
WORKDIR /opt/scannellio/themes/terminal
RUN npm install
WORKDIR /opt/scannellio


# Copy the configuration
RUN rm config.toml
COPY config.toml config.toml

# Copy the actual site content
COPY ./static/ ./static/
COPY ./content/ ./content/

ENTRYPOINT hugo server --bind 0.0.0.0 --appendPort=false -p 80 --minify --noTimes --baseURL https://scannell.io
