# Use an official Ubuntu as a base image
FROM ubuntu:latest

# Install necessary dependencies
RUN apt-get update && \
    apt-get --assume-yes install \
    apt-utils \
    systemd \
    python3 \
    python3-pip \
    net-tools \
    sudo \
    nmap \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=$PATH:/snap/bin

# Set the working directory to /app
WORKDIR /app

# Copy all files from the current directory and its subdirectories to the container
COPY . .

# Install pymetasploit3 using pip
RUN pip3 install pymetasploit3
RUN pip3 install msgpack
RUN pip3 install retry
RUN pip3 install requests

EXPOSE 55553

# Run the setup.sh script
# RUN chmod +x setup.sh
# RUN ./setup.sh

# Run the main.py script
CMD ["python3", "main.py"]