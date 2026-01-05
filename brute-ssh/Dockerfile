FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Create SSH directory
RUN mkdir /var/run/sshd

# Create CTF user with weak password
RUN useradd -m -s /bin/bash ctfuser && \
    echo "ctfuser:password123" | chpasswd

# Allow password authentication
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Create flag file
ENV FLAG="CTF{brute_force_victory}"
RUN echo "${FLAG}" > /home/ctfuser/flag.txt && \
    chown ctfuser:ctfuser /home/ctfuser/flag.txt && \
    chmod 400 /home/ctfuser/flag.txt

# Create a hint file
RUN echo "Welcome to the SSH Brute Force Challenge!" > /home/ctfuser/README.txt && \
    echo "" >> /home/ctfuser/README.txt && \
    echo "The flag is in this directory. Can you read it?" >> /home/ctfuser/README.txt && \
    echo "" >> /home/ctfuser/README.txt && \
    echo "Hint: The username is 'ctfuser' and the password is weak." >> /home/ctfuser/README.txt && \
    echo "Try using tools like hydra, ncrack, or medusa!" >> /home/ctfuser/README.txt && \
    chown ctfuser:ctfuser /home/ctfuser/README.txt

# Expose SSH port
EXPOSE 22

# Start SSH daemon
CMD ["/usr/sbin/sshd", "-D"]
