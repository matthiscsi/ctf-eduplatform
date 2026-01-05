FROM docker:24-dind

# Simulated "host" flag that should be exfiltrated via bind-mount breakout
RUN mkdir -p /root && echo "CTF{host_root_pwn}" > /root/host-flag.txt

# The entrypoint from docker:dind will start dockerd; we add no extra layers here.