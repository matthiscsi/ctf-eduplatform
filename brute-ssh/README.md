# SSH Brute Force Challenge

This container runs an SSH server with a user that has weak credentials.

## Challenge

- **Username**: ctfuser
- **Password**: ??? (You need to find this!)
- **Flag location**: `/home/ctfuser/flag.txt`

## Tools to try

- `hydra` - Fast network login cracker
- `ncrack` - High-speed network authentication cracking tool
- `medusa` - Speedy, parallel, modular login brute-forcer
- `nmap --script ssh-brute` - Nmap's SSH brute force script

## Wordlists

Try common wordlists like:
- `/usr/share/wordlists/rockyou.txt`
- `/usr/share/wordlists/fasttrack.txt`
- `/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt`
