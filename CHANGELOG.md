# Changelog
1.0.2 (2024-04-30)

**Améliorations ou changements/Implemented enhancements or changes:**

- Nothing new

**Correction de bugs/Fixed bugs:**

- Starting Debian 12 Bookworm (running OpenSSH_9.2) only the rsa-sha2-512, rsa-sha2-256 server host key algorithms are available by default: force to keep the old RSA key challenge compatibility (temporary)
- In case of using the same public IPv4 address, removing the old offending RSA key in /root/.ssh/known_hosts
- We lower the scan speed to avoid being banned (OVH)
- The transitional package "netcat" (Debian 11) was dropped from Debian 12: we need to explicitly choose which netcat implementation we want ("netcat-openbsd" in our case)
