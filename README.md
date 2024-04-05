# wireguard-show-clients
Shows wireguard clients names with traffic + online/offline (info from last handshake)

Language: python. Based on config created by https://github.com/Nyr/wireguard-install

/etc/wireguard/wg0.conf syntax should be like

```
# BEGIN_PEER CLIENT_NAME
[Peer]
PublicKey = XXX
PresharedKey = xxx
AllowedIPs = xxx
# any other lines here
# END_PEER CLIENT_NAME
```
Test at Ubuntu Server 22.04.4 LTS

Script output should looks like:
```
CLIENT NAME 1| RX: 34.05 GB   |  TX: 534.47 MB  | 0m ago
CLIENT NAME 2 | RX: 13.12 GB   |  TX: 904.05 MB  | 1m ago
CLIENT NAME 3 | RX: 1.52 GB    |  TX: 779.95 MB  | 0m ago
CLIENT NAME 4 | RX: 1.54 GB    |  TX: 302.7 MB   | 0m ago
CLIENT NAME 5 | RX: 242.89 MB  |  TX: 81.8 MB    | 0m ago

Offline:

OFFLINE_CLIENT    8h 8m ago
OFFLINE_CLIENT    1d 0h 22m ago
OFFLINE_CLIENT    1d 8h 50m ago
OFFLINE_CLIENT    2d 9h 20m ago
OFFLINE_CLIENT
OFFLINE_CLIENT
```

Information automactically updates every 2 seconds
For any questions contact my tg: @ishr00m
