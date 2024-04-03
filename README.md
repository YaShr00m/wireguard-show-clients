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
CLIENT_NAME1:      RX: 4.64 GB    , TX: 327.09 MB  2 мин. назад
CLIENT_NAME2:      RX: 869.96 MB  , TX: 47.22 MB   0 мин. назад
CLIENT_NAME3:      RX: 774.86 MB  , TX: 33.36 MB   1 мин. назад
CLIENT_NAME4:      RX: 85.94 MB   , TX: 29.89 MB   1 мин. назад
CLIENT_NAME5:      RX: 87.34 MB   , TX: 17.68 MB   2 мин. назад

Offline:

CLIENT_NAME6
CLIENT_NAME7 (last seen 15 min ago)
```
