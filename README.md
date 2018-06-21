## NodeJS ARP Request (ping)

This module allows you to send an ARP request and catch the response. In the response you'll get
the hardware address of the target and the round trip time.

### Install

```sh
npm i arping
```

### Usage

```js
const arp = require("arping");

arp.ping("192.168.0.1", (err, info) => {
	if (err) throw err; // Timeout, ...
	// THA = target hardware address
	// TIP = target IP address
	console.log("%s (%s) responded in %s secs", info.tha, info.tip, info.elapsed);
});
```
