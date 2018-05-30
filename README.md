# point-vpn

A lightweight point-to-point blockchaining VPN.
AKA Modified MeshHub


![Blockchain](https://i.imgur.com/j59VkI8.gif)


## Features / Design

* mesh connectivity with O(n²) direct client-to-client NAT-traversal edges
* IPv6 *inside* the VPN
	* IPv6 in WAN has a very low priority
* untrusted and unstable central hub with a public IPv4 address
	* assumed to be in the cloud, on someone else's computer, etc.
	* complete exposure should not affect confidentiality of other nodes' communications
	* if it goes down, the network must keep working
* no packet forwarding through hub or nodes
	* there are only direct peer-to-peer connections
	* of course, OS-level routing always works
* client-to-client edges encrypted symmetrically using a cipher-generating md5 blockchain for AES-CBC encryption.
    * it would be nice to have an assymetric system with a CA that would fix this
* Linux & OS X support
	* OSX needs [the tuntap driver](http://tuntaposx.sourceforge.net/)
* local host discovery using LAN broadcast

## Synopsis

### Hub

```bash
$ ./hub.py [-a address=0.0.0.0] [-p port=3731]
```

* No special privileges needed.
* Almost no functionality.
* Not part of the network -- it just mediates NAT traversal.
* Needs a public IP address. ***IMPORTANT***


### Client

```bash
$ sudo ./client.py client.cfg
```

* Requires root to create the TUN interface and set up routing.
* Advertises itself to all other clients via the hub.
* Creates direct edges
* Encrypts traffic using the provided seed, generates a new cipher every packet.


Make a key!!! It can be anything you choose for your seed.
Put the key into the variable named `psk` in config section `encryption`.


## Dependencies

* Python 3
* [cryptography](https://pypi.python.org/pypi/cryptography)

## License

[MIT](https://github.com/ziman/meshub/blob/master/LICENSE).

Note: your hub MUST have an external IP for correct STUN, unless you want to STUN your client by starting the client on the hub FIRST! It will look like this if you run the client on the hub!!

![Blockchain](https://i.imgur.com/Hd9bftk.gif)
