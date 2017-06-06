# meshub

A lightweight full-mesh VPN

## Goals

* mesh connectivity with O(n²) direct client-to-client NAT-traversal edges
* IPv6 *inside* the VPN
* untrusted and unstable central hub
	* assumed to be in the cloud, on someone else's computer, etc.
	* complete exposure should not affect confidentiality of other nodes' communications
	* if it goes down, the network must keep working (but new clients may not be able to join)
* no packet forwarding through hub or nodes
	* there are only direct peer-to-peer connections
	* of course, OS-level routing always works
* client-to-client edges encrypted using a PSK
	* clients are trusted and can impersonate each other
    * it would be nice to have an assymetric system with a CA that would fix this
* Linux & OS X support
	* OSX needs [the tuntap driver](http://tuntaposx.sourceforge.net/)

## Synopsis

### Hub

```bash
$ ./hub.py [-a address=0.0.0.0] [-p port=3731]
```

* No special privileges needed.
* Almost no functionality.
* Not part of the network -- it just mediates NAT traversal.
* Needs a public IP address.

### Client

```bash
$ sudo ./client.py client.cfg
```

* Requires root to create the TUN interface and set up routing.
* Advertises itself to all other clients via the hub.
* Creates direct mesh edges to all other clients.
* Encrypts traffic using the provided PSK.

### Generate a PSK

```bash
$ ./generate_fernet_key.py
--your-key-in-urlsafe-base64--
```

Put the key into the variable named `psk` in config section `encryption`.

## Related projects

Other mesh VPNs worth checking out:
* [peervpn](https://peervpn.net/)
	* my choice until recently, very easy to configure and get running
	* requires PSK to be present in cleartext on the hub node
* [tinc](https://tinc-vpn.org/)
	* assymetric crypto
	* won't work when the central node goes down (v1.0 at least)
	* there's v1.1 but I haven't tried it
* [freelan](https://freelan.org/)
	* PSK or CA
	* does not seem to create everyone-to-everyone mesh automatically

## Dependencies

* Python 3
* [cryptography](https://pypi.python.org/pypi/cryptography)

## License

[MIT](https://github.com/ziman/meshub/blob/master/LICENSE).

## Wishlist/TODO

* assymetric crypto
* a status command that would print all edges and their detailed diagnostics
    * generally a RPC
* ICMP inside VPN
    * for unroutable hosts etc.
* log level config option
* make hub listen on multiple addresses (and send responses to all of them)
* drop privileges after opening sockets & ifaces
* a performant (but secure) symmetric encryption
    * currently using `Fernet` from `cryptography` which should be foolproof but it's not very fast
