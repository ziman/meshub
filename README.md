# meshub

A lightweight mesh VPN

## Goals

* mesh connectivity with O(n²) client-to-client NAT-traversal edges
* untrusted central node -- if it's compromised, it shouldn't affect confidentiality
  of other nodes' communications
* unstable central node -- if it goes down, the network must keep working
    * but new clients may not be able to join
* no packet forwarding through nodes
* clients are trusted and can impersonate each other
    * (this may change in the future)
* client-to-client edges encrypted using a PSK
    * would be nice to have an assymetric system with a CA
* (eventually) IPv6 *inside* the VPN
    * almost working but I don't care enough just yet

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
* Creates O(n²) mesh edges to all other clients.
* Encrypts traffic using the provided PSK.

### Generate a PSK

```bash
$ ./generate_fernet_key.py
--your-key-in-urlsafe-base64--
```

Put the key into the variable named `psk` in config section `encryption`.

## Related projects

Other mesh VPNs worth checking out.

* [peervpn](https://peervpn.net/)
	* my choice until recently, very easy to configure and get running
	* requires PSK to be present in cleartext on the hub node
* [tinc](https://tinc-vpn.org/)
	* won't work when the central node goes down (v1.0 at least)
	* there's v1.1 but I haven't migrated
* [freelan](https://freelan.org/)
	* does not seem to create everyone-to-everyone mesh automatically

## Dependencies

* Python 3
* [cryptography](https://pypi.python.org/pypi/cryptography)

## Wishlist

* a status command that would print all edges and their detailed diagnostics
* ICMP inside VPN
* make ipv6 work properly
