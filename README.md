# meshub

A lightweight mesh VPN

## Goals

* mesh connectivity with O(n^2) client-to-client NAT-traversal edges

* untrusted central node -- if it's compromised, it shouldn't affect confidentiality
  of other nodes' communications

* unstable central node -- if it goes down, the network must keep working
	* but new clients may not be able to join

* clients are trusted and can impersonate each other
	* (this may change in the future)

* client-to-client edges encrypted using a PSK

## Dependencies

* Python 3

* [cryptography](https://pypi.python.org/pypi/cryptography)

## Protocol

### Hub

* broadcasts everything it receives
	* including IP address + port where it saw the packet come from

### Clients

* advertise themselves to everyone else using the hub
* create O(n^2) mesh edges to other clients
