#!/usr/bin/env python3

from cryptography.fernet import Fernet
print(Fernet.generate_key().decode('ascii'))
