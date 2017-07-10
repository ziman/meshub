#!/usr/bin/env python3

import base64

try:
    from cryptography.fernet import Fernet
    print('fernet key:', Fernet.generate_key().decode('ascii'))
    something_worked = True
except ImportError:
    print('for a fernet key, install `cryptography`')

try:
    import nacl.utils
    import nacl.secret
    print('nacl key:', base64.b64encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode('ascii'))
except ImportError:
    print('for a nacl key, install `pynacl`')
