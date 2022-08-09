#!/usr/bin/env python3
import argparse
import binascii
import ipaddress
import re
import subprocess
import sys
import json


class ParamBase:

    def __init__(self, key, name, value):
        self._key = key
        self._name = name
        self._value = value

    @property
    def key(self):
        return self._key

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return f'{self.name}={str(self)}'

    def __str__(self):
        return binascii.hexlify(self._value).decode()

    def to_json(self):
        return {
            'name': self.name,
            'value': self.value_json()
        }

    def value_json(self):
        return binascii.hexlify(self._value).decode()


class ParamMandatory(ParamBase):
    KEY = 0

    def __init__(self, value):
        super().__init__(key=self.KEY, name='mandatory', value=value)


class ParamALPN(ParamBase):
    KEY = 1

    @classmethod
    def parse_protocols(cls, value):
        protos = []
        while len(value) > 0:
            plen = int(value[0])
            value = value[1:]
            protos.append(value[0:plen].decode())
            value = value[plen:]
        return protos

    def __init__(self, value):
        super().__init__(key=self.KEY, name='alpn', value=value)
        self._protocols = ParamALPN.parse_protocols(value)

    def __str__(self):
        return f"\'{', '.join(self._protocols)}\'"

    def value_json(self):
        return self._protocols.copy()


class ParamNoDefaultALPN(ParamBase):
    KEY = 2

    def __init__(self, value):
        super().__init__(key=self.KEY, name='no-default-alpn', value=value)
        self._protocols = ParamALPN.parse_protocols(value)

    def __str__(self):
        return ', '.join(self._protocols)

    def value_json(self):
        return self._protocols.copy()


class ParamPort(ParamBase):
    KEY = 3

    def __init__(self, value):
        super().__init__(self.KEY, name='port', value=value)

    def __str__(self):
        return str(int(self.value))

    def value_json(self):
        return int(self.value)


class ParamIPv4Hint(ParamBase):
    KEY = 4

    def __init__(self, value):
        super().__init__(key=self.KEY, name='ipv4hint', value=value)
        assert len(value) % 4 == 0

    def __str__(self):
        return f"\'{self.value_json()}\'"

    def value_json(self):
        addrs = []
        v = self.value
        i = 0
        while i < len(v):
            addrs.append(str(ipaddress.IPv4Address(v[i:i+4])))
            i += 4
        return addrs


class ParamIPv6Hint(ParamBase):
    KEY = 6

    def __init__(self, value):
        super().__init__(key=self.KEY, name='ipv6hint', value=value)
        assert len(value) % 16 == 0

    def __str__(self):
        return f"\'{self.value_json()}\'"

    def value_json(self):
        addrs = []
        v = self.value
        i = 0
        while i < len(v):
            addrs.append(str(ipaddress.IPv6Address(v[i:i+16])))
            i += 16
        return addrs


class ECHConfigBlob:

    def __init__(self, version, data):
        self._version = version
        self._data = data

    def __str__(self):
        return f'UnknownECHConfigContent(version={self._version}, ' \
               f'data={binascii.hexlify(self._data)})'

    def __repr__(self):
        return str(self)

    def to_json(self):
        return {
            'version': self._version,
            'data': binascii.hexlify(self._data),
        }


class HpkeKeyConfig:

    KEM_ID_NAMES = {
        0x0010: 'P-256',
        0x0011: 'P-384',
        0x0012: 'P-521',
        0x0020: 'X25519',
        0x0021: 'X448',
    }

    @classmethod
    def kem_name(cls, kemid):
        if kemid in cls.KEM_ID_NAMES:
            return cls.KEM_ID_NAMES[kemid]
        return f'{kemid:0x}'

    def __init__(self, data):
        self._data = data
        self._id = data[0]
        data = data[1:]
        self._kem_id = int.from_bytes(data[0:2], byteorder='big')
        data = data[2:]
        self._pubkey_len = int.from_bytes(data[0:2], byteorder='big')
        data = data[2:]
        self._pubkey = data[0:self._pubkey_len]
        data = data[self._pubkey_len:]
        self._suites_len = int.from_bytes(data[0:2], byteorder='big')
        data = data[2:]
        self._suites = data[0:self._suites_len]
        self._data_len = 1 + 2 + 2 + self._pubkey_len + 2 + self._suites_len

    @property
    def data_len(self):
        return self._data_len

    def __str__(self):
        return f'KeyConfig[id={self._id}, kem={self.kem_name(self._kem_id)}, ' \
               f'pubkey[{len(self._pubkey)}]={binascii.hexlify(self._pubkey)}, ' \
               f'cipher_suites={binascii.hexlify(self._suites)}]'

    def to_json(self):
        return {
            'id': self._id,
            'kem': self.kem_name(self._kem_id),
            'pubkey': binascii.hexlify(self._pubkey).decode(),
            'suites': binascii.hexlify(self._suites).decode(),
        }


class ECHConfigContents:

    @classmethod
    def parse(cls, version, data):
        return ECHConfigContents(version, data)

    def __init__(self, version, data):
        self._version = version
        self._data = data
        self._key_config = HpkeKeyConfig(data)
        data = data[self._key_config.data_len:]
        self._max_name_len = data[0]
        data = data[1:]
        l = data[0]
        data = data[1:]
        self._pub_name = data[0:l].decode()
        data = data[l:]
        exts_len = int.from_bytes(data[0:2], byteorder='big')
        data = data[2:]
        self._exts = data[0:exts_len]

    def __str__(self):
        return f'ECHConfigContent(version={self._version:0x}, ' \
               f'{self._key_config}, ' \
               f'max_name_len={self._max_name_len}, ' \
               f'public_name={self._pub_name}, ' \
               f'extensions={binascii.hexlify(self._exts).decode()})'

    def __repr__(self):
        return str(self)

    def to_json(self):
        jval = {
            'version': self._version,
            'pub_name': self._pub_name,
            'key': self._key_config.to_json(),
            'max_name_len': self._max_name_len,
        }
        if len(self._exts) > 0:
            jval['extensions'] = binascii.hexlify(self._exts).decode()
        return jval


class ParamECH(ParamBase):
    KEY = 5

    @classmethod
    def parse_config(cls, version, data):
        if version == 0xfe0d:
            return ECHConfigContents.parse(version, data)
        return ECHConfigBlob(version, data)

    def __init__(self, value):
        super().__init__(key=self.KEY, name='ech', value=value)
        self._configs = []
        conf_len = int.from_bytes(value[0:2], byteorder='big')
        value = value[2:]
        if conf_len > len(value):
            raise Exception(f"ECH param has invalid length")
        while len(value) > 0:
            conf_version = int.from_bytes(value[0:2], byteorder='big')
            value = value[2:]
            l = int.from_bytes(value[0:2], byteorder='big')
            value = value[2:]
            if l < len(value):
                raise Exception(f"ECH param config length invalid")
            self._configs.append(self.parse_config(conf_version, value[0:l]))
            value = value[l:]

    def __str__(self):
        return f'{self._configs}'

    def value_json(self):
        return [ c.to_json() for c in self._configs]


class HTTPSRecord:

    KnownParams = [
        ParamMandatory,
        ParamALPN,
        ParamNoDefaultALPN,
        ParamPort,
        ParamIPv4Hint,
        ParamECH,
        ParamIPv6Hint
    ]

    @classmethod
    def _make_param(cls, key, data):
        for pclass in cls.KnownParams:
            if pclass.KEY == key:
                return pclass(data)
        return ParamBase(key=key, name=f'0x{key}', value=data)

    @classmethod
    def parse_type65(cls, data):
        priority = int.from_bytes(data[0:2], byteorder='big')
        data = data[2:]
        labels = []
        while True:
            label_len = int(data[0])
            data = data[1:]
            if label_len == 0:
                break
            labels.append(data[0:label_len].encode())
            data = data[label_len:]
        pub_name = '.'.join(labels)
        params = []
        while len(data) > 0:
            key_idx = int.from_bytes(data[0:2], byteorder='big')
            data = data[2:]
            plen = int.from_bytes(data[0:2], byteorder='big')
            data = data[2:]
            param = cls._make_param(key_idx, data[0:plen])
            data = data[plen:]
            params.append(param)
        return HTTPSRecord(priority=priority, pub_name=pub_name, params=params)

    @classmethod
    def dig(cls, hostname):
        args = ['dig', '+short', '+split=0', hostname, 'type65']
        rv = subprocess.run(args=args, capture_output=True, text=True, shell=False)
        records = []
        for line in rv.stdout.splitlines():
            if len(line) == 0 or line.startswith(';'):
                continue
            m = re.match(r'^\\#\s+(?P<length>\d+)\s+(?P<hexdata>.+)$', line)
            if m:
                data = binascii.unhexlify(m.group('hexdata'))
                assert int(m.group('length')) == len(data)
                records.append(cls.parse_type65(data))
        return records

    def __init__(self, priority, pub_name, params):
        self.priority = priority
        self.pub_name = pub_name
        self.params = params

    def __repr__(self):
        return f'HTTPSRecord[priority={self.priority}, ' \
               f'pub_name={self.pub_name}, params={self.params}]'

    def to_json(self):
        obj = {
            'priority': self.priority,
        }
        if self.pub_name:
            obj['pub_name'] = self.pub_name
        pjson = {}
        for p in self.params:
            pjson[p.name] = p.value_json()
        obj['params'] = pjson
        return obj


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='dns_https', description="""
        mess with HTTPS records (Type 65) in DNS
        """)
    parser.add_argument("-j", "--json", default=False, action='store_true',
                        help="output record in JSON format")
    parser.add_argument('dns_name', help="DNS name to look up")

    args = parser.parse_args()
    recs = HTTPSRecord.dig(args.dns_name)
    if len(recs) == 0:
        sys.stderr.write(f'{args.dns_name}: no HTTPS record found.\n')
        sys.exit(1)
    if args.json:
        jrecs = [r.to_json() for r in recs]
        if len(jrecs) == 1:
            json.dump(jrecs[0], sys.stdout, indent=2)
        else:
            json.dump(jrecs, sys.stdout, indent=2)
        print('')
    else:
        for r in recs:
            print(f'{args.dns_name}: {r}')
    sys.exit(0)
