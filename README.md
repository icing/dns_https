# dns_https

messing with HTTPS records in DNS since...2022.

This is a little Python tool that allows one to view HTTPS records (Type 65) in DNS. Example:

```
> ./dns_https.py -j cloudflare.com
{
  "priority": 1,
  "params": {
    "alpn": [
      "h3", "h3-29", "h2"
    ],
    "ipv4hint": [
      "104.16.132.229", "104.16.133.229"
    ],
    "ipv6hint": [
      "2606:4700::6810:84e5", "2606:4700::6810:85e5"
    ]
  }
}
```

## How does it work?

`dns_https.py` just invokes `dig +short +split=0 dns_name type65` and parses the record. HTTPS records in DNS are a blob, so what dig returns in the example above is:

```
> dig +short +split=0 cloudflare.com type65
\# 67 0001000001000C0268330568332D323902683200040008681084E5681085E500060020260647000000000000000000681084E5260647000000000000000000681085E5
```

and I found that hard to read. There are probably lots of other tools out there that can analyze this, but I wanted to learn its internals, so I wrote this tool to dissect it.

## Where is it defined?

[dnsop-svcb-https-08](https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-08.html) is the draft I looked at. This refers to other RFCs and drafts. For example, the [draft for Encrypted Client Hellos](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-13#section-4) is also connected to this.

## Encrypted Client Hellos?

That TLS feature (in planning) is of interest to me. It will up your security on the internet by a bit by preventing
people to snoop on what sites you visit. The anti-snoop tech is, simplistically, the encryption of the important things you ask a server about. Like the site name, for example.

So, people can visit an abortion/press freedom/taiwan web site and the only thing your Internet Provider sees is that you are talking to Cloudflare (or Akamai or Fastly, etc.). 

In order to get this working, a "public key" needs to be distributed. `HTTPS` records in DNS is one proposal on how to do that. There is an example site for ECH which uses that:

```
> ./dns_https.py -j tls-ech.dev
{
  "priority": 1,
  "params": {
    "ech": [
      {
        "version": 65037,
        "pub_name": "public.tls-ech.dev",
        "key": {
          "id": 43,
          "kem": "X25519",
          "pubkey": "015881d41a3e2ef8f2208185dc479245d20624ddd0918a8056f2e26af47e2628",
          "suites": "0001000100010003"
        },
        "max_name_len": 64
      }
    ]
  }
}
```



