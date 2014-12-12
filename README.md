ampdefend
=========

###Defend DNS attacks based on repeating
Set of configs and scripts to defend from DNSAMP attacks. Mostly cover it's "repeating" type &mdash; request the same record (set) over and over again. 

<blockquote>Usuallyan ANY query is used. An ANY query returns all the records for a specific domain name regardless of the record type. When sent to a recursive server, the server will only return the records that it has cached. The server will have to reply, regardless of available recursion. This is currently the most common attack because the ANY request usually returns a large collection of resource records, creating a high amplification ratio.</blockquote>


Based on two things:

1. BIND config enable RRL (Response Rate Limit) and SLIP (switch client to TCP) in BIND and limit similar UPD requests per host. Tune it to adopt to your situation.

2. Script that check named.log for type of request mostly used to DNSAMP attacks and create DROP rules for that hosts. In some cases it can block some of query types for legitimate host, so if this is important to you - add this hosts to whitelist.
