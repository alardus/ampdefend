# That script check named.log for queries mostly popular for DNS AMP
# attacks and create iptables rules for blocking them.
#
# Run in through crontab to perform check in loop.
#

import os, syslog
base = [] # what we have at hostbase.txt
host = [] # hosts that was added to checklist 

# create new chain and put all traffic to 53 port through it
os.system("/sbin/iptables -N DNSAMP")
os.system("/sbin/iptables -I INPUT -p udp --dport 53 -j DNSAMP")
os.system("/sbin/iptables -I FORWARD -p udp --dport 53 -j DNSAMP")

# load list of banned hosts to 'base'
with open('./hostbase.txt', 'r') as hostbase:
	for i in hostbase:
		base.append(i.strip())

# looking for TXT, ANY, DNSKEY, NS, RRSIG requests in named.log
checklist = os.popen("cat /var/log/named.log | egrep 'ANY|TXT|DNSKEY|NS|RRSIG' | grep queries").readlines()
for i in checklist:
	qtype = i.split(" ")[10].strip()
	i = i.split(" ")[8].strip()
	print "Working on " + i

# check if this host exist in "hostbase" and if it's not - add it and ban
	if i not in host:
		if i not in base:
			print "CHECK: Not in hostbase, create a rule"
			rule = os.popen("./generate-netfilter-u32-dns-rule.py --qname " + i + " --qtype " + qtype).read()
			print rule
			os.system("/sbin/iptables -A DNSAMP -p udp --dport 53 --match u32 --u32 '"+rule+"' -j DROP")
			with open('./hostbase.txt', 'a') as hostbase:
				hostbase.write(i+'\n')
			print "Rule added to iptables DNSAMP chain.\n"
			host.append(i)
		else:
			print "CHECK: Found in hostbase, skipped.\n"
			pass
	else:
		print "CHECK: Added to checklist already\n"
		pass
