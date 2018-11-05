import hashlib
import os, os.path

count = 0
total = 0
output = open("vulnfiles.txt", "w")

nmap = ["cb6a1aa59fab3185347fa0e7c1d1f502", "ad4fda7575c0e648ce20fb390cb43d0d"]
ncat = ["eb330a7e2e51122976d75853f913d084", "5dcf26e3fbce71902b0cd7c72c60545b", "523613a7b9dfa398cbd5ebd2dd0f4f38",
	"e0db1d3d47e312ef62e5b0c74dceafe5", "470797a25a6b21d0a46f82968fd6a184", "ab41b1e2db77cebd9e2779110ee3915d", "94a1c655ba93be5a0205af99ac513f4e"
]
wireshark = ["2e0210246fbf557bb32669feab768640", "923440a7226bed2f521fbf69f2c7d0a5"]
hacking_tools = ["f24e8173d18171bcce29f6952380eb7c","9df53ddc13d751d6ed1f514cac364bf6","50f05297b231d92ca7a8911f851ce38e",
	"80dfbab8966c81588b7b15704c9ec648", "687838d8a9edb3d4854c8e23a66dde9f", "171bb98e82f17a60723813d72d36d77c",
	"4e91ac0d6b6fda7b31b4c0dc5bec696a", "9f3efdd4b51ea128d657fbb56420b787", "291277d0b3e2a173823b6fb020a9b61a"
]
keyloggers = ["9dc0108618bc60abc2e9b630b9c55f05", "440e1d7d4c1c03c5481433633935bac0", "acb7f57c560692b2c20a24c9dcc7e609", "78b7a2e2bf40de88e6da2867d65e16da"]

nmap = set(nmap)
ncat = set(ncat)
wireshark = set(wireshark)
hacking_tools = set(hacking_tools)
keyloggers = set(keyloggers)

vulns = [nmap, ncat, wireshark, hacking_tools, keyloggers]

def md5(fname): ## Have to read 4096 bit chunks to feed into md5 function
	hash_md5 = hashlib.md5()
	try: ## Just in case there is no permissions to access
		with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				hash_md5.update(chunk)
		return hash_md5.hexdigest()
	except:
		return ""

def hasHash(h):
	for hashset in vulns:
			for hash in hashset:
				if hash == h:
					return True
	return False

for root, _, files in os.walk("C:\\"):
	for f in files:
		total = total + 1
	
for root, _, files in os.walk("C:\\"):
	for f in files:
		count = count + 1
		fullpath = os.path.join(root, f)
		filehash = md5(fullpath)
		if hasHash(filehash):
			print(fullpath)
			output.write(fullpath+"\n")
		if count % 1000 == 0:
			print(str(count) + "/" + str(total))

output.close()