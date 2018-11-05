import hashlib ############# This program is made for Ubuntu 14.04.5
import os, os.path

count = 0
total = 0
output = open("vulnfiles.txt", "w")

nmap = ["dfffcdf98c181bcae13150170250ec85"]
ncat = ["2bd82f46244f19a9ba52805aa524c624","2880733f8710bf85fb7742ca2a142495"]
hacking_tools = ["2004d20aa459a71345782cf73b72d6da", "07847c062bfad918fced76d9f646e1a8", "692ad992586be73092f0b2de568ce43e",
"7dd53fce53cb4c85db5453b0d5c8aeb0","9a62ad3334d8785d02eb5f19bea1ab4c", "1d0868c924aa87fb3b6de1fe72a64b16",
"b35b341620e716a174bbd95bb00f1c66", "96496e145a355f6e33fa7c775da3c2b3", "492aa6ceb21b705059739eab23ca0d45",
"9005be75c3747e049b433b83b9137b44", "d6f3125c4299560e3072cac59b97993f", "aa36403abee866281f461b8c1a5c4cc7",
"ced6a4a4dabfc37fa2e454be08227e25", "278360341e743a44082210fe32142368", "e60e1896c621b137e7c381bdb34234e4",
"b5f49fdab1b27b72fec69f755109c4d6", "6a7cc473d451d472cdabc01780c2ce0a", "ae9e239c190693899161731a78118ee5",
"975566230adc640586e579e3019e42bf", "399bc86131b0ad903966eb5946e61521", "212ab16e7bde430fc83870d7d23b66fa",
"d4f41c3e3d5114938f48c86e47468d82", "bd0a277dc25d195a0bd3253ea0728075", "51b20117392c47675009281a67d2e63d",
"1b2d165e9f6b423eace00798d3e3ed19", "7c9411c3dc722dd1b8dad7a77ad401e7", "487ff63504869a82a20997dba3713708",
"5a6a9863f375a4affa9f763ed22cc6a0", "debc4f67f107b854b18740486ff2d4c8", "a254df85a09fe31d96e3dc84baa90404",
"c8cfdb7a43bac95b3f8bf7c1b233323e"]

nmap = set(nmap)
ncat = set(ncat)
hacking_tools = set(hacking_tools)

vulns = [nmap, ncat, hacking_tools]

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

for root, _, files in os.walk("/"):
	for f in files:
		total = total + 1
print(total)	
for root, _, files in os.walk("/"):
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
