import hashlib ############# This program is made for Debian 7.6 gnome-desktop
import os, os.path

count = 0
total = 0
output = open("vulnfiles.txt", "w")

nmap = ["b60081126cd5e789962f6757594ed605"]
ncat = ["36250698d3ad7b0c572cab937b6297d1", "baab2f25dbd300ef3b4483e28668ae69"]
hacking_tools = ["7dd53fce53cb4c85db5453b0d5c8aeb0", "9a62ad3334d8785d02eb5f19bea1ab4c",
"1d0868c924aa87fb3b6de1fe72a64b16", "b35b341620e716a174bbd95bb00f1c66", "492aa6ceb21b705059739eab23ca0d45",
"9005be75c3747e049b433b83b9137b44", "d6f3125c4299560e3072cac59b97993f", "aa36403abee866281f461b8c1a5c4cc7",
"ced6a4a4dabfc37fa2e454be08227e25", "c6b0a982ab63db880c8b6e4d0e373c08", "1c1d93e89f9c8de6563e3ba9ee74f293",
"494f7f2ef8a22adbd4143f20f2141c0c", "17f6571db20d839dc887699af5333e46", "161074b0c870da8192df1c471de0483b",
"f58fbfd9097dd62e06d4972a2263c599", "9c9922ac5545112c964f91bfc5dcd4cb", "6a97bbec868b21e08d3829a3431278a9",
"7b2ef3c1797ff65788a92c390a665c15", "09fc68a026f4dcbb174516ca0004b68c", "55126dcf2b447a3af1639b4292109abb",
"6322d903108ac6963005f679d57a8170", "dcb5652df843f51ab881d75a9c0e7f09", "8a77b98be3ecda2119b764c68c19fdd7",
"73fcf8afd41256a36974d92633061170", "c8cfdb7a43bac95b3f8bf7c1b233323e", "af8069be078c61560234f66f00f716bb"]

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
		if count % 10 == 0:
			print(str(count) + "/" + str(total))

output.close()
