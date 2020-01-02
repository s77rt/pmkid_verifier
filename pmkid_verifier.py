import hashlib, binascii, hmac
from pbkdf2 import PBKDF2

def verify_pmkid(pmkid, essid, mac_ap, mac_sta, passphrase, hashcat_format=False):
	# Clean inputs:
	mac_ap = str(mac_ap).replace(':', '').replace('-', '').lower()
	mac_sta = str(mac_sta).replace(':', '').replace('-', '').lower()
	# Convert to bytes
	try:
		b_mac_ap = (binascii.unhexlify(mac_ap))
		b_mac_sta = (binascii.unhexlify(mac_sta))
	except:
		return False
	# Compute PMKID
	pmk = PBKDF2(str(passphrase), str(essid), 4096).read(32)
	computed_pmkid = hmac.new(pmk, b"PMK Name"+b_mac_ap+b_mac_sta, hashlib.sha1).hexdigest()
	computed_pmkid = str(computed_pmkid[:32])
	## hashcat format
	if hashcat_format:
		computed_pmkid = computed_pmkid+'*'+mac_ap+'*'+mac_sta+'*'+str(essid.encode().hex())
	# Compare:
	if computed_pmkid == str(pmkid).lower():
		return True
	return False

def main():
	pmkid = input("PMKID: ")
	essid = input("ESSID: ")
	mac_ap = input("MAC-AP: ")
	mac_sta = input("MAC-STA: ")
	passphrase = input("Passphrase: ")
	if len(pmkid) > 32:
		hashcat_format = True # Probably (else, that is an invalid pmkid)
	else:
		hashcat_format = False
	if verify_pmkid(pmkid, essid, mac_ap, mac_sta, passphrase, hashcat_format):
		print("OK!")
	else:
		print("NOT OK!")

if __name__ == '__main__':
	main()
