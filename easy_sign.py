import hashlib
import argparse
import ed25519
import binascii

def genkey():
	signing_key, verifying_key = ed25519.create_keypair()
	open("root_signing.key","wb").write(signing_key.to_bytes())
	open("root_signing.seed","wb").write(signing_key.to_seed())
	vkey_hex = verifying_key.to_ascii(encoding="hex")
	print "the public key is", vkey_hex
	pass

def verify_sig(sig_in, hash_in):
	keydata = open("root_signing.seed","rb").read()
	signing_key = ed25519.SigningKey(keydata)
	verifying_key = signing_key.get_verifying_key()
	try:
  		verifying_key.verify(sig_in, hash_in, encoding="hex")
		print "signature is good"
	except ed25519.BadSignatureError:
		print "signature is bad!"
	pass

def sign_hash(hash_in):
	print('Signing '+hash_in)
	keydata = open("root_signing.key","rb").read()
	signing_key = ed25519.SigningKey(keydata)
	seed = open("root_signing.seed","rb").read()
	signing_key2 = ed25519.SigningKey(seed)
	sig = signing_key.sign(hash_in, encoding="hex")
	print "sig is:", sig
	verify_sig(sig, hash_in);
	write_ticket(signing_key.get_verifying_key().to_ascii(encoding="hex"), sig, hash_in);
	pass

def create_hash(file):
	sha256_hash = hashlib.sha256()
	with open(file,"rb") as f:
	    # Read and update hash string value in blocks of 4K
	    for byte_block in iter(lambda: f.read(4096),b""):
	        sha256_hash.update(byte_block)
	    return sha256_hash.hexdigest()
	pass


def write_ticket(publickey, signature, hashin):
	final = ''
	final += binascii.unhexlify(hashin)
	final += binascii.unhexlify(publickey)
	final += binascii.unhexlify(signature)
	open("os.ticket","wb").write(final)
	pass

def make_padding(val):
	ret = '';
	for x in range(val):
		ret += '\0'
		pass
	return ret;

def stitch_image(inputImage, ticketFile):
	image = open(inputImage, "rb").read()
	ticket = open(ticketFile, "rb").read()
	esi = 'ESBI'
	esi += make_padding(int("0x1C", 16))
	esi += ticket
	esi += make_padding(int("0x50", 16))
	esi += 'DATA'
	esi += make_padding(int("0xC", 16))
	esi += image
	open('esi.bin', "wb").write(esi)
	pass

def Dump(n): 
  s = '%x' % n
  if len(s) & 1:
    s = '0' + s
  return s.decode('hex')
  
def combine_files(bootloaderFile, mainosFile):
    original = open(bootloaderFile, "r")
    stage1Buffer = original.read()

    qemuFile = open("stitched_image.bin", "wb+")
    qemuFile.write(stage1Buffer);

    original.close();

    currentOffset = qemuFile.tell()
    diff = 0x8000 - currentOffset
    if currentOffset > 0x8000:
        print "Stage 1 image too large for our scheme!"
        return 0

    i = 0
    while i < diff:
        qemuFile.write(Dump(0xFF));
        i += 1

    mainOS = open(mainosFile, "r")
    mainOSBuffer = mainOS.read()

    qemuFile.write(mainOSBuffer);
    qemuFile.close();
    pass 

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--sign', type=str, nargs='?')
	parser.add_argument('--generate', action="store_true")
	parser.add_argument('--stitch', type=str, nargs='?')
	parser.add_argument('--ticket', type=str, nargs='?')
	parser.add_argument('--bootloader', type=str, nargs='?')
	args = parser.parse_args()
	if args.generate:
		genkey()
		pass
	if args.sign is not None:
		filename = args.sign
		cHash = create_hash(filename)
		sign_hash(cHash);
		pass
	if args.stitch is not None:
		if args.ticket is not None:
			print 'stitching image!'
			stitch_image(args.stitch, args.ticket)
			combine_files(args.bootloader, "esi.bin")
			pass
		else:
			print "--ticket must be set with --stitch!\n"
			pass
		pass
	pass

if __name__ == '__main__':
	main()