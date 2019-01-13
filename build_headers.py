import os,sys,hashlib
	
def hash(buf):
	obj=hashlib.sha256(buf)
	return obj.digest()
	
def buff2array(s):
	final=""
	for i in s:
		final+=",0x%02X" % ord(i)
	return final[1:]

d="resources\\int"
os.system("twlbannertool %s/int.banner.bin" % d)
os.system("twlbannertool %s/frog.banner.bin" % d)
os.system("copy /b %s\\frog.nds + %s\\int.nds + %s\\frog.banner.bin + %s\\int.banner.bin + %s\\tmd.bin + %s\\ctcert.bin resources\\fredcertXL.bin" % (d,d,d,d,d,d))

with open("resources/fredcertXL.bin","rb") as f:
	fred=f.read()
	
with open("include/hash_stash.h","w") as f:
	f.write("u8 fredcertXL_hash[] = {" + buff2array(hash(fred))+"}; //resources for flipnote injected and clean DS internet TAD\n") #sha256 should be (9D FA 74 E3 ...)