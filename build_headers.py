import os,sys,glob,binascii,hashlib
	
def hash(buf):
	obj=hashlib.sha256(buf)
	return obj.digest()
	
def buff2array(s):
	final=""
	for i in s:
		final+=",0x%02X" % ord(i)
	return final[1:]

d="resources\\frog"
os.system("twlbannertool.exe %s/banner.bin" % d)
os.system("copy /b %s\\srl.nds + %s\\banner.bin + %s\\tmd.bin + %s\\ctcert.bin resources\\frogcertXL.bin" % (d,d,d,d))

d="resources\\dlp"
os.system("twlbannertool.exe %s/banner.bin" % d)
os.system("copy /b %s\\srl.nds + %s\\banner.bin + %s\\tmd.bin + %s\\ctcert.bin resources\\dlpcertXL.bin" % (d,d,d,d))

with open("resources/frogcertXL.bin","rb") as f:
	frog=f.read()
with open("resources/dlpcertXL.bin","rb") as f:
	dlp=f.read()
	
with open("include/hash_stash.h","w") as f:
	f.write("u8 frogcertXL_hash[] = {" + buff2array(hash(frog))+"}; //resources for flipnote injected DS dlp TAD\n")
	f.write("u8  dlpcertXL_hash[] = {" + buff2array(hash(dlp))+"}; //resources for clean DS dlp TAD\n")