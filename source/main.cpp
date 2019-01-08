#include <cstring>
#include <string>
#include <iostream>
#include "crypto.h"
#include "tadpole.h"
#include "types.h"
#include "hash_stash.h"
//0x4000+0x20+0xF0+0x20+0x4E0+0x20+0xB40+0x20+0x00218800+0x20 = 0x21D9B0  

void error(const char *errormsg, const char *filename, bool fatal) {
	printf("%s:%s %s\nHit Enter to close\n", fatal ? "ERROR":"WARNING", errormsg, filename);
	getchar();
	if(fatal) exit(-1); 
}

u8 *readAllBytes(const char *filename, u32 &filelen) {
	FILE *fileptr = fopen(filename, "rb");
	if (fileptr == NULL) {
		error("Failed to open ", filename, true);
	}
	
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);
	
	if(filelen > 0x21E000) filelen=0x21E000; //keep dsiware buffer reasonable - some dsiwares can get really large and we don't need to go over flipnote injected DS dlp size

	u8 *buffer = (u8*)malloc(filelen);

	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(const char *filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename, "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
}

void dumpMsedData(u8 *msed){
	u32 keyy[4]={0};
	int mdata[3]={33,33,33};
	memcpy(keyy, msed+0x110, 0x10);
	mdata[0]=(keyy[0]&0xFFFFFF00) | 0x80;
	keyy[3]&=0x7FFFFFFF;
	
	mdata[1]=(keyy[0]/5) - keyy[3];
	if(keyy[1]==2) mdata[2]=3;
	else if(keyy[1]==0) mdata[2]=2;
	
	writeAllBytes("msed_data.bin", (u8*)mdata, 12);
}

void makeTad(char *filename, u32 ishax) {
	u8 *dsiware, *resources, *ctcert, *injection, *tmd, *banner, *movable;
	u32 dsiware_size, resources_size, ctcert_size, movable_size, injection_size, banner_size, tmd_size;
	u8 header_hash[0x20] = {0}, srl_hash[0x20] = {0}, tmp_hash[0x20] = {0}, tmd_hash[0x20]={0}, banner_hash[0x20]={0};
	u8 normalKey[0x10] = {0}, normalKey_CMAC[0x10] = {0};
	//char outfile[64]={0};
	header_t header_out;
	memset(&header_out, 0, 0xF0);

	printf("\nReading %s\n", filename);
	dsiware = readAllBytes(filename, dsiware_size);
	if (dsiware_size > 0x4000000) {
		error("Provided dsiware seems to be way too large!","", true);
	}
	
	printf("Reading & parsing movable.sed\n");
	movable = readAllBytes("movable.sed", movable_size);
	if (movable_size != 320 && movable_size != 288) {
		error("Provided movable.sed is not 320 or 288 bytes of size","", true);
	}
	
	printf("Reading resources/frogcertXL.bin\n");
	resources = readAllBytes(ishax ? "resources/frogcertXL.bin" : "resources/dlpcertXL.bin", resources_size);
	calculateSha256(resources, resources_size, tmp_hash);
	if (memcmp(tmp_hash, ishax ? frogcertXL_hash : dlpcertXL_hash, 0x20) != 0) {
		error("Provided resources file's hash doesn't match","", true);
	}
	
	injection = resources;
	injection_size = resources_size - 0x4CDE;
	banner = injection + injection_size;
	banner_size = 0x4000;
	tmd = banner + banner_size;
	tmd_size = 0xB40;
	ctcert = tmd + tmd_size;
	ctcert_size = 0x19E;
	
	if(ishax){ //only need to do this once
		printf("Dumping msed_data.bin\n");
		dumpMsedData(movable);
	}

	printf("Scrambling keys\n");
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	
	// === HEADER ===
	printf("Decrypting header\n");
	u8 *header = new u8[0xF0];
	getSection((dsiware + 0x4020), 0xF0, normalKey, header);
	
	if (memcmp("3FDT", header, 4)) {
		error("Decryption failed","", true);
	}
	
	printf("Writing new header data\n");
	header_out.magic=0x54444633; //"3FDT"
	header_out.group_id=0;
	header_out.version=0x400;
	memcpy(&header_out.sha256_ivs, header + 0x8, 0x20);
	memcpy(&header_out.aes_zeroblock, header + 0x28, 0x10);
	header_out.tid=0x00048005484E4441; //DS dlp
	header_out.installed_size=(injection_size+0x20000)&0xFFFF8000;
	header_out.content[0]=0xB34; //tmd size
	header_out.content[1]=injection_size; //srl size
	memcpy(&header_out.padding[0x50], "\x40\xE2\x09\x08\x60\xE2\x09\x08\x10", 9); //no idea what this crap is, but the 3ds wants it lol

	printf("Placing back header\n");
	placeSection((dsiware + 0x4020), (u8*)&header_out, 0xF0, normalKey, normalKey_CMAC);

	printf("Calculating new header hash\n");
	calculateSha256((u8*)&header_out, 0xF0, header_hash);
	delete[] header;

	// === SRL.NDS ===
	// Basically, the srl.nds of DS Download play is right at the end of the TAD container
	// Because we don't care about what it contains, we can overwrite it directly with our new
	// flipnote srl.nds straight off the bat, without having to do any decryption
	// We of course need to extend our dsiware array by the necessary difference in bytes
	// to accomodate the new flipnote srl.nds (which is 0x218800 in size)
	printf("Resizing array\n");
	printf("Old DSiWare size: %08X\n", dsiware_size);
	dsiware_size = injection_size + 0x51B0;
	printf("New DSiWare size: %08X\n", dsiware_size);
	dsiware = (u8*)realloc(dsiware, dsiware_size);
	printf("Placing back srl.nds\n");
	placeSection((dsiware + 0x5190), injection, injection_size, normalKey, normalKey_CMAC);

	printf("Calculating new srl, banner, and tmd hashes\n");
	calculateSha256(injection, injection_size, srl_hash);
	calculateSha256(banner, banner_size, banner_hash);
	calculateSha256(tmd, tmd_size, tmd_hash);
	
	// === BANNER ===
	placeSection((dsiware + 0x0), banner, banner_size, normalKey, normalKey_CMAC);
	
	// === TMD ===
	placeSection((dsiware + 0x4630), tmd, tmd_size, normalKey, normalKey_CMAC);

	// === FOOTER ===
	printf("Decrypting footer\n");
	footer_t *footer = (footer_t*)malloc(SIZE_FOOTER);
	getSection((dsiware + 0x4130), 0x4E0, normalKey, (u8*)footer);

	printf("Fixing hashes\n");
	memcpy(footer->banner_hash , banner_hash, 0x20); //Fix the banner hash
	memcpy(footer->hdr_hash , header_hash, 0x20); //Fix the header hash
	memcpy(footer->tmd_hash , tmd_hash, 0x20); //Fix the tmd hash
	memcpy(footer->content_hash[0], srl_hash, 0x20);	//Fix the srl.nds hash
	memset(footer->content_hash[1], 0, 0x20*9); //Zero out hashes we don't use for dlp

	printf("Signing footer with 0x%x byte ctcert file\n", ctcert_size);
	Result res = doSigning(ctcert, footer);
	if (res < 0) {
		error("Signing failed","", true);
	}
	
	printf("Placing back footer\n");
	placeSection((dsiware + 0x4130), (u8*)footer, 0x4E0, normalKey, normalKey_CMAC);
	
	const char *outname = ishax ? "output/hax/484E4441.bin" : "output/clean/484E4441.bin";

	printf("Writing %s\n", outname);
	writeAllBytes(outname, dsiware, dsiware_size);
	printf("Done!\n");
	
	printf("Cleaning up\n");
	free(footer);
	free(dsiware);
	free(resources);
	free(movable);
	printf("Done!\n");
}

int main(int argc, char* argv[]) {

	makeTad(argv[1], 1); //DS dlp injected with JPN flipnote v0
	makeTad(argv[1], 0); //DS dlp clean, intended for restoring title to prehax state
	printf("\nJobs completed\n");
	
	return 0;
}