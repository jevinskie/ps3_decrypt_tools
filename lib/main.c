/*
* Copyright (c) 2011-2012 by ps3dev.net
* This file is released under the GPLv2.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "util.h"
#include "keys.h"
#include "eid.h"
#include "hdd.h"
#include "kgen.h"
#include "types.h"
#include "indiv.h"

void decrypt_hdd()
{
    u8 ata_k1[0x20], ata_k2[0x20], edec_k1[0x20], edec_k2[0x20];
  u32 size;

	//fetching root_key
	eid_root_key = _read_buffer((s8*)"data/eid_root_key", NULL);
	
	//Assuming sectors start with sector 0.
	u8 *sectors = _read_buffer((s8*)"data/sectors", &size);

	//Generate keys.
	generate_ata_keys(eid_root_key, eid_root_key + 0x20, ata_k1, ata_k2);
	generate_encdec_keys(eid_root_key, eid_root_key + 0x20, edec_k1, edec_k2);

	_hexdump(stdout, "ATA-DATA-KEY    ", 0, ata_k1, 0x20, 0);
	_hexdump(stdout, "ATA-TWEAK-KEY   ", 0, ata_k2, 0x20, 0);
	_hexdump(stdout, "ENCDEC-DATA-KEY ", 0, edec_k1, 0x20, 0);
	_hexdump(stdout, "ENCDEC-TWEAK-KEY", 0, edec_k2, 0x20, 0);

	//Decrypt all sectors.
	decrypt_sectors(sectors, 0, size, ata_k1, ata_k2, 1);

	// we should make better a fn() with sector_start, sector_size params, and also to make
	// 3rd arg the MIN() of "size", sector_size

	//Decrypt VFLASH sectors starting at sector 8.
	// decrypt_sectors(sectors+8*SECTOR_SIZE, 8, size - 8*SECTOR_SIZE, edec_k1, edec_k2, 0);
	decrypt_sectors(sectors+8*SECTOR_SIZE, 8, size - 8*SECTOR_SIZE, edec_k1, edec_k2, 0);

	//Decrypt GameOS (UFS2) sectors starting at sector 0x80010 (524304).
	decrypt_sectors(sectors+524304*SECTOR_SIZE, 524304, size - 524304*SECTOR_SIZE, ata_k1, ata_k2, 1);

	_write_buffer((s8*)"data/sectors_decrypted", sectors, size);

}

void decrypt_eid()
{	
	//fetching root_key
	eid_root_key = _read_buffer((s8*)"data/eid_root_key", NULL);
	
	//unpacking eid
	eid_unpack((s8*)"eid/eid");

	//decrypting
	eid0_decrypt((s8*)"eid/eid0",(s8*)"eid/eid0decrypted");
	eid1_decrypt((s8*)"eid/eid1",(s8*)"eid/eid1decrypted.bin");
	eid2_generate_block((s8*)"eid/eid2",EID2_BLOCKTYPE_P,(s8*)"eid/eid2pblock.bin",0x80);
	eid2_generate_block((s8*)"eid/eid2",EID2_BLOCKTYPE_S,(s8*)"eid/eid2sblock.bin",0x690);
	eid2_decrypt_block((s8*)"eid/eid2pblock.bin",0x80,(s8*)"eid/eid2pblockdec.bin");
	eid2_decrypt_block((s8*)"eid/eid2sblock.bin",0x690,(s8*)"eid/eid2sblockdec.bin");
	eid3_decrypt((s8*)"eid/eid3",(s8*)"eid/eid3decrypted.bin");
	eid4_decrypt((s8*)"eid/eid4",(s8*)"eid/eid4decrypted.bin");
}

void encrypt_eid0_section_A()
{	
	//fetching root_key
	eid_root_key = _read_buffer((s8*)"data/eid_root_key", NULL);
	
	//encrypting
	eid0_encrypt_section_A((s8*)"eid/eid0decrypted",(s8*)"eid/eid0encrypted");
}

void encrypt_hdd()
{
    u8 ata_k1[0x20], ata_k2[0x20], edec_k1[0x20], edec_k2[0x20];
	u32 size;
	
	//fetching root_key
	eid_root_key = _read_buffer((s8*)"data/eid_root_key", NULL);

	//Assuming sectors start with sector 0.
	u8 *sectors = _read_buffer((s8*)"data/sectors_decrypted", &size);

	//Generate keys.
	generate_ata_keys(eid_root_key, eid_root_key + 0x20, ata_k1, ata_k2);
	generate_encdec_keys(eid_root_key, eid_root_key + 0x20, edec_k1, edec_k2);

	_hexdump(stdout, "ATA-DATA-KEY    ", 0, ata_k1, 0x20, 0);
	_hexdump(stdout, "ATA-TWEAK-KEY   ", 0, ata_k2, 0x20, 0);
	_hexdump(stdout, "ENCDEC-DATA-KEY ", 0, edec_k1, 0x20, 0);
	_hexdump(stdout, "ENCDEC-TWEAK-KEY", 0, edec_k2, 0x20, 0);
	
	//Encrypt all sectors.
	encrypt_sectors(sectors, 0, size, ata_k1, ata_k2, 1);

	//Encrypt VFLASH sectors starting at sector 8.
	encrypt_sectors(sectors+8*SECTOR_SIZE, 8, size - 8*SECTOR_SIZE, edec_k1, edec_k2, 0);

	_write_buffer((s8*)"data/sectors_encrypted", sectors, size);

}

void syscon_auth()
{
	aes_context aes_ctxt;
	u8 indiv[0x40];
	u8 indiv_key[0x20];
	u8 zero_iv[0x10]={0};
	u8 enc_key_seed[INDIV_SIZE];
	
	//fetching root_key
	eid_root_key = _read_buffer((s8*)"data/eid_root_key", NULL);

	//Generate individuals.
	indiv_gen(eid1_indiv_seed, NULL, NULL, NULL, indiv);
	_write_buffer((s8*)"syscon/indiv", indiv, 0x40);
	
	//Generate seeds
	memcpy(indiv_key,indiv + 0x20,0x20);
	aes_setkey_enc(&aes_ctxt, indiv_key, KEY_BITS(0x20));
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, INDIV_SIZE, zero_iv, syscon_key_seed, enc_key_seed);
	_write_buffer((s8*)"syscon/enc_key_seed", enc_key_seed, INDIV_SIZE);
}

int main()
{
    int i;
    printf("Select an option\n1-Decrypt HDD\n2-Encrypt HDD\n3-Decrypt eEID(missing eid5)\n4-Decrypt ALL\n5-Generate Syscon AUTH seeds(Acording to wiki)\n6-Encrypt EID0 Section A\n0-Exit\n");
    scanf("%d",&i);
    switch(i)
    {
        case 1:
            decrypt_hdd();
            break;
        case 2:
			encrypt_hdd();
            break;
        case 3:
            decrypt_eid();
			break;
        case 4:
			decrypt_hdd();
			decrypt_eid();
			break;
		case 5:
			syscon_auth();
			break;
		case 6:
			encrypt_eid0_section_A();
			break;
		case 0:
            break;
        default:
            printf("Incorrect Option Selected! Try Again.");
			break;
    }
    return 0;
}
