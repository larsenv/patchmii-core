/*  patchmii_core -- low-level functions to handle the downloading, patching
    and installation of updates on the Wii

    Copyright (C) 2008 bushing / hackmii.com

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ogcsys.h>
#include <gccore.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <network.h>
#include <sys/errno.h>

#include "patchmii_core.h"
#include "sha1.h"
#include "debug.h"
#include "http.h"
#include "haxx_certs.h"

#define VERSION "0.1"

// These parameters will download IOS37, modify it, and install it as IOS5
#define INPUT_TITLEID_H 1
#define INPUT_TITLEID_L 37
#define OUTPUT_TITLEID_H 1
#define OUTPUT_TITLEID_L 5

#define ALIGN(a,b) ((((a)+(b)-1)/(b))*(b))

int http_status = 0;
int tmd_dirty = 0, tik_dirty = 0;

void debug_printf(const char *fmt, ...) {
  char buf[1024];
  int len;
  va_list ap;
  usb_flush(1);
  va_start(ap, fmt);
  len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (len <= 0 || len > sizeof(buf)) printf("Error: len = %d\n", len);
  else usb_sendbuffer(1, buf, len);
  puts(buf);
}

char ascii(char s) {
  if(s < 0x20) return '.';
  if(s > 0x7E) return '.';
  return s;
}

void hexdump(void *d, int len) {
  u8 *data;
  int i, off;
  data = (u8*)d;
  for (off=0; off<len; off += 16) {
    debug_printf("%08x  ",off);
    for(i=0; i<16; i++)
      if((i+off)>=len) debug_printf("   ");
      else debug_printf("%02x ",data[off+i]);

    debug_printf(" ");
    for(i=0; i<16; i++)
      if((i+off)>=len) debug_printf(" ");
      else debug_printf("%c",ascii(data[off+i]));
    debug_printf("\n");
  }
}

char *spinner_chars="/-\\|";
int spin = 0;

void spinner(void) {
//  debug_printf("\b%c ", spinner_chars[spin++]);
  if(!spinner_chars[spin]) spin=0;
}

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

void printvers(void) {
  debug_printf("IOS Version: %08x\n", *((u32*)0xC0003140));
}

void console_setup(void) {
  VIDEO_Init();
  PAD_Init();
  
  rmode = VIDEO_GetPreferredMode(NULL);

  xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
  VIDEO_ClearFrameBuffer(rmode,xfb,COLOR_BLACK);
  VIDEO_Configure(rmode);
  VIDEO_SetNextFramebuffer(xfb);
  VIDEO_SetBlack(FALSE);
  VIDEO_Flush();
  VIDEO_WaitVSync();
  if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
  CON_InitEx(rmode,20,30,rmode->fbWidth - 40,rmode->xfbHeight - 60);
}

int get_nus_object(u32 titleid1, u32 titleid2, char *content, u8 **outbuf, u32 *outlen) {
  static char buf[128];
  int retval;
  u32 http_status;

  snprintf(buf, 128, "http://nus.cdn.shop.wii.com/ccs/download/%08x%08x/%s",
	   titleid1, titleid2, content);

  retval = http_request(buf, 1 << 31);
  if (!retval) {
    debug_printf("Error making http request\n");
    return 0;
  }

  retval = http_get_result(&http_status, outbuf, outlen); 
  if (((int)*outbuf & 0xF0000000) == 0xF0000000) {
    return (int) *outbuf;
  }

  return 0;
}

void decrypt_buffer(u16 index, u8 *source, u8 *dest, u32 len) {
  static u8 iv[16];
  if (!source) {
	debug_printf("decrypt_buffer: invalid source paramater\n");
	exit(1);
  }
  if (!dest) {
	debug_printf("decrypt_buffer: invalid dest paramater\n");
	exit(1);
  }

  memset(iv, 0, 16);
  memcpy(iv, &index, 2);
  aes_decrypt(iv, source, dest, len);
}

static u8 encrypt_iv[16];
void set_encrypt_iv(u16 index) {
  memset(encrypt_iv, 0, 16);
  memcpy(encrypt_iv, &index, 2);
}
  
void encrypt_buffer(u8 *source, u8 *dest, u32 len) {
  aes_encrypt(encrypt_iv, source, dest, len);
}

int create_temp_dir(void) {
  int retval;
  retval = ISFS_CreateDir ("/tmp/patchmii", 0, 3, 1, 1);
  if (retval) debug_printf("ISFS_CreateDir(/tmp/patchmii) returned %d\n", retval);
  return retval;
}

u32 save_nus_object (u16 index, u8 *buf, u32 size) {
  char filename[256];
  static u8 bounce_buf[1024] ATTRIBUTE_ALIGN(0x20);
  u32 i;

  int retval, fd;
  snprintf(filename, sizeof(filename), "/tmp/patchmii/%08x", index);
  
  retval = ISFS_CreateFile (filename, 0, 3, 1, 1);

  if (retval != ISFS_OK) {
    debug_printf("ISFS_CreateFile(%s) returned %d\n", filename, retval);
    return retval;
  }
  
  fd = ISFS_Open (filename, ISFS_ACCESS_WRITE);

  if (fd < 0) {
    debug_printf("ISFS_OpenFile(%s) returned %d\n", filename, fd);
    return retval;
  }

  for (i=0; i<size;) {
    u32 numbytes = ((size-i) < 1024)?size-i:1024;
    memcpy(bounce_buf, buf+i, numbytes);
    retval = ISFS_Write(fd, bounce_buf, numbytes);
    if (retval < 0) {
      debug_printf("ISFS_Write(%d, %p, %d) returned %d at offset %d\n", 
		   fd, bounce_buf, numbytes, retval, i);
      ISFS_Close(fd);
      return retval;
    }
    i += retval;
  }
  ISFS_Close(fd);
  return size;
}

s32 install_nus_object (tmd *p_tmd, u16 index) {
  char filename[256];
  static u8 bounce_buf1[1024] ATTRIBUTE_ALIGN(0x20);
  static u8 bounce_buf2[1024] ATTRIBUTE_ALIGN(0x20);
  u32 i;
  const tmd_content *p_cr = TMD_CONTENTS(p_tmd);
  
  int retval, fd, cfd, ret;
  snprintf(filename, sizeof(filename), "/tmp/patchmii/%08x", index);
  
  fd = ISFS_Open (filename, ISFS_ACCESS_READ);
  
  if (fd < 0) {
    debug_printf("ISFS_OpenFile(%s) returned %d\n", filename, fd);
    return fd;
  }
  set_encrypt_iv(index);

  cfd = ES_AddContentStart(p_tmd->title_id, index);
  if(cfd < 0) {
    debug_printf(":\nES_AddContentStart(%016llx, %d) failed: %d\n",p_tmd->title_id, index, cfd);
    ES_AddTitleCancel();
    return -1;
  }
  debug_printf(" (cfd %d): ",cfd);
  for (i=0; i<p_cr[index].size;) {
    u32 numbytes = ((p_cr[index].size-i) < 1024)?p_cr[index].size-i:1024;
    numbytes = ALIGN(numbytes, 32);
    retval = ISFS_Read(fd, bounce_buf1, numbytes);
    if (retval < 0) {
      debug_printf("ISFS_Read(%d, %p, %d) returned %d at offset %d\n", 
		   fd, bounce_buf1, numbytes, retval, i);
      ES_AddContentFinish(cfd);
      ES_AddTitleCancel();
      ISFS_Close(fd);
      return retval;
    }
    
    encrypt_buffer(bounce_buf1, bounce_buf2, sizeof(bounce_buf1));
    ret = ES_AddContentData(cfd, bounce_buf2, retval);
    if (ret < 0) {
      debug_printf("ES_AddContentData(%d, %p, %d) returned %d\n", cfd, bounce_buf2, retval, ret);
      ES_AddContentFinish(cfd);
      ES_AddTitleCancel();
      ISFS_Close(fd);
      return ret;
    }
    i += retval;
  }

  debug_printf("  done! (0x%x bytes)\n",i);
  ret = ES_AddContentFinish(cfd);
  if(ret < 0) {
    printf("ES_AddContentFinish failed: %d\n",ret);
    ES_AddTitleCancel();
    ISFS_Close(fd);
    return -1;
  }
  
  ISFS_Close(fd);
  
  return 0;
}

int get_title_key(signed_blob *s_tik, u8 *key) {
  static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
  static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
  static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);
  int retval;

  const tik *p_tik;
  p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);
  u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
  memcpy(keyin, enc_key, sizeof keyin);
  memset(keyout, 0, sizeof keyout);
  memset(iv, 0, sizeof iv);
  memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
  
  retval = ES_Decrypt(ES_KEY_COMMON, iv, keyin, sizeof keyin, keyout);
  if (retval) debug_printf("ES_Decrypt returned %d\n", retval);
  memcpy(key, keyout, sizeof keyout);
  return retval;
}

int change_ticket_title_id(signed_blob *s_tik, u32 titleid1, u32 titleid2) {
	static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);
	int retval;

	tik *p_tik;
	p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyin, enc_key, sizeof keyin);
	memset(keyout, 0, sizeof keyout);
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);

	retval = ES_Decrypt(ES_KEY_COMMON, iv, keyin, sizeof keyin, keyout);
	p_tik->titleid = (u64)titleid1 << 32 | (u64)titleid2;
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
	
	retval = ES_Encrypt(ES_KEY_COMMON, iv, keyout, sizeof keyout, keyin);
    if (retval) debug_printf("ES_Decrypt returned %d\n", retval);
	memcpy(enc_key, keyin, sizeof keyin);
	tik_dirty = 1;

    return retval;
}

void change_tmd_title_id(signed_blob *s_tmd, u32 titleid1, u32 titleid2) {
	tmd *p_tmd;
	u64 title_id = titleid1;
	title_id <<= 32;
	title_id |= titleid2;
	p_tmd = (tmd*)SIGNATURE_PAYLOAD(s_tmd);
	p_tmd->title_id = title_id;
	tmd_dirty = 1;
}

void display_tag(u8 *buf) {
  debug_printf("Firmware version: %s      Builder: %s\n",
	       buf, buf+0x30);
}

void display_ios_tags(u8 *buf, u32 size) {
  u32 i;
  char *ios_version_tag = "$IOSVersion:";

  if (size == 64) {
    display_tag(buf);
    return;
  }

  for (i=0; i<(size-64); i++) {
    if (!strncmp((char *)buf+i, ios_version_tag, 10)) {
      char version_buf[128], *date;
      while (buf[i+strlen(ios_version_tag)] == ' ') i++; // skip spaces
      strlcpy(version_buf, (char *)buf + i + strlen(ios_version_tag), sizeof version_buf);
      date = version_buf;
      strsep(&date, "$");
      date = version_buf;
      strsep(&date, ":");
      debug_printf("%s (%s)\n", version_buf, date);
      i += 64;
    }
  }
}

int patch_hash_check(u8 *buf, u32 size) {
  u32 i;
  u32 match_count = 0;
  u8 new_hash_check[] = {0x20,0x07,0x4B,0x0B};
  u8 old_hash_check[] = {0x20,0x07,0x23,0xA2};
  
  for (i=0; i<size-4; i++) {
    if (!memcmp(buf + i, new_hash_check, sizeof new_hash_check)) {
      debug_printf("Found new-school ES hash check @ 0x%x, patching.\n", i);
      buf[i+1] = 0;
      buf += 4;
      match_count++;
      continue;
    }

    if (!memcmp(buf + i, old_hash_check, sizeof old_hash_check)) {
      debug_printf("Found old-school ES hash check @ 0x%x, patching.\n", i);
      buf[i+1] = 0;
      buf += 4;
      match_count++;
      continue;
    }
  }
  return match_count;
}

void print_tmd_summary(const tmd *p_tmd) {
  const tmd_content *p_cr;
  p_cr = TMD_CONTENTS(p_tmd);

  u32 size=0;

  u16 i=0;
  for(i=0;i<p_tmd->num_contents;i++) {
    size += p_cr[i].size;
  }

  debug_printf("Title ID: %016llx\n",p_tmd->title_id);
  debug_printf("Number of parts: %d.  Total size: %uK\n", p_tmd->num_contents, (u32) (size / 1024));
}

void zero_sig(signed_blob *sig) {
  u8 *sig_ptr = (u8 *)sig;
  memset(sig_ptr + 4, 0, SIGNATURE_SIZE(sig)-4);
}

void brute_tmd(tmd *p_tmd) {
  u16 fill;
  for(fill=0; fill<65535; fill++) {
    p_tmd->fill3=fill;
    sha1 hash;
    //    debug_printf("SHA1(%p, %x, %p)\n", p_tmd, TMD_SIZE(p_tmd), hash);
    SHA1((u8 *)p_tmd, TMD_SIZE(p_tmd), hash);;
  
    if (hash[0]==0) {
      //      debug_printf("setting fill3 to %04hx\n", fill);
      return;
    }
  }
  printf("Unable to fix tmd :(\n");
  exit(4);
}

void brute_tik(tik *p_tik) {
  u16 fill;
  for(fill=0; fill<65535; fill++) {
    p_tik->padding=fill;
    sha1 hash;
    //    debug_printf("SHA1(%p, %x, %p)\n", p_tmd, TMD_SIZE(p_tmd), hash);
    SHA1((u8 *)p_tik, sizeof(tik), hash);
  
    if (hash[0]==0) return;
  }
  printf("Unable to fix tik :(\n");
  exit(5);
}
    
void forge_tmd(signed_blob *s_tmd) {
  debug_printf("forging tmd sig\n");
  zero_sig(s_tmd);
  brute_tmd(SIGNATURE_PAYLOAD(s_tmd));
}

void forge_tik(signed_blob *s_tik) {
  debug_printf("forging tik sig\n");
  zero_sig(s_tik);
  brute_tik(SIGNATURE_PAYLOAD(s_tik));
}

#define BLOCK 0x1000

s32 install_ticket(const signed_blob *s_tik, const signed_blob *s_certs, u32 certs_len) {
  u32 ret;

  debug_printf("Installing ticket...\n");
  ret = ES_AddTicket(s_tik,STD_SIGNED_TIK_SIZE,s_certs,certs_len, NULL, 0);
  if (ret < 0) {
      debug_printf("ES_AddTicket failed: %d\n",ret);
      return ret;
  }
  return 0;
}

s32 install(const signed_blob *s_tmd, const signed_blob *s_certs, u32 certs_len) {
  u32 ret, i;
  tmd *p_tmd = SIGNATURE_PAYLOAD(s_tmd);
  debug_printf("Adding title...\n");

  ret = ES_AddTitleStart(s_tmd, SIGNED_TMD_SIZE(s_tmd), s_certs, certs_len, NULL, 0);

  if(ret < 0) {
    debug_printf("ES_AddTitleStart failed: %d\n",ret);
    ES_AddTitleCancel();
    return ret;
  }

  for(i=0; i<p_tmd->num_contents; i++) {
    debug_printf("Adding content ID %08x", i);
    ret = install_nus_object((tmd *)SIGNATURE_PAYLOAD(s_tmd), i);
    if (ret) return ret;
  }

  ret = ES_AddTitleFinish();
  if(ret < 0) {
    printf("ES_AddTitleFinish failed: %d\n",ret);
    ES_AddTitleCancel();
    return ret;
  }

  printf("Installation complete!\n");
  return 0;

}

int main(int argc, char **argv) {

  console_setup();
  printf("PatchMii Core v" VERSION ", by bushing\n");

// ******* WARNING *******
// Obviously, if you're reading this, you're obviously capable of disabling the
// following checks.  If you put any of the following titles into an unusuable state, 
// your Wii will fail to boot:
//
// 1-1 (BOOT2), 1-2 (System Menu), 1-30 (IOS30, currently specified by 1-2's TMD)
// Corrupting other titles (for example, BC or the banners of installed channels)
// may also cause difficulty booting.  Please do not remove these safety checks
// unless you have performed extensive testing and are willing to take on the risk
// of bricking the systems of people to whom you give this code.  -bushing

  if ((OUTPUT_TITLEID_H == 1) && (OUTPUT_TITLEID_L == 2)) {
	printf("Sorry, I won't modify the system menu; too dangerous. :(\n");
	while(1);
  }

  if ((OUTPUT_TITLEID_H == 1) && (OUTPUT_TITLEID_L == 30)) {
	printf("Sorry, I won't modify IOS30; too dangerous. :(\n");
	while(1);
  }

  printvers();
  
  int retval;

  ISFS_Initialize();
  create_temp_dir();
  printf("Initializing network."); fflush(stdout);
  while (1) {
  	retval = net_init ();
 	if (retval < 0) {
		if (retval != -EAGAIN) {
			debug_printf ("net_init failed: %d\n", retval);
			exit(0);
		}
    }
	if (!retval) break;
	usleep(100000);
	printf("."); fflush(stdout);
  }

  printf("Done!\n");
  signed_blob *s_tmd = NULL, *s_tik = NULL, *s_certs = NULL;

  u8 *temp_tmdbuf = NULL, *temp_tikbuf = NULL;

  static u8 tmdbuf[MAX_SIGNED_TMD_SIZE] ATTRIBUTE_ALIGN(0x20);
  static u8 tikbuf[STD_SIGNED_TIK_SIZE] ATTRIBUTE_ALIGN(0x20);
  
  u32 tmdsize;

  debug_printf("Downloading IOS%d metadata: ..", INPUT_TITLEID_L);
  retval = get_nus_object(INPUT_TITLEID_H, INPUT_TITLEID_L, "tmd", &temp_tmdbuf, &tmdsize);
  if(retval<0) debug_printf("get_nus_object(tmd) returned %d, tmdsize = %u\n", retval, tmdsize);
  memcpy(tmdbuf, temp_tmdbuf, MIN(tmdsize, sizeof(tmdbuf)));
  free(temp_tmdbuf);

  s_tmd = (signed_blob *)tmdbuf;
  if(!IS_VALID_SIGNATURE(s_tmd)) {
    debug_printf("Bad TMD signature!\n");
    return -1;
  }
  debug_printf("\b ..tmd..");

  u32 ticketsize;
  retval = get_nus_object(INPUT_TITLEID_H, INPUT_TITLEID_L, 
						  "cetk", &temp_tikbuf, &ticketsize);
						
  if (retval < 0) debug_printf("get_nus_object(cetk) returned %d, ticketsize = %u\n", retval, ticketsize);
  memcpy(tikbuf, temp_tikbuf, MIN(ticketsize, sizeof(tikbuf)));
  
  s_tik = (signed_blob *)tikbuf;
  if(!IS_VALID_SIGNATURE(s_tik)) {
    debug_printf("Bad tik signature!\n");
    return -1;
  }
  
  free(temp_tikbuf);

  s_certs = (signed_blob *)haxx_certs;
  if(!IS_VALID_SIGNATURE(s_certs)) {
    debug_printf("Bad cert signature!\n");
    return -1;
  }

  debug_printf("\b ..ticket..");

  u8 key[16];
  get_title_key(s_tik, key);
  aes_set_key(key);

  const tmd *p_tmd;
  tmd_content *p_cr;
  p_tmd = (tmd*)SIGNATURE_PAYLOAD(s_tmd);
  p_cr = TMD_CONTENTS(p_tmd);
        
  print_tmd_summary(p_tmd);

  debug_printf("Downloading contents: \n");
  static char cidstr[32];
  u16 i;
  for(i=0;i<p_tmd->num_contents;i++) {
    debug_printf("Downloading part %d/%d (%uK): ", i+1, 
		 p_tmd->num_contents, p_cr[i].size / 1024);
    sprintf(cidstr, "%08x", p_cr[i].cid);
    
    u8 *content_buf, *decrypted_buf;
    u32 content_size;

    retval = get_nus_object(1, 37, cidstr, &content_buf, &content_size);
    if (retval < 0) debug_printf("get_nus_object(%s) returned %d, content size = %u\n", cidstr, retval, content_size);
    if (content_size % 16) {
      debug_printf("ERROR: downloaded content[%hu] size %u is not a multiple of 16\n", i, content_size);
    }
    if (content_size < p_cr[i].size) {
      debug_printf("ERROR: only downloaded %u / %u bytes\n", content_size, p_cr[i].size);
    } else {
      decrypted_buf = malloc(content_size);
	  if (!decrypted_buf) {
		debug_printf("ERROR: failed to allocate decrypted_buf (%u bytes)\n", content_size);
		exit(1);
	}
	decrypt_buffer(i, content_buf, decrypted_buf, content_size);

	sha1 hash;

	SHA1(decrypted_buf, p_cr[i].size, hash);

	if (!memcmp(p_cr[i].hash, hash, sizeof hash)) {
		debug_printf("\b hash OK. ");
		display_ios_tags(decrypted_buf, content_size);
		if (patch_hash_check(decrypted_buf, content_size)) {
			debug_printf("Updating TMD.\n");
			SHA1(decrypted_buf, p_cr[i].size, hash);
			memcpy(p_cr[i].hash, hash, sizeof hash);
			tmd_dirty=1;
		}
	
		retval = (int) save_nus_object(p_cr[i].cid, decrypted_buf, content_size);
		if (retval < 0) debug_printf("save_nus_object(%x) returned %d\n", p_cr[i].cid, retval);
	} else {
		debug_printf("hash BAD\n");
	}
      
	free(decrypted_buf);
    free(content_buf);
	}
      
  }
  /* this doesn't seem to work yet ... */
  if ((INPUT_TITLEID_H != OUTPUT_TITLEID_H) 
	|| (INPUT_TITLEID_L != OUTPUT_TITLEID_L)) {
		debug_printf("Changing titleid from %08x-%08x to %08x-%08x\n",
			INPUT_TITLEID_H, INPUT_TITLEID_L,
			OUTPUT_TITLEID_H, OUTPUT_TITLEID_L);
		change_ticket_title_id(s_tik, OUTPUT_TITLEID_H, OUTPUT_TITLEID_L);
		change_tmd_title_id(s_tmd, OUTPUT_TITLEID_H, OUTPUT_TITLEID_L);
  } 

  if (tmd_dirty) {
    forge_tmd(s_tmd);
    tmd_dirty = 0;
  }

  if (tik_dirty) {
    forge_tik(s_tik);
    tik_dirty = 0;
  }

  debug_printf("Download complete. Installing:\n");

  retval = install_ticket(s_tik, s_certs, haxx_certs_size);
  if (retval) {
    debug_printf("install_ticket returned %d\n", retval);
    return 1;
  }

  retval = install(s_tmd, s_certs, haxx_certs_size);
		   
  if (retval) {
    debug_printf("install returned %d\n", retval);
    return 1;
  }

  debug_printf("Done!\n");

  return 0;
}
