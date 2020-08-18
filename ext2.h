#ifndef _FAT_H_
#define _FAT_H_

#include "common.h"
#include "disk.h"
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#define GNU_SOURCE"

#include <string.h>

#define      EXT2_N_BLOCKS         15
#define		NUMBER_OF_SECTORS		( 4096 + 1 )
#define		NUMBER_OF_GROUPS		2
#define		NUMBER_OF_INODES		200
#define		VOLUME_LABLE			"EXT2 BY NC"

#define MAX_SECTOR_SIZE			1024
#define MAX_BLOCK_SIZE			1024
#define MAX_NAME_LENGTH			256
#define MAX_ENTRY_NAME_LENGTH	11

#define ATTR_READ_ONLY			0x01
#define ATTR_HIDDEN				0x02
#define ATTR_SYSTEM				0x04
#define ATTR_VOLUME_ID			0x08
#define ATTR_DIRECTORY			0x10
#define ATTR_ARCHIVE			0x20
#define ATTR_LONG_NAME			ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID

#define DIR_ENTRY_FREE			0xE5
#define DIR_ENTRY_NO_MORE		0x00
#define DIR_ENTRY_OVERWRITE		1

#define GET_INODE_GROUP(x) ((x) - 1)/( NUMBER_OF_INODES / NUMBER_OF_GROUPS )
#define SQRT(x)  ( (x) * (x)  )
#define TRI_SQRT(x)  ( (x) * (x) * (x) )
#define WHICH_GROUP_BLONG(x) ( ( (x) - 1)  / ( NUMBER_OF_INODES / NUMBER_OF_GROUPS )  )

#define TSQRT(x) ((x)*(x)*(x))
#define GET_INODE_FROM_NODE(x) ((x)->entry.inode)

#ifdef _WIN32
#pragma pack(push,fatstructures)
#endif
#pragma pack(1)

typedef struct
{
	UINT32 max_inode_count;
	UINT32 block_count;
	UINT32 reserved_block_count;
	UINT32 free_block_count;
	UINT32 free_inode_count;

	UINT32 first_data_block;
	UINT32 log_block_size;
	UINT32 log_fragmentation_size;
	UINT32 block_per_group;
	UINT32 fragmentation_per_group;
	UINT32 inode_per_group;
	UINT16 magic_signature;
	UINT16 errors;
	UINT32 first_non_reserved_inode;
	UINT16 inode_structure_size;

	UINT16 block_group_number;
	UINT32 first_data_block_each_group;
} EXT2_SUPER_BLOCK;

typedef struct
{
	UINT16  mode;         /* File mode */
	UINT16  uid;          /* Low 16 bits of Owner Uid */
	UINT32  size;         /* Size in bytes */
	UINT32  atime;        /* Access time */
	UINT32  ctime;        /* Creation time */
	UINT32  mtime;        /* Modification time */
	UINT32  dtime;        /* Deletion Time */
	UINT16  gid;          /* Low 16 bits of Group Id */
	UINT16  links_count;  /* Links count */
	UINT32  blocks;       /* Blocks count */
	UINT32  flags;        /* File flags */
	UINT32  i_reserved1;   // OS dependent 1
	UINT32  block[EXT2_N_BLOCKS];/* Pointers to blocks */
	UINT32  generation;   /* File version (for NFS) */
	UINT32  file_acl;     /* File ACL */
	UINT32  dir_acl;      /* Directory ACL */
	UINT32  faddr;        /* Fragment address */
	UINT32  i_reserved2[3];   // OS dependent 2
} INODE;

typedef struct
{
	UINT32 start_block_of_block_bitmap;
	UINT32 start_block_of_inode_bitmap;
	UINT32 start_block_of_inode_table;
	UINT32 free_blocks_count;
	UINT32 free_inodes_count;
	UINT16 directories_count;
	BYTE padding[2];
	BYTE reserved[12];
} EXT2_GROUP_DESCRIPTOR;

typedef struct
{
	UINT32 inode;
	BYTE name[11];
	UINT32 name_len;
	BYTE pad[13];
} EXT2_DIR_ENTRY;

#ifdef _WIN32
#pragma pack(pop, fatstructures)
#else
#pragma pack()
#endif

typedef struct
{
	EXT2_SUPER_BLOCK		sb;
	EXT2_GROUP_DESCRIPTOR	gd;
	DISK_OPERATIONS*		disk;

} EXT2_FILESYSTEM;

typedef struct
{
	UINT32 group;
	UINT32 block;
	UINT32 offset;
} EXT2_DIR_ENTRY_LOCATION;

typedef struct
{
	EXT2_FILESYSTEM * fs;
	EXT2_DIR_ENTRY entry;
	EXT2_DIR_ENTRY_LOCATION location;

} EXT2_NODE;

#define SUPER_BLOCK 0
#define GROUP_DES  1
#define BLOCK_BITMAP 2
#define INODE_BITMAP 3
#define INODE_TABLE(x) (4 + x)

#define FILE_TYPE_FIFO               0x1000
#define FILE_TYPE_CHARACTERDEVICE    0x2000
#define FILE_TYPE_DIR				 0x4000
#define FILE_TYPE_BLOCKDEVICE        0x6000
#define FILE_TYPE_FILE				 0x8000

int meta_read(EXT2_FILESYSTEM *, SECTOR group,SECTOR block, BYTE* sector);
int meta_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector);
int data_read(EXT2_FILESYSTEM *, SECTOR group, SECTOR block, BYTE* sector);
int data_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector);

int ext2_format(DISK_OPERATIONS* disk);
int ext2_create(EXT2_NODE* parent, char* entryName, EXT2_NODE* retEntry);
int ext2_lookup(EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry);

UINT32 expand_block(EXT2_FILESYSTEM * , UINT32 );
int fill_super_block(EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector);
int fill_descriptor_block(EXT2_GROUP_DESCRIPTOR * gd, EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector);
int create_root(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK * sb);
typedef int(*EXT2_NODE_ADD)(EXT2_FILESYSTEM*,void*, EXT2_NODE*);
void process_meta_data_for_block_used(EXT2_FILESYSTEM * fs, UINT32 inode_num);
#endif

