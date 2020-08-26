#ifndef _FAT_SHELL_H_
#define _FAT_SHELL_H_
#define FSOPRS_TO_EXT2FS( a )      ( EXT2_FILESYSTEM* )a->pdata
#include "ext2.h"
#include "shell.h"

void shell_register_filesystem( SHELL_FILESYSTEM* );
int fs_read( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, unsigned long offset, unsigned long length, const char* buffer );
int fs_write( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, unsigned long offset, unsigned long length, const char* buffer );
int	fs_create(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name, SHELL_ENTRY* retEntry);
int fs_lookup(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, const char* name);
int fs_read_dir(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY_LIST* list);
int fs_mkdir(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name, SHELL_ENTRY* retEntry);
int fs_rmdir( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name );
int fs_format(DISK_OPERATIONS* disk, void* param);
int fs_remove( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name );
int fs_stat( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, unsigned int* totalSectors, unsigned int* usedSectors );
#endif
