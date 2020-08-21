 typedef struct
{
	char*	address;
} DISK_MEMORY;

#include "ext2.h"
#define MIN( a, b )					( ( a ) < ( b ) ? ( a ) : ( b ) )
#define MAX( a, b )					( ( a ) > ( b ) ? ( a ) : ( b ) )

int ext2_write(EXT2_NODE* file, unsigned long offset, unsigned long length, const char* buffer)
{
	BYTE	sector[MAX_SECTOR_SIZE];
	DWORD	currentOffset, currentBlock, blockSeq = 0;
	DWORD	blockNumber, sectorNumber, sectorOffset;
	DWORD	readEnd;
	DWORD	blockSize;
	INODE node;
	int i;

	get_inode(file->fs, file->entry.inode, &node);
	currentBlock = node.block[0];
	readEnd = offset + length;

	currentOffset = offset;

	blockSize = MAX_BLOCK_SIZE;

	i = 1;
	while (offset > blockSize)
	{

		currentBlock = get_data_block_at_inode(file->fs, node, ++i);
		blockSize += blockSize;
		blockSeq++;
	}

	while (currentOffset < readEnd)
	{
		DWORD	copyLength;


		blockNumber = currentOffset / MAX_BLOCK_SIZE;
		if (currentBlock == 0)
		{
			if (expand_block(file->fs, file->entry.inode) == EXT2_ERROR)
				return EXT2_ERROR;
			process_meta_data_for_block_used(file->fs, file->entry.inode);
			get_inode(file->fs, file->entry.inode, &node);
			currentBlock = node.block[0];
		}

		if (blockSeq != blockNumber)
		{
			DWORD nextBlock;
			blockSeq++;
			++i;
			nextBlock = get_data_block_at_inode(file->fs, node, i);
			if (nextBlock == 0)
			{
				expand_block(file->fs, file->entry.inode);
				get_inode(file->fs, file->entry.inode, &node);
				process_meta_data_for_block_used(file->fs, file->entry.inode);

				nextBlock = get_data_block_at_inode(file->fs, node, i);
	
				if (nextBlock == 0)
				{
					return EXT2_ERROR;
				}
			}
			currentBlock = nextBlock;
		}
		sectorNumber = (currentOffset / (MAX_SECTOR_SIZE)) % (MAX_BLOCK_SIZE / MAX_SECTOR_SIZE);
		sectorOffset = currentOffset % MAX_SECTOR_SIZE;

		copyLength = MIN(MAX_SECTOR_SIZE - sectorOffset, readEnd - currentOffset);

		if (copyLength != MAX_SECTOR_SIZE)
		{
			if (data_read(file->fs, 0, currentBlock, sector))
				break;
		}

		memcpy(&sector[sectorOffset],
			buffer,
			copyLength);

		if (data_write(file->fs, 0, currentBlock, sector))
			break;

		buffer += copyLength;
		currentOffset += copyLength;
	}

	node.size = MAX(currentOffset, node.size);
	set_inode_onto_inode_table(file->fs, file->entry.inode, &node);

	return currentOffset - offset;
}

UINT32 get_free_inode_number(EXT2_FILESYSTEM* fs);

int ext2_format(DISK_OPERATIONS* disk)
{
	EXT2_SUPER_BLOCK sb;
	EXT2_GROUP_DESCRIPTOR gd;
	EXT2_GROUP_DESCRIPTOR  gd_another_group;

	QWORD sector_num_per_group = (disk->numberOfSectors - 1) / NUMBER_OF_GROUPS;
	int i, gi, j;
	const int BOOT_SECTOR_BASE = 1;
	char sector[MAX_SECTOR_SIZE];

	if (fill_super_block(&sb, disk->numberOfSectors, disk->bytesPerSector) != EXT2_SUCCESS)
		return EXT2_ERROR;

	ZeroMemory(sector, sizeof(sector));
	memcpy(sector, &sb, sizeof(sb));
	disk->write_sector(disk, BOOT_SECTOR_BASE + 0, sector);

	if (fill_descriptor_block(&gd, &sb, disk->numberOfSectors, disk->bytesPerSector) != EXT2_SUCCESS)
		return EXT2_ERROR;

	gd_another_group = gd;
	gd_another_group.free_inodes_count = NUMBER_OF_INODES / NUMBER_OF_GROUPS;
	gd_another_group.free_blocks_count = sb.free_block_count / NUMBER_OF_GROUPS;

	ZeroMemory(sector, sizeof(sector));
	for (j = 0; j < NUMBER_OF_GROUPS; j++)
	{
		if (j == 0)memcpy(sector + j * sizeof(gd), &gd, sizeof(gd));
		else memcpy(sector + j * sizeof(gd_another_group), &gd_another_group, sizeof(gd_another_group));
	}

	disk->write_sector(disk, BOOT_SECTOR_BASE + 1, sector);

	// block bitmap
	ZeroMemory(sector, sizeof(sector));
 
	sector[0] = 0xff;//11111111
	sector[1] = 0xff;//11111111
	sector[2] = 0x01;//00000001 -> 10000000여야하는거 아님?
	disk->write_sector(disk, BOOT_SECTOR_BASE + 2, sector);

	// inode bitmap
	ZeroMemory(sector, sizeof(sector));

	sector[0] = 0xff;//11111111
	sector[1] = 0x03;//00000011
	disk->write_sector(disk, BOOT_SECTOR_BASE + 3, sector);

	// inode table
	ZeroMemory(sector, sizeof(sector));

	for (i = 4; i < sb.first_data_block_each_group; i++)
		disk->write_sector(disk, BOOT_SECTOR_BASE + i, sector);

	for (gi = 1; gi < NUMBER_OF_GROUPS; gi++)
	{
		sb.block_group_number = gi;

		ZeroMemory(sector, sizeof(sector));
		memcpy(sector, &sb, sizeof(sb));

		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE, sector);

		ZeroMemory(sector, sizeof(sector));
		for (j = 0; j < NUMBER_OF_GROUPS; j++)
		{
			memcpy(sector + j * sizeof(gd), &gd, sizeof(gd));
		}
		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 1, sector);

		// block bitmap
		ZeroMemory(sector, sizeof(sector));
		sector[0] = 0xff;
		sector[1] = 0xff;
		sector[2] = 0x01;
		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 2, sector);

		//inode bitmap
		ZeroMemory(sector, sizeof(sector));

		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 3, sector);

		// inode table
		ZeroMemory(sector, sizeof(sector));
		for (i = 4; i < sb.first_data_block_each_group; i++)
			disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + i, sector);
	}

	PRINTF("max inode count                : %u\n", sb.max_inode_count);
	PRINTF("total block count              : %u\n", sb.block_count);
	PRINTF("byte size of inode structure   : %u\n", sb.inode_structure_size);
	PRINTF("block byte size                : %u\n", MAX_BLOCK_SIZE);
	PRINTF("total sectors count            : %u\n", NUMBER_OF_SECTORS);
	PRINTF("sector byte size               : %u\n", MAX_SECTOR_SIZE);
	PRINTF("\n");

	create_root(disk, &sb);

	return EXT2_SUCCESS;
}

int fill_super_block(EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector)
{
	ZeroMemory(sb, sizeof(EXT2_SUPER_BLOCK));

	sb->max_inode_count = NUMBER_OF_INODES;
	sb->block_count = numberOfSectors;
	sb->reserved_block_count = 0;
	sb->free_block_count = numberOfSectors - (17 * NUMBER_OF_GROUPS) - 1;
	sb->free_inode_count = NUMBER_OF_INODES - 10; //10개는 예약 11번부터 사용
	sb->first_data_block = 1;
	sb->log_block_size = 0;
	sb->log_fragmentation_size = 0;
	sb->block_per_group = (numberOfSectors - 1) / NUMBER_OF_GROUPS;
	sb->fragmentation_per_group = 0;
	sb->inode_per_group = NUMBER_OF_INODES / NUMBER_OF_GROUPS;
	sb->magic_signature = 0xEF53;
	sb->errors = 0;
	sb->first_non_reserved_inode = 11;
	sb->inode_structure_size = 128;
	sb->block_group_number = 0;
	sb->first_data_block_each_group = 1 + 1 + 1 + 1 + 13; //데이터블록은 18번부터 시작 so, block bitmap도 18번 부터 시작

	return EXT2_SUCCESS;
}

int fill_descriptor_block(EXT2_GROUP_DESCRIPTOR * gd, EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector)
{
	ZeroMemory(gd, sizeof(EXT2_GROUP_DESCRIPTOR));

	gd->start_block_of_block_bitmap = 2;
	gd->start_block_of_inode_bitmap = 3;
	gd->start_block_of_inode_table = 4;
	gd->free_blocks_count = (UINT16)(sb->free_block_count / NUMBER_OF_GROUPS + sb->free_block_count % NUMBER_OF_GROUPS);
	gd->free_inodes_count = (UINT16)(((sb->free_inode_count) + 10) / NUMBER_OF_GROUPS - 10);
	gd->directories_count = 0;

	return EXT2_SUCCESS;
}

//jump
int create_root(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK * sb)
{
	BYTE   sector[MAX_SECTOR_SIZE];
	SECTOR   rootSector = 0;
	EXT2_DIR_ENTRY * entry;
	EXT2_GROUP_DESCRIPTOR * gd;
	EXT2_SUPER_BLOCK * sb_read;
	QWORD sector_num_per_group = (disk->numberOfSectors - 1) / NUMBER_OF_GROUPS;
	INODE * ip;
	const int BOOT_SECTOR_BASE = 1;
	int gi;

	ZeroMemory(sector, MAX_SECTOR_SIZE);
	entry = (EXT2_DIR_ENTRY*)sector;

	memcpy(entry->name, VOLUME_LABLE, 11);
	entry->name_len = strlen(VOLUME_LABLE);
	entry->inode = 2;
	entry++;
	entry->name[0] = DIR_ENTRY_NO_MORE;
	rootSector = 1 + sb->first_data_block_each_group;
	disk->write_sector(disk, rootSector, sector);

	sb_read = (EXT2_SUPER_BLOCK *)sector;
	for (gi = 0; gi < NUMBER_OF_GROUPS; gi++)
	{
		disk->read_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE, sector);
		sb_read->free_block_count--;

		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE, sector);
	}
	sb->free_block_count--;

	gd = (EXT2_GROUP_DESCRIPTOR *)sector;
	disk->read_sector(disk, BOOT_SECTOR_BASE + 1, sector);


	gd->free_blocks_count--;
	gd->directories_count = 1;

	for (gi = 0; gi < NUMBER_OF_GROUPS; gi++)
		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 1, sector);

	disk->read_sector(disk, BOOT_SECTOR_BASE + 2, sector);
	sector[2] |= 0x02;
	disk->write_sector(disk, BOOT_SECTOR_BASE + 2, sector);

	ZeroMemory(sector, MAX_SECTOR_SIZE);
	ip = (INODE *)sector;
	ip++;
	ip->mode = 0x1FF | 0x4000;
	printf("create_root mode : %u\n", ip->mode);
	ip->size = 0;
	ip->blocks = 1;
	ip->block[0] = sb->first_data_block_each_group;
	ip->flags = 10;
	disk->write_sector(disk, BOOT_SECTOR_BASE + 4, sector);

	return EXT2_SUCCESS;
}

void process_meta_data_for_inode_used(EXT2_NODE * retEntry, UINT32 inode_num, int fileType)
{
}

int insert_entry(UINT32 inode_num, EXT2_NODE * retEntry, int fileType)
{
}

UINT32 get_available_data_block(EXT2_FILESYSTEM * fs)//, UINT32 inode_num) //inode_num에 넣어줘야할듯 ????
{
	BYTE sector[MAX_SECTOR_SIZE];
	UINT32 i;
	UINT32 begin=0;  
	UINT32 number_of_blocks_for_group = (fs->disk->numberOfSectors-1)/2;
	UINT32 max_block_num_for_group = number_of_blocks_for_group; 
	UINT32 last = (fs->sb.block_per_group+7) / 8;//(소숫점 생길 경우 올림연산위해 +7)
	UINT32 group_num = 0;
	while(group_num < NUMBER_OF_GROUPS){// 그룹 수 만큼 반복
		data_read(fs, group_num, fs->gd.start_block_of_block_bitmap, sector);
		for( i = begin; i < last; i++ ) 
		{
			int j=1;
			BYTE bit = sector[i];
			while(j<9){
				UINT32 data_num = 8*i+j;
				if (data_num>fs->sb.block_per_group){ // 그룹당 데이터 최대 넘버 초과시 다음 그룹으로 이동
						break;
					}
				if(bit & 0x01==0 && data_num >17){ //비트가 0이고 데이터 넘버가 17 초과이면	
					return data_num+group_num*fs->sb.block_per_group+1; //data_read사용 할 경우 필요 없음
						//실제 블록 번호 반환 <디스크를 섹터로 인덱싱 했을때의 해당 블록 번호>
				}
				bit >>1;
				j++;
			}
		}//그룹 하나 돌고
		group_num++; //다 돌았으면 다음그룹
	} 
	return EXT2_ERROR; 
}

int process_meta_data_for_block_used(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
	
}

int expand_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
	INODE inodeBuffer;
	UINT32 new_block;
	unsigned int block_number_at_inode;
	BYTE sector[1024];

	get_inode(fs, inode_num, &inodeBuffer);
	new_block = get_available_data_block(fs);
	block_number_at_inode = inodeBuffer.blocks + 1;
	ZeroMemory(sector, 0);
	memcpy(sector, &new_block, sizeof(new_block));
	if(fs->disk->write_sector(fs->disk, get_data_block_at_inode(fs, inodeBuffer, block_number_at_inode), sector) == EXT2_ERROR)
	{
		return EXT2_ERROR;
	}
	if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)
	{
		return EXT2_ERROR;
	}
	inodeBuffer.blocks++;
	return EXT2_SUCCESS;
}

int meta_read(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->read_sector(fs->disk, real_index, sector);
}
int meta_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->write_sector(fs->disk, real_index, sector);
}

//블록이 위치하는 섹터의 데이터 읽어옴
int data_read(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1; 
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->read_sector(fs->disk, real_index, sector);
}
int data_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->write_sector(fs->disk, real_index, sector);
}

unsigned char toupper(unsigned char ch);
int isalpha(unsigned char ch);
int isdigit(unsigned char ch);

void upper_string(char* str, int length)
{
	while (*str && length-- > 0)
	{
		*str = toupper(*str);
		str++;
	}
}

int format_name(EXT2_FILESYSTEM* fs, char* name)
{
	UINT32	i, length;
	UINT32	extender = 0, nameLength = 0;
	UINT32	extenderCurrent = 8;
	BYTE	regularName[MAX_ENTRY_NAME_LENGTH];

	memset(regularName, 0x20, sizeof(regularName));
	length = strlen(name);

	if (strncmp(name, "..", 2) == 0)
	{
		memcpy(name, "..         ", 11);
		return EXT2_SUCCESS;
	}
	else if (strncmp(name, ".", 1) == 0)
	{
		memcpy(name, ".          ", 11);
		return EXT2_SUCCESS;
	}
	else
	{
		upper_string(name, MAX_ENTRY_NAME_LENGTH);

		for (i = 0; i < length; i++)
		{
			if (name[i] != '.' && !isdigit(name[i]) && !isalpha(name[i]))
				return EXT2_ERROR;

			if (name[i] == '.')
			{
				if (extender)
					return EXT2_ERROR;
				extender = 1;
			}
			else if (isdigit(name[i]) || isalpha(name[i]))
			{
				if (extender)
					regularName[extenderCurrent++] = name[i];
				else
					regularName[nameLength++] = name[i];
			}
			else
				return EXT2_ERROR;
		}

		if (nameLength > 8 || nameLength == 0 || extenderCurrent > 11)
			return EXT2_ERROR;
	}

	memcpy(name, regularName, sizeof(regularName));
	return EXT2_SUCCESS;
}
//inode= parent's inodenum
int lookup_entry(EXT2_FILESYSTEM* fs, const int inode, const char* name, EXT2_NODE* retEntry)
{
	INODE inodeBuffer;
	get_inode(fs, inode, &inodeBuffer);
	if(inode==2)
		return find_entry_on_root(fs,inodeBuffer,name,retEntry); //root에서 entry찾기
	else
	{
		return find_entry_on_data(fs,inodeBuffer,name,retEntry); //그 외 데이터에서 entry찾기
	}
	

}

int find_entry_at_sector(const BYTE* sector, const BYTE* formattedName, UINT32 begin, UINT32 last, UINT32* number)
{
	UINT32	i;
	const EXT2_DIR_ENTRY*	entry = ( EXT2_DIR_ENTRY* )sector;
	for( i = begin; i <= last; i++ )
	{if( formattedName == NULL )
		{// formattedName == NULL인 경우
			if( entry[i].name[0] != DIR_ENTRY_FREE && entry[i].name[0] != DIR_ENTRY_NO_MORE )
			{
				*number = i;
				return EXT2_SUCCESS;
				// 현재 사용중인 첫번째 entry읽어옴
			} 
		}
		else 
		{ // formattedName을 가진 경우
			if( ( formattedName[0] == DIR_ENTRY_FREE || formattedName[0] == DIR_ENTRY_NO_MORE ) &&
				( formattedName[0] == entry[i].name[0] ) )
			{ 
				// 새로운 dir_entry 추가할 때 추가될 dir_entry의 위치 찾음
				// entry[i]와 formattedName을 비교해서 동일하면 
				*number = i;
				return EXT2_SUCCESS;
			}

			if( memcmp( entry[i].name, formattedName, MAX_ENTRY_NAME_LENGTH ) == 0 )
			{
				// entry name을 검색할 때 해당 dir_entry를 찾은 경우
				// entry[i]와 formattedName을 비교해서 동일하면 
				*number = i;
				return EXT2_SUCCESS;
			}
		}

		if( entry[i].name[0] == DIR_ENTRY_NO_MORE )
		{
			// dir_entry의 끝 -> 검색 중지, 해당 위치 number에 저장
			// null 로 검색할 경우 && dir_entry 배열이 비어있는 경우
			*number = i;
			return -2;
		}
	}

	*number = i;
	return -1;
}

int find_entry_on_root(EXT2_FILESYSTEM* fs, INODE inode, char* formattedName, EXT2_NODE* ret)
{
	BYTE	sector[MAX_SECTOR_SIZE];
	UINT32	i, number;
	UINT32	lastSector;
	UINT32	entriesPerSector, lastEntry;
	INT32	begin = 0;
	INT32	result;
	EXT2_DIR_ENTRY* entry;
	
	entriesPerSector = fs->disk->bytesPerSector / sizeof(EXT2_DIR_ENTRY);
	lastEntry = entriesPerSector -1;
	
	read_root_sector(fs,sector);

	entry = ( EXT2_DIR_ENTRY* )sector;

	result = find_entry_at_sector( sector, formattedName, begin, lastEntry, &number );
	
	begin = 0;
	if( result == -1 ) //탐색실패
			EXT2_ERROR;
		else
		{
			if( result == -2 ) // 찾은 Directory entry가 없을 경우
				return EXT2_ERROR;
			else // 찾은 경우
			{
				memcpy( &ret->entry, &entry[number], sizeof( EXT2_DIR_ENTRY ) );
				// formattedName으로 검색하여 찾은 FAT_DIR_ENTRY를 ret->entry에 write

				ret->location.group	= 0;
				// cluster위치 고정

				ret->location.block	= 0;
				// sector의 실제 위치

				ret->location.offset = number;
				// sector내부에서의 실제 인덱스

				ret->fs = fs;
				// 파일 시스템 연결
			}

			return EXT2_SUCCESS;
		}


}

int find_entry_on_data(EXT2_FILESYSTEM* fs, INODE first, const BYTE* formattedName, EXT2_NODE* ret)
{
	BYTE	sector[MAX_SECTOR_SIZE];
	UINT32	i, number;
	UINT32	lastSector;
	UINT32	entriesPerSector, lastEntry;
	INT32	begin = 0;
	INT32	result;
	EXT2_DIR_ENTRY* entry;
	
	INT32 currentBlock = 0;
	entriesPerSector = fs->disk->bytesPerSector / sizeof(EXT2_DIR_ENTRY);
	lastEntry = entriesPerSector -1;

	while (-1)
	{
		read_data_sector( fs, first, currentBlock, sector );
		entry = ( EXT2_DIR_ENTRY* )sector;
		result = find_entry_at_sector( sector, formattedName, begin, lastEntry, &number );
		begin = 0;
		if( result == -1 ) //DIR_ENTRY_NO_MORE 만남
			break;
		else
		{
			if( result == -2 ) //엔트리 끝 (DIR_ENTRY_NO_MORE 만남)
				return EXT2_ERROR;
			else //찾
			{
				memcpy( &ret->entry, &entry[number], sizeof( EXT2_DIR_ENTRY ) );
				
				ret->location.group	= first.gid;
				ret->location.block	= currentBlock;
				ret->location.offset	= number;
				
				ret->fs = fs;
				//찾은 정보 ret에 복사
			}

			return EXT2_SUCCESS;
		}
		currentBlock++;

	}

	return EXT2_ERROR;

}


int get_inode_table_block(EXT2_FILESYSTEM* fs, const UINT32 inode, BYTE* inodeTableSector, int *begin)
{
	QWORD sector_num_per_group = (fs->disk->numberOfSectors - 1) / NUMBER_OF_GROUPS;
	const int BOOT_SECTOR_BASE = 1;
	int group_number, ret;

	group_number = (inode-1) / fs->sb.inode_per_group;
	*begin = fs->sb.inode_per_group * group_number;
	ret = fs->disk->read_sector(fs->disk, sector_num_per_group * group_number + BOOT_SECTOR_BASE + fs->gd.start_block_of_inode_table, inodeTableSector);

	return ret;
}

int prepare_inode_table_block(EXT2_FILESYSTEM* fs, const UINT32 inode, BYTE* inodeTableSector, int* begin)// 예외처리 필요
{
	get_inode_table_block(fs, inode, inodeTableSector, begin);
}

int get_inode(EXT2_FILESYSTEM* fs, const UINT32 inode, INODE *inodeBuffer)
{
	BYTE sector[MAX_SECTOR_SIZE];
	int i, begin;
	DWORD sectorOffset;
	INODE *inode_ptr;

	ZeroMemory(sector, sizeof(sector));

	prepare_inode_table_block(fs, inode, sector, &begin);
	printf("inode : %d\nbegin : %d\n", inode, begin);
	inode_ptr = (INODE *)sector;	// begin block of the inode Table
	
	for(i = begin+1; i < inode; i++)
	{
		inode_ptr++;
	}
	*inodeBuffer = *inode_ptr;
}

// root 섹터 메타데이터 정해뒀음
int read_root_sector(EXT2_FILESYSTEM* fs, BYTE* sector)
{
	UINT32 inode = 2;
	INODE inodeBuffer;
	SECTOR rootBlock;
	get_inode(fs, inode, &inodeBuffer);
	rootBlock = get_data_block_at_inode(fs, inodeBuffer, 1);
	return data_read(fs, 0, rootBlock, sector);
}
int read_data_sector(EXT2_FILESYSTEM* fs, INODE first, UINT32 currentBlock, BYTE* sector)
{	
	SECTOR data_block = get_data_block_at_inode(fs, first, currentBlock);
	return fs->disk->read_sector(fs->disk, data_block, sector);
}
int ext2_create(EXT2_NODE* parent, char* entryName, EXT2_NODE* retEntry)
{
	if ((parent->fs->gd.free_inodes_count) == 0) return EXT2_ERROR;
	UINT32 inode;
	BYTE name[MAX_NAME_LENGTH] = { 0, };
	BYTE sector[MAX_BLOCK_SIZE];
	int result;

	strcpy(name, entryName);
	if (format_name(parent->fs, name) == EXT2_ERROR) return EXT2_ERROR;

	ZeroMemory(retEntry, sizeof(EXT2_NODE));
	memcpy(retEntry->entry.name, name, MAX_ENTRY_NAME_LENGTH);
	retEntry->fs = parent->fs;
	inode = parent->entry.inode;
	if ((result = lookup_entry(parent->fs, inode, name, retEntry)) == EXT2_SUCCESS) return EXT2_ERROR;
	else if (result == -2) return EXT2_ERROR;

	if (insert_entry(inode, retEntry, 0) == EXT2_ERROR)return EXT2_ERROR;
	return EXT2_SUCCESS;
}

int get_data_block_at_inode(EXT2_FILESYSTEM *fs, INODE inode, UINT32 number)
{
	BYTE sector[MAX_SECTOR_SIZE];
	unsigned int *block_pointer;
	unsigned int indirect_pointer_per_sector;
	
	indirect_pointer_per_sector = MAX_SECTOR_SIZE / sizeof(UINT32);
	if ( (1 <= number) && (number <= 12) )	// direct block
	{
		printf("get data : %u\n", inode.block[0]);
		return inode.block[number - 1];
	}
	else if ( number <= 12 + indirect_pointer_per_sector )	// single indirect block
	{
		fs->disk->read_sector(fs->disk, inode.block[12], sector);		
		block_pointer = (unsigned int *)sector;
		for(int i=13; i < number-12; i++)	// 13 ~ 268
			block_pointer++;

		return *block_pointer;
	}
	else if ( number <= 12 + indirect_pointer_per_sector + indirect_pointer_per_sector * indirect_pointer_per_sector )	// double indirect block
	{
		int index = (number - 12 - indirect_pointer_per_sector);
		fs->disk->read_sector(fs->disk, inode.block[13], sector);
		block_pointer = (unsigned int *)sector;
		for(int i=0; i < index / indirect_pointer_per_sector; i++)
		{
			block_pointer++;			
		}
		fs->disk->read_sector(fs->disk, *block_pointer, sector);
		block_pointer = (unsigned int *)sector;
		for(int i=1; i < index % indirect_pointer_per_sector; i++)
		{
			block_pointer++;
		}

		return *block_pointer;
	}
	else if ( number <= 12 + indirect_pointer_per_sector + indirect_pointer_per_sector * indirect_pointer_per_sector +
	indirect_pointer_per_sector * indirect_pointer_per_sector * indirect_pointer_per_sector )	// triple indirect block
	{
		int index = (number - 12 - indirect_pointer_per_sector - indirect_pointer_per_sector * indirect_pointer_per_sector);
		fs->disk->read_sector(fs->disk, inode.block[14], sector);
		block_pointer = (unsigned int *)sector;
		for(int i=0; i < index / (indirect_pointer_per_sector*indirect_pointer_per_sector); i++)
		{
			block_pointer++;
		}
		fs->disk->read_sector(fs->disk, *block_pointer, sector);
		block_pointer = (unsigned int *)sector;
		for(int i=0; i < index / indirect_pointer_per_sector; i++)
		{
			block_pointer++;
		}
		fs->disk->read_sector(fs->disk, *block_pointer, sector);
		block_pointer = (unsigned int *)sector;
		for(int i=1; i < index % (indirect_pointer_per_sector*indirect_pointer_per_sector); i++)
		{
			block_pointer++;
		}

		return *block_pointer;
	}
	else
	{
		return EXT2_ERROR;
	}
	
}

int ext2_read_superblock(EXT2_FILESYSTEM* fs, EXT2_NODE* root)
{
	INT result;
	BYTE sector[MAX_SECTOR_SIZE];

	if (fs == NULL || fs->disk == NULL)
	{
		WARNING("DISK OPERATIONS : %p\nEXT2_FILESYSTEM : %p\n", fs, fs->disk);
		return EXT2_ERROR;
	}

	meta_read(fs, 0, SUPER_BLOCK, sector);
	memcpy(&fs->sb, sector, sizeof(EXT2_SUPER_BLOCK));
	meta_read(fs, 0, GROUP_DES, sector);
	memcpy(&fs->gd, sector, sizeof(EXT2_GROUP_DESCRIPTOR));

	if (fs->sb.magic_signature != 0xEF53)
		return EXT2_ERROR;

	ZeroMemory(sector, sizeof(MAX_SECTOR_SIZE));
	if (read_root_sector(fs, sector))
		return EXT2_ERROR;

	ZeroMemory(root, sizeof(EXT2_NODE));
	memcpy(&root->entry, sector, sizeof(EXT2_DIR_ENTRY));
	root->fs = fs;

	return EXT2_SUCCESS;
}

UINT32 get_free_inode_number(EXT2_FILESYSTEM* fs)
{
	BYTE sector[MAX_SECTOR_SIZE];
	UINT32 i;
	UINT32 begin=0;  
	UINT32 number_of_blocks_for_group = (fs->disk->numberOfSectors-1)/2;
	UINT32 max_inode_num_for_group = fs->sb.inode_per_group;
		//한 그룹당 아이노드 비트맵의 마지막 넘버
		//데이터 영역 블록 수 = 그룹당 블록개수 - 데이터 영역 이전 블록개수 
		//아이노드 테이블 수 = 예약된 블록 수 + 데이터 영역 블록 수
	UINT32 last = (max_inode_num_for_group+7) / 8;//(소숫점 생길 경우 올림연산위해 +7)
	UINT32 group_num = 0;
	while(group_num < NUMBER_OF_GROUPS){// 그룹 수 만큼 반복
		data_read(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
		for( i = begin; i < last; i++ ) 
		{
			int j=1;
			BYTE bit = sector[i];
			while(j<9){
				if (8*i+j>max_inode_num_for_group){ // 그룹당 아이노드 최대 넘버 초과시 다음 그룹으로 이동
						break;
					}
				if(8*i+j >10 && bit & 0x01==0){ //비트가 0이고 아이노드넘버가 10 초과이면
					UINT32 inode_num = 8*i+j + group_num*max_inode_num_for_group;
					if( inode_num < fs->sb.max_inode_count) //inode_max보다 작은지 검사
						return inode_num;
					else
						return EXT2_ERROR; 

				}
				bit >>1;
				j++;
			}
		}//그룹 하나 돌고
		group_num++; //다 돌았으면 다음그룹
	} 
	return EXT2_ERROR; 
}

int set_inode_onto_inode_table(EXT2_FILESYSTEM *fs, const UINT32 which_inode_num_to_write, INODE * inode_to_write)
{ 
	BYTE sector[MAX_SECTOR_SIZE];
	UINT32 group_num=0;
	if (which_inode_num_to_write > fs->sb.inode_per_group){
		group_num++;
	}
	data_read(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
	UINT32 i = which_inode_num_to_write/8;
	UINT32 j = which_inode_num_to_write%8;
	BYTE* bit = &sector[i];
	BYTE marker = 0x01 << j-1;
	*bit = *bit | marker;
	data_write(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
	return EXT2_SUCCESS;
}

int ext2_lookup(EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	EXT2_DIR_ENTRY_LOCATION	begin;
	BYTE	formattedName[MAX_NAME_LENGTH] = { 0, };

	strcpy(formattedName, entryName);

	if (format_name(parent->fs, formattedName))
		return EXT2_ERROR;

	return lookup_entry(parent->fs, parent->entry.inode, formattedName, retEntry);
}

int ext2_read_dir(EXT2_NODE* dir, EXT2_NODE_ADD adder, void* list)
{
	BYTE   sector[MAX_SECTOR_SIZE];
	INODE* inodeBuffer;
	UINT32 inode;
	int i, result, num;

	inodeBuffer = (INODE*)malloc(sizeof(INODE));

	ZeroMemory(sector, MAX_SECTOR_SIZE);
	ZeroMemory(inodeBuffer, sizeof(INODE));

	result = get_inode(dir->fs, dir->entry.inode, inodeBuffer);
	if (result == EXT2_ERROR)
		return EXT2_ERROR;

	for (i = 0; i < inodeBuffer->blocks; ++i)
	{
		num = get_data_block_at_inode(dir->fs, *inodeBuffer, i + 1);
		data_read(dir->fs, 0, num, sector);

		if (dir->entry.inode == 2)
			read_dir_from_sector(dir->fs, sector + 32, adder, list);
		else
			read_dir_from_sector(dir->fs, sector, adder, list);
	}

	return EXT2_SUCCESS;
}

int read_dir_from_sector(EXT2_FILESYSTEM* fs, BYTE* sector, EXT2_NODE_ADD adder, void* list)
{
	UINT i, max_entries_Per_Sector;
	EXT2_DIR_ENTRY*   dir;
	EXT2_NODE   node;

	max_entries_Per_Sector = MAX_SECTOR_SIZE / sizeof(EXT2_DIR_ENTRY);
	dir = (EXT2_DIR_ENTRY*)sector;

	for (i = 0; i < max_entries_Per_Sector; i++)
	{
		if (dir->name[0] == DIR_ENTRY_FREE)
			;
		else if (dir->name[0] == DIR_ENTRY_NO_MORE)
			break;
		else
		{
			node.fs = fs;
			node.entry = *dir;
			adder(fs, list, &node);
		}
		dir++;
	}

	return (i == max_entries_Per_Sector ? 0 : -1);
}

char* my_strncpy(char* dest, const char* src, int length)
{
	while (*src && *src != 0x20 && length-- > 0)
		*dest++ = *src++;

	return dest;
}

int ext2_mkdir(const EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	EXT2_NODE      dotNode, dotdotNode;
	DWORD         firstCluster;
	BYTE         name[MAX_NAME_LENGTH];
	int            result;
	int            i;

	strcpy((char*)name, entryName);

	if (format_name(parent->fs, (char*)name))
		return EXT2_ERROR;

	ZeroMemory(retEntry, sizeof(EXT2_NODE));
	memcpy(retEntry->entry.name, name, MAX_ENTRY_NAME_LENGTH);
	retEntry->entry.name_len = strlen((char*)retEntry->entry.name);
	retEntry->fs = parent->fs;

	result = insert_entry(parent->entry.inode, retEntry, FILE_TYPE_DIR);
	if (result == EXT2_ERROR)
		return EXT2_ERROR;

	expand_block(parent->fs, retEntry->entry.inode);

	ZeroMemory(&dotNode, sizeof(EXT2_NODE));
	memset(dotNode.entry.name, 0x20, 11);
	dotNode.entry.name[0] = '.';
	dotNode.fs = retEntry->fs;
	dotNode.entry.inode = retEntry->entry.inode;
	insert_entry(retEntry->entry.inode, &dotNode, FILE_TYPE_DIR);

	ZeroMemory(&dotdotNode, sizeof(EXT2_NODE));
	memset(dotdotNode.entry.name, 0x20, 11);
	dotdotNode.entry.name[0] = '.';
	dotdotNode.entry.name[1] = '.';
	dotdotNode.entry.inode = parent->entry.inode;
	dotdotNode.fs = retEntry->fs;
	insert_entry(retEntry->entry.inode, &dotdotNode, FILE_TYPE_DIR);

	return EXT2_SUCCESS;
}