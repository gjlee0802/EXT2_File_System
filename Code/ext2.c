#include "shell.h"
 typedef struct
{
	char*	address;
} DISK_MEMORY;

#include "ext2.h"
#define MIN( a, b )					( ( a ) < ( b ) ? ( a ) : ( b ) )
#define MAX( a, b )					( ( a ) > ( b ) ? ( a ) : ( b ) )

int ext2_write(EXT2_NODE* file, unsigned long offset, unsigned long length, const char* buffer)
{
	PRINTF("ENTER ext2_write\n");
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
			PRINTF("expand\n");
			if (expand_block(file->fs, file->entry.inode) == EXT2_ERROR)
				return EXT2_ERROR;
			process_meta_data_for_block_used(file->fs, file->entry.inode);
			get_inode(file->fs, file->entry.inode, &node);
			PRINTF("inode.block[0] : %u\n", node.block[0]);
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
				PRINTF("expand\n");
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
			//if (data_read(file->fs, 0, currentBlock, sector))
			if (file->fs->disk->read_sector(file->fs->disk, currentBlock, sector))
				break;
		}

		memcpy(&sector[sectorOffset],
			buffer,
			copyLength);

		//if (data_write(file->fs, 0, currentBlock, sector))
		if(file->fs->disk->write_sector(file->fs->disk, currentBlock, sector))
			break;

		buffer += copyLength;
		currentOffset += copyLength;
	}

	node.size = MAX(currentOffset, node.size);
	set_inode_onto_inode_table(file->fs, file->entry.inode, &node);

	get_inode(file->fs, file->entry.inode, &node);
	PRINTF("node.size : %u\n", node.size);

	return currentOffset - offset;
}

int get_free_inode_number(EXT2_FILESYSTEM* fs);

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
	sector[2] = 0x01;//00000001
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
	ip->size = 0;
	ip->blocks = 1;
	ip->block[0] = sb->first_data_block_each_group + 1;	//->18 |  ip->block[0] = sb->first_data_block_each_group

	disk->write_sector(disk, BOOT_SECTOR_BASE + 4, sector);

	return EXT2_SUCCESS;
}

void process_meta_data_for_inode_used(EXT2_NODE * retEntry, UINT32 inode_num, int fileType) // insertentry에서 inode 생성 시
{
	/*
	BYTE sector[MAX_SECTOR_SIZE];
	UINT32 group_num=0;
	if (inode_num > fs->sb.inode_per_group){
		group_num++;
	}
	data_read(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
	UINT32 i = inode_num/8;
	UINT32 j = inode_num%8;
	BYTE* bit = &sector[i];
	BYTE marker = 0x01 << j-1;
	*bit = *bit | marker;
	data_write(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
	//------- inode비트맵 수정
	//------- 수퍼블록 수정
	*/
}

int set_entry(EXT2_FILESYSTEM* fs, const EXT2_DIR_ENTRY_LOCATION* location, const EXT2_DIR_ENTRY* value)
{ 
	BYTE	sector[MAX_SECTOR_SIZE];
	EXT2_DIR_ENTRY* entry;
	if( location->group == 0 && location->block == 0 )
	{
		printf("FLAG1\n");
		read_root_sector(fs, sector);   // 루트 섹터의 내용을 섹터 버퍼에 저장
		entry = (EXT2_DIR_ENTRY*)sector;   // 섹터 버퍼를 디릭토리 엔트리로써 접근할 수 있도록 type casting
		//PRINTF("test : %u\n", location->offset);
		//entry[location->offset] = *value;   // 섹터 버퍼 내 엔트리 위치에 newEntry->entry의 값을 set
		for(int i=0; i<location->offset; i++)
			entry++;
		*entry = *value;
		write_root_sector(fs, sector);
	}
	else
	{
		printf("FLAG2\n");
		// 루트 그룹 외 그릅에 접근 하여 그릅의 섹터 내용을 섹터 버퍼에 저장
		data_read(fs, location->group, location->block, sector);
		entry = (EXT2_DIR_ENTRY*)sector;
		entry[location->offset] = *value;
		data_write(fs, location->group, location->block, sector);
	}

	return EXT2_ERROR;
}

int expand_inode(EXT2_FILESYSTEM* fs, UINT32* inum)
{
    int new_i_num = get_free_inode_number(fs);
	printf("get free inode : %u\n", new_i_num);
    INODE inode;
    if(get_inode(fs, new_i_num, &inode) != EXT2_SUCCESS)
        return EXT2_ERROR;
    *inum = new_i_num;
    inode.block[0]=0;
    inode.blocks=0;
    inode.mode= 0x1FF | 0x4000;
    inode.size = 0;
    set_inode_onto_inode_table(fs, new_i_num, &inode);
    return EXT2_SUCCESS;
}

int insert_entry(EXT2_NODE * parent, EXT2_NODE * retEntry, BYTE overwrite)
{
	EXT2_DIR_ENTRY_LOCATION begin;
	INODE                  inodeBuffer;
	EXT2_SUPER_BLOCK        sb = parent->fs->sb;
	EXT2_NODE               entryNoMore;
	//BYTE                    buffer[MAX_BLOCK_SIZE];
	BYTE                    entryName[2] = { 0, };
	UINT32                  result;

	if ( get_inode( parent->fs, parent->entry.inode, &inodeBuffer ) != EXT2_SUCCESS){
		return EXT2_ERROR;
	}
	// inode에 해당하는 데이터 블록 반환 , inode에 속한 첫번째 데에터 블록 가져옴
	result = get_data_block_at_inode(parent->fs, inodeBuffer, 1);  // 1번째 데이터 블록의 번호 가져옴

	printf("get data block : %d\n", result);
	begin.group = parent->location.group;
	begin.block = parent->location.block;
	begin.offset = parent->location.offset;
	
	if(overwrite)
	{
		begin.offset = 0;
		expand_inode(parent->fs, &retEntry->entry.inode);
		set_entry(parent->fs, &begin, &retEntry->entry);
		retEntry->location = begin;
		begin.offset = 1;
		ZeroMemory(&entryNoMore, sizeof(EXT2_NODE));
		entryNoMore.entry.name[0] = DIR_ENTRY_NO_MORE;
		set_entry(parent->fs, &begin, &entryNoMore.entry);

		return EXT2_SUCCESS;
	}
	
	entryName[0] = DIR_ENTRY_FREE;       //  빈 entry 찾아아됨.
	
	if( lookup_entry(parent->fs, parent->entry.inode, entryName, &entryNoMore) == EXT2_SUCCESS)
	{
		printf("(1)\n");
		expand_inode(parent->fs, &retEntry->entry.inode);
		set_entry(parent->fs, &entryNoMore.location, &retEntry->entry);
		retEntry->location = entryNoMore.location;
	}
	else	// 빈 엔트리 못 찾았을 경우
	{
		printf("(2)\n");
		entryName[0] = DIR_ENTRY_NO_MORE;
		if( lookup_entry(parent->fs, parent->entry.inode, entryName, &entryNoMore) == EXT2_ERROR)
			return EXT2_ERROR;
		expand_inode(parent->fs, &retEntry->entry.inode);
		//PRINTF("location.block : %u\n", entryNoMore.location.block);
		//PRINTF("location.offset : %u\n", entryNoMore.location.offset);
		set_entry(parent->fs, &entryNoMore.location, &retEntry->entry);
		retEntry->location = entryNoMore.location;

		entryNoMore.location.offset++;

		if(entryNoMore.location.offset == MAX_BLOCK_SIZE / sizeof(EXT2_DIR_ENTRY))
		{
			// 빈 데이터 블록 할당
			if(expand_block(parent->fs, parent->entry.inode) != EXT2_SUCCESS)
				return EXT2_ERROR;

			ZeroMemory(&inodeBuffer, sizeof(INODE));

			if(get_inode(parent->fs, parent->entry.inode, &inodeBuffer) != EXT2_SUCCESS)
				return EXT2_ERROR;
			
			result = get_data_block_at_inode(parent->fs, inodeBuffer, inodeBuffer.blocks);
			entryNoMore.location.group = (result-1) / sb.block_per_group;
			entryNoMore.location.block = (result-1) % sb.block_per_group;
			entryNoMore.location.offset = 0; 
		}

		set_entry(parent->fs, &entryNoMore.location, &entryNoMore.entry);
	}
	PRINTF("insert entry COMPLETE\n");
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
				if(((bit & 0x01)==0) && (data_num >17)){ //비트가 0이고 데이터 넘버가 17 초과이면	
					sector[i] |= (0x01 << j-1); // 해당 비트 1로 변환 후
					PRINTF("datanum : %u\n", data_num);
					data_write(fs, group_num, fs->gd.start_block_of_block_bitmap, sector); //변환내용 write
					return (data_num-1)+group_num*fs->sb.block_per_group+1; //data_read사용 할 경우 필요 없음
						//실제 블록 번호 반환 <디스크를 섹터로 인덱싱 했을때의 해당 블록 번호>
				}
				bit = bit >> 1;
				j++;
			}
		}//그룹 하나 돌고
		group_num++; //다 돌았으면 다음그룹
	} 
	return EXT2_ERROR; 
}

int process_meta_data_for_block_used(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
	BYTE sector[MAX_SECTOR_SIZE];
	
	/*
	UINT32 group_num=0;
	if (inode_num > fs->sb.){
		group_num++;
	}
	data_read(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
	UINT32 i = inode_num/8;
	UINT32 j = inode_num%8;
	BYTE* bit = &sector[i];
	BYTE marker = 0x01 << j-1;
	*bit = *bit | marker;
	data_write(fs, group_num, fs->gd.start_block_of_inode_bitmap, sector);
	*/
	fs->sb.free_block_count--;
	fs->gd.free_blocks_count--;
	UINT32 gi;
	EXT2_SUPER_BLOCK* sb_read = (EXT2_SUPER_BLOCK *)sector;
	for (gi = 0; gi < NUMBER_OF_GROUPS; gi++)
	{
		fs->disk->read_sector(fs->disk, fs->sb.block_per_group * gi + 1, sector);
		sb_read->free_block_count--;
		fs->disk->write_sector(fs->disk, fs->sb.block_per_group * gi + 1, sector);
	}
	EXT2_GROUP_DESCRIPTOR* gd = (EXT2_GROUP_DESCRIPTOR *)sector;
	fs->disk->read_sector(fs->disk, 1 + 1, sector);
	gd->free_blocks_count--;
	fs->disk->write_sector(fs->disk, 1 + 1, sector);
	// fs내의 수퍼블록이랑 gd만 수정해주면 되는지 ? Or 디스크의 수퍼블록 영역 가서 리드 라이트 해줘야 하는지 ?
	
	
	//------- data block 비트맵 수정
	
	//------- 수퍼블록 수정
}

int expand_indirect(EXT2_FILESYSTEM *fs, INODE *inodeBuffer, UINT32 inode_num, const unsigned int block_number)	// block_number: expand할 block_number -> indirect block을 expand 해야하는지 검사
{
	UINT32 new_block;
	BYTE sector[1024];
	unsigned int *block_pointer;
	UINT32 index;
	unsigned int indirect_pointer_per_sector;

	indirect_pointer_per_sector = MAX_SECTOR_SIZE / sizeof(UINT32);

	PRINTF("indirect : %u\n", block_number);
	if ( block_number == 13 )	// check if single indirect block is needed
	{
		// expand single indirect
		new_block = get_available_data_block(fs);
		inodeBuffer->block[12] = new_block;
		if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)	
			return EXT2_ERROR;
		inodeBuffer->blocks++;
	}
	else if( block_number > 13)
	{
		if ( block_number <= 12 + indirect_pointer_per_sector + indirect_pointer_per_sector*indirect_pointer_per_sector )	// check if double indirect block is needed
		{
			index = (block_number - 12 - indirect_pointer_per_sector - 1);	// index: 0부터 시작, triple indirect 범위 내에서의 index

			// expand first layer indirect block (처음으로 첫번째 계층이 필요한 경우)
			if( block_number == 12 + indirect_pointer_per_sector + 1)
			{
				new_block = get_available_data_block(fs);
				inodeBuffer->block[13] = new_block;
				if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)	
					return EXT2_ERROR;
				inodeBuffer->blocks++;
			}
			// expand second layer indirect block 
			if( index % indirect_pointer_per_sector == 0)
			{
				fs->disk->read_sector(fs->disk, inodeBuffer->block[13], sector);
				block_pointer = (unsigned int *)sector;

				for(int i=0; i < index / indirect_pointer_per_sector; i++)
				{
					block_pointer++;
				}
				new_block = get_available_data_block(fs);
				*block_pointer = new_block;
				if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)	
					return EXT2_ERROR;
				inodeBuffer->blocks++;
			}
		}
		else if( block_number <= 12 + indirect_pointer_per_sector + 
		indirect_pointer_per_sector*indirect_pointer_per_sector + 
		indirect_pointer_per_sector*indirect_pointer_per_sector*indirect_pointer_per_sector )	// check if triple indirect block is needed
		{
			index = (block_number - 12 - indirect_pointer_per_sector - indirect_pointer_per_sector * indirect_pointer_per_sector - 1);	//index: 0부터 시작, triple indirect 범위 내에서의 index

			// expand first layer indirect block
			if(block_number == 12 + indirect_pointer_per_sector + indirect_pointer_per_sector*indirect_pointer_per_sector + 1)
			{
				new_block = get_available_data_block(fs);
				inodeBuffer->block[14] = new_block;
				if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)	
					return EXT2_ERROR;
				inodeBuffer->blocks++;
			}
			// expand second layer indirect block
			if( index % (indirect_pointer_per_sector*indirect_pointer_per_sector) == 0)
			{
				fs->disk->read_sector(fs->disk, inodeBuffer->block[14], sector);	// read first layer indirect
				block_pointer = (unsigned int *)sector;

				for(int i=0; i < index / indirect_pointer_per_sector; i++)
				{
					block_pointer++;
				}
				new_block = get_available_data_block(fs);
				*block_pointer = new_block;											// get new block for second layer indirect
				if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)	
					return EXT2_ERROR;
				inodeBuffer->blocks++;
				
			}
			// expand third layer indirect block
			if( index % indirect_pointer_per_sector == 0)
			{
				fs->disk->read_sector(fs->disk, inodeBuffer->block[14], sector);	// read first layer indirect
				block_pointer = (unsigned int *)sector;

				for(int i=0; i < index / indirect_pointer_per_sector; i++)
				{
					block_pointer++;
				}
				
				fs->disk->read_sector(fs->disk, *block_pointer, sector);			// read second layer indirect
				block_pointer = (unsigned int *)sector;

				for(int i=0; i < index % (indirect_pointer_per_sector*indirect_pointer_per_sector); i++)
				{
					block_pointer++;
				}
				new_block = get_available_data_block(fs);
				*block_pointer = new_block;											// get new block for third layer indirect
				if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)	
					return EXT2_ERROR;
				inodeBuffer->blocks++;
			}
		}
	}
	else
	{
		PRINTF("DO NOT EXPAND INDIRECT\n");
	}
	
}



int expand_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)	// indirect가 필요하면 indirect를 expand하는 방식.
{
	INODE *inodeBuffer;
	UINT32 new_block;
	unsigned int block_number_at_inode;
	BYTE sector[1024];
	UINT32 indirect_ptr_per_sector;

	get_inode(fs, inode_num, inodeBuffer);
	block_number_at_inode = inodeBuffer->blocks + 1;
	expand_indirect(fs, inodeBuffer, inode_num, block_number_at_inode);	// indirect block을 expand 해야하는지 검사, expand가 필요하면 expand.

	new_block = get_available_data_block(fs);
	/*
	ZeroMemory(sector, 0);
	memcpy(sector, &new_block, sizeof(new_block));
	if(fs->disk->write_sector(fs->disk, get_data_block_at_inode(fs, inodeBuffer, block_number_at_inode), sector) == EXT2_ERROR)
	{
		return EXT2_ERROR;
	}
	*/
	if(block_number_at_inode < 13)
	{
		PRINTF("newblock : %d\n", new_block);
		inodeBuffer->block[block_number_at_inode-1] = new_block;
	}
	else
	{
		unsigned int *block_pointer;
		unsigned int temp;
		unsigned int indirect_pointer_per_sector;
	
		indirect_pointer_per_sector = MAX_SECTOR_SIZE / sizeof(UINT32);
		if ( block_number_at_inode <= 12 + indirect_pointer_per_sector )	// single indirect block
		{
			fs->disk->read_sector(fs->disk, inodeBuffer->block[12], sector);	
			block_pointer = (unsigned int *)sector;
			for(int i=13; i < block_number_at_inode-12; i++)	// 13 ~ 268
				block_pointer++;

			*block_pointer = new_block;//
			fs->disk->write_sector(fs->disk, inodeBuffer->block[12], sector);
		}
		else if ( block_number_at_inode <= 12 + indirect_pointer_per_sector + indirect_pointer_per_sector * indirect_pointer_per_sector )	// double indirect block
		{
			unsigned int index = (block_number_at_inode - 12 - indirect_pointer_per_sector);	// index: 1부터 시작
			fs->disk->read_sector(fs->disk, inodeBuffer->block[13], sector);
			block_pointer = (unsigned int *)sector;
			for(int i=0; i < index / indirect_pointer_per_sector; i++)
			{
				block_pointer++;
			}
			temp = *block_pointer;
			fs->disk->read_sector(fs->disk, *block_pointer, sector);
			block_pointer = (unsigned int *)sector;
			for(int i=1; i < index % indirect_pointer_per_sector; i++)
			{
				block_pointer++;
			}

			*block_pointer = new_block;	//
			fs->disk->write_sector(fs->disk, temp, sector);
		}
		else if ( block_number_at_inode <= 12 + indirect_pointer_per_sector + indirect_pointer_per_sector * indirect_pointer_per_sector +
		indirect_pointer_per_sector * indirect_pointer_per_sector * indirect_pointer_per_sector )	// triple indirect block
		{
			unsigned int index = (block_number_at_inode - 12 - indirect_pointer_per_sector - indirect_pointer_per_sector * indirect_pointer_per_sector);
			fs->disk->read_sector(fs->disk, inodeBuffer->block[14], sector);
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
			temp = *block_pointer;
			fs->disk->read_sector(fs->disk, *block_pointer, sector);
			block_pointer = (unsigned int *)sector;
			for(int i=1; i < index % (indirect_pointer_per_sector*indirect_pointer_per_sector); i++)
			{
				block_pointer++;
			}

			*block_pointer = new_block;	//
			fs->disk->write_sector(fs->disk, temp, sector);
		}
	}
	
	
	if(process_meta_data_for_block_used(fs, inode_num) == EXT2_ERROR)
	{
		return EXT2_ERROR;
	}
	inodeBuffer->blocks++;
	PRINTF("expand ' blocks : %u\n", inodeBuffer->blocks);
	PRINTF("expand ' block[0] : %u\n", inodeBuffer->block[0]);
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

/*
 * (수정 사항)
 * root의 data block에 엔트리가 찼을 경우, 다음 data block을 expand하여 그 data block에 엔트리를 추가할 수 있다면,
 * 	for(i=1; i <= inode.blocks; i++)
 *		fs->disk->read_sector(fs->disk, get_data_block_at_inode(fs, inode, i), sector);
 * 와 같이 반복문을 돌며 다음 data block로 넘어가서 entry를 검사할 수 있도록 해야함.
 */
int find_entry_on_root(EXT2_FILESYSTEM* fs, INODE inode, char* formattedName, EXT2_NODE* ret)
{
	BYTE	sector[MAX_SECTOR_SIZE];
	UINT32	i, number;
	UINT32	entriesPerSector, lastEntry;
	INT32	begin = 0;
	INT32	result;
	EXT2_DIR_ENTRY* entry;
	
	entriesPerSector = fs->disk->bytesPerSector / sizeof(EXT2_DIR_ENTRY);
	lastEntry = entriesPerSector -1;
	
	//read_root_sector(fs, sector);
	for(i=1; i <= inode.blocks; i++)
	{
		fs->disk->read_sector(fs->disk, get_data_block_at_inode(fs, inode, i), sector);
		entry = ( EXT2_DIR_ENTRY* )sector;

		result = find_entry_at_sector( sector, formattedName, begin, lastEntry, &number );
	
		begin = 0;
		if( result == -1 ) //탐색실패
			;
		else
		{
			if( result == -2 ) // 찾은 Directory entry가 없을 경우
				return EXT2_ERROR;
			else // 찾은 경우
			{
				memcpy( &ret->entry, &entry[number], sizeof( EXT2_DIR_ENTRY ) );
				// formattedName으로 검색하여 찾은 FAT_DIR_ENTRY를 ret->entry에 write

				ret->location.group	= 0;
				// group위치 고정

				ret->location.block	= 0;
				// block 위치

				ret->location.offset = number;
				// sector내부에서의 실제 인덱스

				ret->fs = fs;
				// 파일 시스템 연결
			}

			return EXT2_SUCCESS;
		}
	}
	return EXT2_ERROR;
}

/*
 * (수정 사항)
 * for(int i=1; i <= inode.blocks; i++)
 * 		get_data_block_at_inode(fs, inode, i(반복문 변수));
 * 와 같이 반복문을 돌며 inode의 다음 data block로 넘어가서 entry를 검사할 수 있도록 함.
 * 수정후 -> read_data_sector를 안쓰면 get_data_block 호출 2번 -> 1번으로 호출 횟수가 줄어듦
 */
int find_entry_on_data(EXT2_FILESYSTEM* fs, INODE inode, const BYTE* formattedName, EXT2_NODE* ret)
{
	BYTE	sector[MAX_SECTOR_SIZE];
	UINT32	i, number;
	UINT32	entriesPerSector, lastEntry;
	INT32	begin = 0;
	INT32	result;
	SECTOR  data_block;
	EXT2_DIR_ENTRY* entry;
	
	INT32 currentBlock = 0;
	entriesPerSector = fs->disk->bytesPerSector / sizeof(EXT2_DIR_ENTRY);
	lastEntry = entriesPerSector -1;

	//while (-1)
	for(int i=1; i <= inode.blocks; i++)	// 연결된 data block의 개수만큼 반복문을 돌도록 함.
	{
		//read_data_sector( fs, inode, currentBlock, sector );
		data_block = get_data_block_at_inode(fs, inode, i);
		fs->disk->read_sector(fs->disk, data_block, sector);

		entry = ( EXT2_DIR_ENTRY* )sector;
		result = find_entry_at_sector( sector, formattedName, begin, lastEntry, &number );
		begin = 0;
		if( result == -1 ) // 현재 섹터에서는 NO_MORE 못 만나고 탐색 실패
			;
		else
		{
			if( result == -2 ) //엔트리 끝 (DIR_ENTRY_NO_MORE 만남)
				return EXT2_ERROR;
			else // 찾음
			{
				memcpy( &ret->entry, &entry[number], sizeof( EXT2_DIR_ENTRY ) );
				//SECTOR data_block = get_data_block_at_inode(fs, inode, currentBlock);
				ret->location.group	= (data_block-1) / fs->sb.block_per_group;
				ret->location.block	= (data_block-1) % fs->sb.block_per_group;
				ret->location.offset	= number;
				ret->fs = fs;
				//찾은 정보 ret에 복사
			}

			return EXT2_SUCCESS;
		}
		//currentBlock++;
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
	return get_inode_table_block(fs, inode, inodeTableSector, begin);
}

int get_inode(EXT2_FILESYSTEM* fs, const UINT32 inode, INODE *inodeBuffer)
{
	BYTE sector[MAX_SECTOR_SIZE];
	int i, begin;
	DWORD sectorOffset;
	INODE *inode_ptr;

	ZeroMemory(sector, sizeof(sector));

	if( prepare_inode_table_block(fs, inode, sector, &begin) == -1)
	{
		PRINTF("ERROR: Cannot read inode table\n");
		return EXT2_ERROR;
	}
	printf("get_inode : %d\n", inode, begin);
	inode_ptr = (INODE *)sector;	// begin block of the inode Table
	
	for(i = begin+1; i < inode; i++)
	{
		inode_ptr++;
	}
	*inodeBuffer = *inode_ptr;

	return EXT2_SUCCESS;
}

// root 섹터 메타데이터 정해뒀음
int read_root_sector(EXT2_FILESYSTEM* fs, BYTE* sector)
{
	UINT32 inode = 2;
	INODE inodeBuffer;
	SECTOR rootBlock;
	get_inode(fs, inode, &inodeBuffer);
	rootBlock = get_data_block_at_inode(fs, inodeBuffer, 1);
	//data_read(fs, 0, rootBlock, sector);
	
	return fs->disk->read_sector(fs->disk, rootBlock, sector);
}

int write_root_sector(EXT2_FILESYSTEM* fs, BYTE* sector)
{
	UINT32 inode = 2;
	INODE inodeBuffer;
	SECTOR rootBlock;
	get_inode(fs, inode, &inodeBuffer);   // 위의 inode에 해당하는 inode 구조체를 inodeBuffer에 연결
	rootBlock = get_data_block_at_inode(fs, inodeBuffer, 1);  // inodeBuffer에서 첫번째 데에터 블록 가자옴

	return fs->disk->write_sector(fs->disk, rootBlock, sector);
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

	if (insert_entry(parent, retEntry, 0) == EXT2_ERROR) return EXT2_ERROR;

	INODE inodeBuff;
	PRINTF("retEntry.inode : %u\n", retEntry->entry.inode);
	get_inode(parent->fs, retEntry->entry.inode, &inodeBuff);
	PRINTF("retEntry's inode blocks : %u\n", inodeBuff.blocks);

	printf("ext2 create COMPLETE\n");
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
		unsigned int index = (number - 12 - indirect_pointer_per_sector);	// index: 1부터 시작
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
		unsigned int index = (number - 12 - indirect_pointer_per_sector - indirect_pointer_per_sector * indirect_pointer_per_sector);
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

int get_free_inode_number(EXT2_FILESYSTEM* fs)
{
	BYTE sector[MAX_SECTOR_SIZE];
	UINT32 i;
	UINT32 begin=0;  
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
				if((8*i+j > 10) && ((bit & 0x01)==0)){ //비트가 0이고 아이노드넘버가 10 초과이면
					UINT32 inode_num = 8*i+j + group_num*max_inode_num_for_group;
					if( inode_num < fs->sb.max_inode_count) //inode_max보다 작은지 검사
					{
						return inode_num;
					}
					else
						return EXT2_ERROR; 
				}
				bit = bit >> 1;
				j++;
			}
		}//그룹 하나 돌고
		group_num++; //다 돌았으면 다음그룹
	} 
	return EXT2_ERROR; 
}

// inode 수정한거 실제 테이블에 저장
int set_inode_onto_inode_table(EXT2_FILESYSTEM *fs, const UINT32 which_inode_num_to_write, INODE *inode_to_write)
{ 
	BYTE sector[MAX_SECTOR_SIZE];
	INODE* inode_pointer;
	UINT32 group_num=0;

	group_num = (which_inode_num_to_write - 1) / fs->sb.inode_per_group; 
	data_read(fs, group_num, fs->gd.start_block_of_inode_table, sector);
	inode_pointer = (INODE*)sector;
	/*
	for(int i=1; i < which_inode_num_to_write; i++)
	{
		inode_pointer++;
	}*/
	inode_pointer[which_inode_num_to_write-1] = *inode_to_write;
	//*inode_pointer=*inode_to_write;
	data_write(fs, group_num, fs->gd.start_block_of_inode_table, sector);
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
		//data_read(dir->fs, 0, num, sector);
		dir->fs->disk->read_sector(dir->fs->disk, num, sector);

		if (dir->entry.inode == 2)
			// 32 == sizeof(EXT2_DIR_ENTRY), 즉 &sector[0]에 있는 root엔트리를 제외함.
			read_dir_from_sector(dir->fs, sector + 32, adder, list);
		else
			read_dir_from_sector(dir->fs, sector, adder, list);
	}

	PRINTF("list->first size : %u\n", ((SHELL_ENTRY_LIST*)list)->first->entry.size);

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
			
			INODE inodebuff;
			PRINTF("");
			PRINTF("node.entry.inode : %d\n", node.entry.inode);
			get_inode(fs, node.entry.inode, &inodebuff);
			PRINTF("readdir SIZE : %u\n", inodebuff.size);
			PRINTF("readdir BLOCKS : %u\n", inodebuff.blocks);
			PRINTF("readdir BLOCK[0] : %u\n", inodebuff.block[0]);

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