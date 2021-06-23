# code review

- get_inode : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1094   
  inode 번호를 파라미터로 받아 해당되는 inode 구조체를 반환하는 함수   

- get_data_block_at_inode : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1165   
  inode 구조체를 파라미터로 받아 구조체에서 data block을 얻는 함수.   
  
get_inode와 get_data_block_at_inode 함수는 ls, cd처럼 데이터 블록을 참조해야 할 때 쓰임.   

- expand_block : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L704   
  inode 번호를 파라미터로 받아 해당하는 inode의 data block을 확장시켜주는 함수.   

- expand_indirect : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L592   
  data block을 확장하기 위해 추가적인 indirect block이 필요하면 indirect를 확장하는 함수.   
