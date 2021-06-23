# EXT2 File system 기본 개념
## 디스크 구조
![disk_struct](https://user-images.githubusercontent.com/49184890/123117911-20ba1a80-d47d-11eb-9f98-ce2522f4cf37.PNG)   
![disk_struct2](https://user-images.githubusercontent.com/49184890/123117949-2b74af80-d47d-11eb-8faf-2a322e3bca3e.PNG)   

## Multi-level access
![ext2_multi-level-access](https://user-images.githubusercontent.com/49184890/123118211-64148900-d47d-11eb-8880-f7daa1502796.png)   


# code review

## Super block & Group descriptor 관련 구조체
![struct1](https://user-images.githubusercontent.com/49184890/123119276-56abce80-d47e-11eb-8b36-5f2396a3f9ed.PNG)   
## Shell Entry 관련 구조체
![struct2](https://user-images.githubusercontent.com/49184890/123119292-590e2880-d47e-11eb-9ce5-a65e865d116c.PNG)   
## Ext2 Node 관련 구조체
![struct3](https://user-images.githubusercontent.com/49184890/123119296-5ad7ec00-d47e-11eb-9d6c-fa9458c4c560.PNG)   


## 함수

get_inode와 get_data_block_at_inode 함수는 ls, cd처럼 데이터 블록을 참조해야 할 때 쓰임.   

- get_inode : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1094   
  inode 번호를 파라미터로 받아 해당되는 inode 구조체를 반환하는 함수   
![get_inode](https://user-images.githubusercontent.com/49184890/123131631-d50d6e00-d488-11eb-8759-d126ab57dc1c.PNG)   

- get_data_block_at_inode : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1165   
  inode 구조체를 파라미터로 받아 구조체에서 data block을 얻는 함수.   
  ![double_indirect_access](https://user-images.githubusercontent.com/49184890/123131288-84961080-d488-11eb-9286-48c44dbe95e8.PNG)   
--------------------------------------------
- expand_block : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L704   
  inode 번호를 파라미터로 받아 해당하는 inode의 data block을 확장시켜주는 함수.   

- expand_indirect : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L592   
  data block을 확장하기 위해 추가적인 indirect block이 필요하면 indirect를 확장하는 함수.   
--------------------------------------------
- ls -> ext2_read_dir : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1335   
- read_dir_from_sector : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1366   
![read_dir](https://user-images.githubusercontent.com/49184890/123131086-53b5db80-d488-11eb-9d71-cc008bd5ebfd.PNG)   

--------------------------------------------

- cd -> ext2_lookup : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1322   
- lookup_entry -> find_entry_on_data : https://github.com/gjlee0802/EXT2_File_System/blob/master/Code/ext2.c#L1026   
![lookup](https://user-images.githubusercontent.com/49184890/123154260-93d58800-d4a1-11eb-8420-1bff1bc653f5.PNG)   

