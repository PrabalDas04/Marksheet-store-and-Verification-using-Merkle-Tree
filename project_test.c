#include<stdio.h>
#include<stdlib.h>
#include <memory.h>
#include "pro.h"


int main()
{  
    int i, j, depth, *binary;
    BYTE *mark_concate[STUDENT];
    BYTE *mark_hash[STUDENT];
    BYTE *buf;
    MerkleNode  *root = NULL;
    
    Marksheet *mark_arr;
   
    mark_arr = Marksheet_arr_malloc(STUDENT);
    
    mark_arr = Create_marksheet_arr(mark_arr, STUDENT);
  
    Print_marksheet(mark_arr, STUDENT);
   
    buf = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
    
    for(i =0; i<STUDENT; i++)
    {
        mark_concate[i] = str_concate(mark_arr[i] );
        printf("\nConcate marksheet of student %d: ",i+1);
        printf("\n%s\n",mark_concate[i]);
    }
    
    for(i =0; i<STUDENT; i++)
    {
        buf = sha256_hash(mark_concate[i], buf);   
        mark_hash[i]  = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
        str_cpy(mark_hash[i], buf); 
    }
    
    depth = Find_tree_depth(STUDENT);
    
    root = Merkle_tree_gen(root, mark_hash, depth);
    
    FILE * out_file_ptr;
    out_file_ptr = fopen("output.txt","w");
    
    binary = (int *)malloc(depth * sizeof(int));
	for(i = 0 ; i < STUDENT ; i++)
  	{
    	fprintf(out_file_ptr,"Result of student %d :\n",i+1);
    	binary = bin_rep(binary, i, depth);
   		find_path( root, binary, out_file_ptr);
   		fprintf(out_file_ptr,"\n\n");
   	}
   
   fclose(out_file_ptr);
   
   //verification();
   
	  return 0;
}

