//Project: Online Marksheet store and Verification Using Merkle Tree structure
//Collaborators: Bishakha Sarkar, Prabal Das, Sayantan Ganguly
//Ackownledgement: Dr. Laltu Sardar, Dr. Ritankar Mandal
// Place : IAI, CREST, Kolkata
/*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include<stdio.h>
/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

#define NAME 30
#define ROLL 9
#define REG 10
#define SUB 5
#define GRADE 3
#define MARK 4
#define STUDENT 8
#define STRCONCATE 100

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct
{
  	BYTE data[64];
  	WORD datalen;
  	unsigned long long bitlen;
  	WORD state[8];
} SHA256_CTX;


typedef struct marksheet
{
    BYTE st_name[NAME];
  	BYTE st_roll[ROLL];
  	BYTE st_reg_no[REG];
   
  	BYTE sub_1[SUB];
  	BYTE sub_1_ob_mark[MARK];
  	BYTE sub_1_grade[GRADE];
    
   	BYTE sub_2[SUB];
  	BYTE sub_2_ob_mark[MARK];
  	BYTE sub_2_grade[GRADE];
    
   	BYTE sub_3[SUB];
  	BYTE sub_3_ob_mark[MARK];
  	BYTE sub_3_grade[GRADE];
    
   	BYTE sub_4[SUB];
  	BYTE sub_4_ob_mark[MARK];
  	BYTE sub_4_grade[GRADE];
    
   	BYTE sub_5[SUB];
  	BYTE sub_5_ob_mark[MARK];
  	BYTE sub_5_grade[GRADE];   
  	
  	BYTE total_obt_mark[MARK];
  	BYTE total_mark[MARK];
  	BYTE final_grade[GRADE];
}Marksheet;

typedef struct node
{
    BYTE hash[SHA256_BLOCK_SIZE];
    struct node *lchild;
    struct node *rchild;
}MerkleNode;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

#endif   // SHA256_H
  
/***************************** My functions *************************/
Marksheet* Marksheet_arr_malloc(int );
Marksheet* Create_marksheet_arr(Marksheet * , int );
void Print_marksheet(Marksheet * , int );
BYTE * str_cpy(BYTE *, const BYTE *);

BYTE *str_concate(Marksheet );
BYTE *sha256_hash(BYTE *, BYTE * );

int Find_tree_depth(int );
MerkleNode *Merkle_tree_gen(MerkleNode *, BYTE **, int );
MerkleNode  **Add_tree_step(BYTE **, MerkleNode **, int );

int * bin_rep(int *, int , int );
void find_path(MerkleNode * ,int * , FILE * );
void verification();





