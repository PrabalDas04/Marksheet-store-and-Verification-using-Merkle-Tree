#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include <memory.h>
#include "pro.h"



/*********************************************** SHA256 FUNCTION START ****************************************/


/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

/*********************************************** SHA256 FUNCTION FINISH ****************************************/

//Memory allocation for marksheet structure
Marksheet* Marksheet_arr_malloc(int n)
{
    Marksheet *mark_arr;
    
    mark_arr = (Marksheet*)malloc(n * sizeof(Marksheet));
    if(mark_arr == NULL)
    {
        printf("\nError in memory allocation for the marksheet array!!\n");
        exit(0);
    }
    return mark_arr;
}


//Scanning marksheets from input file
Marksheet* Create_marksheet_arr(Marksheet *mark_arr, int st_no)
{
  	int i;
  	BYTE a[NAME];
  
  	FILE * inp_file_ptr;
  	inp_file_ptr=fopen("input_project_name.txt","r");
 
  	for(i=0; i<st_no; i++)
  	{	
        
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].st_name, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].st_roll, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].st_reg_no, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_1, a);
    		fscanf(inp_file_ptr,"%s",a);
     	    	str_cpy(mark_arr[i].sub_1_ob_mark, a);
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_1_grade, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_2, a);
    		fscanf(inp_file_ptr,"%s",a);
     	    	str_cpy(mark_arr[i].sub_2_ob_mark, a);
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_2_grade, a);
     
    	    	fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_3, a);
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_3_ob_mark, a);
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_3_grade, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_4, a);
    		fscanf(inp_file_ptr,"%s",a);
     	    	str_cpy(mark_arr[i].sub_4_ob_mark, a);
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_4_grade, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_5, a);
    		fscanf(inp_file_ptr,"%s",a);
     	    	str_cpy(mark_arr[i].sub_5_ob_mark, a);
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].sub_5_grade, a);
     		
      		fscanf(inp_file_ptr,"%s",a);
      		str_cpy(mark_arr[i].total_obt_mark, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].total_mark, a);
     		
    		fscanf(inp_file_ptr,"%s",a);
    		str_cpy(mark_arr[i].final_grade, a);
	  }
     
	  fclose(inp_file_ptr);
   
    return mark_arr;
	
}


//Print marksheets
void Print_marksheet(Marksheet *mark_arr, int st_no)
{
    int i;
    
    for(i=0;i<st_no;i++)
    {   
        printf("\n\nMarksheet of student %d\n\n",i+1);
        
    		printf("%s\n",mark_arr[i].st_name);
    		printf("%s\n",mark_arr[i].st_roll);
    		printf("%s\n",mark_arr[i].st_reg_no);
    		printf("%s\n",mark_arr[i].sub_1);
    		printf("%s\n",mark_arr[i].sub_1_ob_mark);
    		printf("%s\n",mark_arr[i].sub_1_grade);
    		printf("%s\n",mark_arr[i].sub_2);
    		printf("%s\n",mark_arr[i].sub_2_ob_mark);
    		printf("%s\n",mark_arr[i].sub_2_grade);
    		printf("%s\n",mark_arr[i].sub_3);
    		printf("%s\n",mark_arr[i].sub_3_ob_mark);
    		printf("%s\n",mark_arr[i].sub_3_grade);
    		printf("%s\n",mark_arr[i].sub_4);
    		printf("%s\n",mark_arr[i].sub_4_ob_mark);
    		printf("%s\n",mark_arr[i].sub_4_grade);
    		printf("%s\n",mark_arr[i].sub_5);
    		printf("%s\n",mark_arr[i].sub_5_ob_mark);
    		printf("%s\n",mark_arr[i].sub_5_grade);
    		printf("%s\n",mark_arr[i].total_obt_mark);
    		printf("%s\n",mark_arr[i].total_mark);
    		printf("%s\n",mark_arr[i].final_grade);
	  }

}


//Converting marksheets from a structure to a string
BYTE *str_concate(Marksheet mark_struc)
{
    BYTE *marksheet_concate;
    marksheet_concate = (BYTE *)malloc(100 * sizeof(BYTE));
    
    str_cpy(marksheet_concate, mark_struc.st_name);
    strcat(marksheet_concate, mark_struc.st_roll);
    strcat(marksheet_concate, mark_struc.st_reg_no);
    strcat(marksheet_concate, mark_struc.sub_1);
    strcat(marksheet_concate, mark_struc.sub_1_ob_mark);
    strcat(marksheet_concate, mark_struc.sub_1_grade);
    strcat(marksheet_concate, mark_struc.sub_2);
    strcat(marksheet_concate, mark_struc.sub_2_ob_mark);
    strcat(marksheet_concate, mark_struc.sub_2_grade);
    strcat(marksheet_concate, mark_struc.sub_3);
    strcat(marksheet_concate, mark_struc.sub_3_ob_mark);
    strcat(marksheet_concate, mark_struc.sub_3_grade);
    strcat(marksheet_concate, mark_struc.sub_4);
    strcat(marksheet_concate, mark_struc.sub_4_ob_mark);
    strcat(marksheet_concate, mark_struc.sub_4_grade);
    strcat(marksheet_concate, mark_struc.sub_5);
    strcat(marksheet_concate, mark_struc.sub_5_ob_mark);
    strcat(marksheet_concate, mark_struc.sub_5_grade);
    strcat(marksheet_concate, mark_struc.total_obt_mark);
    strcat(marksheet_concate, mark_struc.total_mark);
    strcat(marksheet_concate, mark_struc.final_grade);
    return marksheet_concate;
}

// my string copy function
BYTE * str_cpy(BYTE *dest, const BYTE *src)
{
    if(dest == NULL)
   	{
     		printf("\nDestination memory is empty\n.");
     		return NULL;
   	}
   	
   	while(*src != '\0')
   	{
  			*dest = * src;
  			dest++;
  			src++;
		}
		*dest = '\0';
    return dest;
}


//Hash of marksheets using SHA256
BYTE *sha256_hash(BYTE *mark_concate, BYTE *buf)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
   	sha256_update(&ctx, mark_concate, strlen(mark_concate));
   	sha256_final(&ctx, buf);
   
    return buf;
}

// finding tree depth
int Find_tree_depth(int N)
{
    int i = 0;
    while(N > pow(2,i))
        i++;
        
    return i;
}


// function for creating Merkle Tree
MerkleNode* Merkle_tree_gen(MerkleNode *root, BYTE **mark_hash, int depth)
{
    int i, j, n;
    n = pow(2,depth);
    
    BYTE buf[SHA256_BLOCK_SIZE], *str[n];
    
    MerkleNode *leaf[n], *curr_step[n]; 
        
    
    for(i=0;i<n;i++)
        str[i] = (BYTE *)malloc((2 * SHA256_BLOCK_SIZE) * sizeof(BYTE));

    for(i=0;i<n;i++)
    {
        leaf[i] = (MerkleNode *)malloc(sizeof(MerkleNode ));
        str_cpy(leaf[i]->hash, mark_hash[i]);
        leaf[i]->lchild = NULL;
        leaf[i]->rchild = NULL;
    }
    
    for(i=0;i<n;i++)
        curr_step[i] = leaf[i];
        
    n = n / 2;
    
    BYTE **temp_hash, **curr_hash;
    
    temp_hash = (BYTE **)malloc(n * sizeof(BYTE *));
    for(i=0;i<STUDENT;i++)
        temp_hash[i] = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
        
    j = 0;
    
    
    for(i=0;i<n;i++)
    {   
        str_cpy(str[i], mark_hash[j]);
        strcat(str[i], mark_hash[j+1]);
        
        str_cpy(temp_hash[i], sha256_hash(str[i], buf));
        j = j+2;    
    }    
    
    curr_hash = (BYTE **)malloc((n/2) * sizeof(BYTE *));
    for(i=0;i<n;i++)
        curr_hash[i] = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE)); 
    
    MerkleNode **temp_step;
    
    while(n != 0)
    {
        temp_step =  Add_tree_step(temp_hash, curr_step, n);
        for(i=0;i<n;i++)
            curr_step[i] = temp_step[i];

        n = n / 2;
        
        j = 0;
        for(i=0;i<n;i++)
        {   
            str_cpy(str[i], temp_hash[j]);
            strcat(str[i], temp_hash[j+1]);
            str_cpy(curr_hash[i], sha256_hash(str[i], buf));
            j = j+2;
        }
        
        for(i=0;i<n;i++)
            str_cpy(temp_hash[i], curr_hash[i]); 
         
    }
   
    root = (MerkleNode *)malloc(sizeof(MerkleNode));
    str_cpy(root->hash, (curr_step[0]->hash));
    
    j = 0;
    root->lchild = (curr_step[j])->lchild;
    root->rchild = (curr_step[j])->rchild;

    return root;
    
}

MerkleNode  **Add_tree_step(BYTE **temp_hash, MerkleNode **curr_step, int n)
{
    int i, j = 0;
    MerkleNode **temp_step;
    temp_step = (MerkleNode **)malloc(n * sizeof(MerkleNode *));

    j = 0;
  
    for(i=0;i<n;i++)
    {
        temp_step[i] = (MerkleNode *)malloc(sizeof(MerkleNode));

        str_cpy(temp_step[i]->hash, temp_hash[i]);
        
        temp_step[i]->lchild = curr_step[j];
        temp_step[i]->rchild = curr_step[j+1];
        j = j+2;
    }
        
    return temp_step;
}

// integer to binary representation
int * bin_rep(int *b, int n, int depth)
{
    int  r, i;
    
    for(i=0; i<depth; i++)
    {
    	r = n % 2;
    	b[depth -i-1] = r;
    	n = n/2;
    }
    return b;
}


// function for finding path from root to each leaf nodes
void find_path(MerkleNode * root,int * binary, FILE * out_file_ptr)
  {
  	int i, j, depth;
  	MerkleNode * curr = root;
  	
  	depth = Find_tree_depth(STUDENT);
  	
  	fprintf(out_file_ptr,"Root = ");
   	for (j = 0; j < SHA256_BLOCK_SIZE ; j++)
    		fprintf(out_file_ptr,"%X",(root->hash)[j]);
   	
   	for(i = 0; i < depth; i++)
   	{
     		fprintf(out_file_ptr,"\nleft child = ");
     		for (j = 0; j < SHA256_BLOCK_SIZE ; j++)
  	   		  fprintf(out_file_ptr,"%X",((curr->lchild)->hash)[j]);
  	   	fprintf(out_file_ptr,"\n");
  	   	
  	   	fprintf(out_file_ptr,"right child = ");
     		for (j = 0; j < SHA256_BLOCK_SIZE ; j++)
  	   		  fprintf(out_file_ptr,"%X",((curr->rchild)->hash)[j]);
     		fprintf(out_file_ptr,"\n");
     		
     		if( binary[i] == 0)
     		{
       			fprintf(out_file_ptr,"\n0 : Go to LEFT Child\n");
       			curr = curr->lchild;	
     		}	
     		
     		if( binary[i] == 1)
     		{
       			fprintf(out_file_ptr,"\n1 : Go to RIGHT Child\n");
       			curr = curr->rchild;	
     		}
   	}
   	fprintf(out_file_ptr,"-------------------------------------------------------------------------------------");
   	
   	
}


// function for verification (under construction)
void verification()
{
  	int depth, n, i, j;
  	BYTE a[2 * SHA256_BLOCK_SIZE];
  	
  	depth = Find_tree_depth(STUDENT);
  	n = 3 * depth + 2;
  	
  	BYTE * array[n];
  	
  	FILE * test;
  	test = fopen("check.txt","r");
  	
  	for(i = 0; i < n; i++ )
  	{
  		array[i] = (BYTE *)malloc((2 * SHA256_BLOCK_SIZE) * sizeof(BYTE));
  		fscanf(test,"%s",a);
      		str_cpy(array[i], a);
  	}
  	
  	for(i = 0; i < n; i++ )
  	{
  		printf("%s",array[i]);
  		printf("\n");
  		//printf("array[i][32] = %c",array[i][32]);
  		printf("\n");
  	}
  
  	i = 0;
  	BYTE *temp_2, *temp_1, *buf;
  	temp_1 = (BYTE *)malloc((4 * SHA256_BLOCK_SIZE) * sizeof(BYTE));
  	temp_2 = (BYTE *)malloc((2 * SHA256_BLOCK_SIZE) * sizeof(BYTE));
  	buf = (BYTE *)malloc((2 * SHA256_BLOCK_SIZE) * sizeof(BYTE));
  	
  	for(j = 0; j < 64; j++ )
  	{
  		printf("%d %c  ",j ,array[0][j]);
  	}
  	
  	str_cpy( temp_1, array[i]);
  	for(i = 0; i < 64; i++ )
  	{
  		printf("%d %c  ",i,temp_1[i]);
  	}
  	//strcat( temp_1, array[i+1]);
  	//buf = sha256_hash( temp_1, buf);
  
  	for(i = 0; i < 32; i++ )
  	{
  		//printf("%X",buf[i]);
  	}

}
















