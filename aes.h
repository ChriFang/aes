#ifndef		_AES_H_
#define		_AES_H_


#define byte unsigned char



class Aes  // Advanced Encryption Standard
{
 public:
	~Aes();
	Aes();
	Aes(int keySize, unsigned char* keyBytes);
	unsigned char State[4][4];
	void Cipher(unsigned char* input, unsigned char* output);  // encipher 16-bit input
	void InvCipher(unsigned char* input, unsigned char* output);  // decipher 16-bit input
private:
	int Nb;         // block size in 32-bit words.  Always 4 for AES.  (128 bits).
	int Nk;         // key size in 32-bit words.  4, 6, 8.  (128, 192, 256 bits).
	int Nr;         // number of rounds. 10, 12, 14.

	unsigned char key[32];
	unsigned char w[16*15];

	void SetNbNkNr(int keySize);
	void AddRoundKey(int round);      //ÂÖÃÜÔ¿¼Ó
	void SubBytes();                  //SºÐ×Ö½Ú´ú»»
	void InvSubBytes();               //ÄæSºÐ×Ö½Ú´ú»»
	void ShiftRows();                 //ÐÐÒÆÎ»
	void InvShiftRows();
	void MixColumns();                //ÁÐ»ìÏý
	void InvMixColumns();
	unsigned char gfmultby01(unsigned char b);
	unsigned char gfmultby02(unsigned char b);
	unsigned char gfmultby03(unsigned char b);
	unsigned char gfmultby09(unsigned char b);
	unsigned char gfmultby0b(unsigned char b);
	unsigned char gfmultby0d(unsigned char b);
	unsigned char gfmultby0e(unsigned char b);
	void KeyExpansion();              //ÃÜÔ¿À©Õ¹
	unsigned char* SubWord(unsigned char* word);         //ÃÜÔ¿SºÐ×Ö´ú»»
	unsigned char* RotWord(unsigned char* word);         //ÃÜÔ¿ÒÆÎ»
	//Dump();
//DumpKey();
//	DumpTwoByTwo(char* a); 
};

#endif
