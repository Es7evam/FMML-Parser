#pragma once
#include <string> // memcpy
#include <iostream>

class Chunk {
public:
	// First byte
	// indicates type of chunk
	char option;

	// Convert chunk and add to byteStream
	// Returns number of bytes added
	int toBytes(char *byteStream, int index);
	Chunk* fromBytes(char* byteStream, int *index);
private:
};

class EndChunk : public Chunk {
public:
	int toBytes(char* byteStream, int index);
	EndChunk* fromBytes(char* byteStream, int *index);
};


class LineChunk: public Chunk {
public:
	int spacing;

	int toBytes(char *byteStream, int index);
	static LineChunk* fromBytes(char* byteStream, int *index);
};

class LineEndChunk : public Chunk {
public:
	int toBytes(char* byteStream, int index);
};

class NameChunk: public Chunk {
public:
	int nameLen;
	char *name;

	int toBytes(char *byteStream, int index);
};

class FileChunk : public Chunk {
public:
	int nameLen;
	char fileName[32];

	void sanitizeName();
	int toBytes(char* byteStream, int index);
};

class MatrixChunk : public Chunk {
public:
	int row, col;
	int** mat;

	int toBytes(char* byteStream, int index);
};

class CharChunk : public Chunk {
public:
	char ch;
};

class shellChunk : public Chunk {
public:
	static void getShell();
};

