#pragma once
#include "Chunk.h"
#include "Config.h"
#include <string>
#include <stack>
#include <vector>

using namespace std;

class Parser {
public:
	Parser(Config configs, char* baseStream);
	// Parser, return false in case it fails
	bool Parse();
	void PrintSpacing();
	// todo - Parse headers

	EndChunk* ParseEnd();
	LineChunk* ParseLine();
	LineEndChunk* ParseLineEnd();
	NameChunk* ParseName();
	FileChunk* ParseFile();
	MatrixChunk* ParseMatrix();
	CharChunk* ParseChar();



private:
	char *stream;
	int currIdx;
	int totalSpacing;

	Config headers;
	stack<Chunk*> chunkStack;
	stack<LineChunk*> lineStack;
};




