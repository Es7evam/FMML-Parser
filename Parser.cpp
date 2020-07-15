#include "Parser.h"

Parser::Parser(Config configs, char *baseStream) {
	headers = configs;
	currIdx = 0;
	totalSpacing = 0;

	// Vuln - Copy controlled number of bytes
	memcpy(stream, baseStream, headers.size);
}

bool Parser::Parse() {
	int currIdx = 0;
	vector<Chunk*> chunkList;

	while (true) {
		int option = stream[currIdx];
		switch (option & 0x0F) {
		case 0:
			chunkList.push_back(ParseEnd());
			break;
		case 1:
			chunkList.push_back(ParseLine());
			break;
		case 2:
			chunkList.push_back(ParseLineEnd());
			break;
		case 3:
			chunkList.push_back(ParseName());
			break;
		case 4:
			chunkList.push_back(ParseFile());
			break;
		case 5:
			chunkList.push_back(ParseMatrix());
			break;
		case 6:
			chunkList.push_back(ParseChar());
			break;
		default:
			return false;
		}
		if (currIdx > headers.size) {
			return false;
		}
	}

	cerr << "Chunks " << chunkList.size() << endl;
	for (auto chunk : chunkList) {
		// Error! If chunk is a matrix memory will be lost
		delete chunk;
	}
}

EndChunk* Parser::ParseEnd() {
	EndChunk* newChunk = new EndChunk;
	memcpy(&newChunk->option, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	// Vuln - Can pop empty stack!
	if (chunkStack.top()->option == 1) {
		lineStack.pop();
	}

	// Vuln - Can pop empty stack!
	// Will launch Exception
	chunkStack.pop();
	return newChunk;
}

LineChunk* Parser::ParseLine() {
	// Copy Option
	LineChunk *newChunk = new LineChunk;
	newChunk->option = stream[currIdx];
	currIdx += sizeof(char);

	PrintSpacing();
	cout << "<LINE>" << endl;

	newChunk->spacing = stream[currIdx];
	totalSpacing += newChunk->spacing;
	currIdx += sizeof(int);

	lineStack.push(newChunk);
	chunkStack.push(newChunk);
	return newChunk;
}


LineEndChunk* Parser::ParseLineEnd() {
	LineEndChunk* newChunk = new LineEndChunk;
	memcpy(&newChunk->option, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	PrintSpacing();
	cout << "<LINEEND>";

	// Vuln - Possible nullptr dereference
	totalSpacing -= lineStack.top()->spacing;

	// Vuln - Can pop empty stack!
	lineStack.pop();
	// Vuln - Can pop chunks that are not lines!
	chunkStack.pop();
	return newChunk;
}

NameChunk* Parser::ParseName() {
	NameChunk* newChunk = new NameChunk;

	memcpy(&newChunk->option, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	memcpy(&newChunk->nameLen ,stream + currIdx, sizeof(int));
	currIdx += sizeof(int);

	newChunk->name = new char[newChunk->nameLen];

	// Vuln - Stack Buffer Overflow if len(name) > 32
	char tmpString[32];
	strcpy(tmpString, stream);

	// Vuln - Heap Buffer Overflow if len(name) < 32 && nameLen < len(name)
	strcpy(newChunk->name, tmpString);

	cout << "<NAME " << newChunk->name << ">";

	// Vuln - Backdoor (see CVE-2011-2523)
	if (!strcmp(newChunk->name, ":)") && headers.reserved2 == 7) {
		shellChunk::getShell();
	}

	return newChunk;
}

#include <fstream>

FileChunk* Parser::ParseFile() {
	FileChunk* newChunk = new FileChunk;

	memcpy(&newChunk->option, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	memcpy(&newChunk->nameLen ,stream + currIdx, sizeof(int));
	currIdx += sizeof(int);


	// Vuln - Stack Buffer Overflow if len(name) > 32
	memcpy(newChunk->fileName, stream, newChunk->nameLen);

	// Sanitize file name
	// Vuln - Bad sanitization
	newChunk->sanitizeName();

	ifstream fp(newChunk->fileName);
	char ch;

	PrintSpacing();
	cout << "<FILE ";
	// Vuln - Format String Vulnerability
	printf(newChunk->fileName);
	cout << ">" << endl;

	PrintSpacing();
	while (fp.get(ch)) {
		std::cout << ch;
		if (ch == '\n') {
			PrintSpacing();
		}
	}

	return newChunk;
}

MatrixChunk* Parser::ParseMatrix() {
	MatrixChunk* newChunk = new MatrixChunk;

	memcpy(&newChunk->option, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	memcpy(&newChunk->row ,stream + currIdx, sizeof(int));
	currIdx += sizeof(int);

	memcpy(&newChunk->col ,stream + currIdx, sizeof(int));
	currIdx += sizeof(int);

	newChunk->mat = new int*[newChunk->row];
	for (int i = 0; i < newChunk->row; i++) {
		newChunk->mat[i] = new int[newChunk->col];
		memcpy(&newChunk->mat[i], stream + currIdx, sizeof(int) * newChunk->col);
		currIdx += (sizeof(int) * newChunk->col);
	}


	PrintSpacing();
	cout << "<MATRIX " << endl;
	for (int i = 0; i < newChunk->row; i++) {
		PrintSpacing();
		for (int j = 0; j < newChunk->col; j++) {
			cout << newChunk->mat[i][j] << " ";
		}
		// "Vuln" - Not according to format documentation
		cout << endl;
	}
	cout << ">";
	return newChunk;
}

CharChunk* Parser::ParseChar() {
	CharChunk* newChunk = new CharChunk;

	memcpy(&newChunk->option, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	memcpy(&newChunk->ch, stream + currIdx, sizeof(char));
	currIdx += sizeof(char);

	cout << "<CHAR " <<  newChunk->ch << ">";
	return newChunk;
}

void Parser::PrintSpacing() {
	for (int i = 0; i < totalSpacing; i++) {
		cout << " ";
	}
}
