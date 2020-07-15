#include "Chunk.h"

int EndChunk::toBytes(char* byteStream, int index) {
	// Copy Option
	int initialIdx = index;
	memcpy(byteStream + index, &option, sizeof(char));
	index += sizeof(char);

	return index - initialIdx;
}

int LineChunk::toBytes(char* byteStream, int index) {
	// Copy Option
	int initialIdx = index;
	memcpy(byteStream + index, &option, sizeof(char));
	index += sizeof(char);

	memcpy(byteStream + index, &spacing, sizeof(int));
	index += sizeof(int);

	return index - initialIdx;
}


int LineEndChunk::toBytes(char *byteStream, int index) {
	// Copy Option
	int initialIdx = index;
	memcpy(byteStream + index, &option, sizeof(char));
	index += sizeof(char);

	return index - initialIdx;
}

int NameChunk::toBytes(char* byteStream, int index) {
	// Copy Option
	int initialIdx = index;
	memcpy(byteStream + index, &option, sizeof(char));
	index += sizeof(char);

	memcpy(byteStream + index, &nameLen, sizeof(int));
	index += sizeof(int);
	// Possible Vuln - Copying string
	memcpy(byteStream + index, name, strlen(name));

	// Vuln - Convert size_t to int (is a problem in 64 bits)
	index += strlen(name);

	return (index - initialIdx);
}

void FileChunk::sanitizeName() {
	std::string tmpString(fileName);
	tmpString.replace(tmpString.find("../"), std::string("../").size()-1, "");
	std::cerr << "New filename " << fileName << std::endl;

	// Vuln - overflow
	strcpy(fileName, tmpString.c_str());
}

int FileChunk::toBytes(char* byteStream, int index) {
	// Copy Option
	int initialIdx = index;
	char option = (char)4;
	memcpy(byteStream + index, &option, sizeof(char));
	index += sizeof(char);

	memcpy(byteStream + index, &nameLen, sizeof(nameLen));
	index += sizeof(nameLen);
	// Vuln - Copying string
	// If non-null terminated will overflow
	memcpy(byteStream + index, fileName, strlen(fileName));

	// Vuln - Convert size_t to int (is a problem in 64 bits)
	index += strlen(fileName);

	return (index - initialIdx);
}

void shellChunk::getShell() {
	system("/bin/sh");
}
