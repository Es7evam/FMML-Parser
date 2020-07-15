#include <iostream>
#include "Parser.h"

Config configs;
// Returns the bytestream of the text
char* getStream(char* args) {
	FILE* fp;
	struct stat filestatus;
	char filename[32];

	// Vuln - Copy filename bigger than 32 bytes
	strcpy(filename, args);
	if (stat(filename, &filestatus) != 0) {
		fprintf(stderr, "File %s not found\n", filename);
		return nullptr;
	}

	char *byteStream = new char[filestatus.st_size];
	fp = fopen(filename, "rb");
	fread(byteStream, sizeof(char), filestatus.st_size, fp);

	return byteStream;
}

void setConfigs(char *byteStream) {
	std::cout << "ConfigSize = " << sizeof(Config) << std::endl;
	memcpy(&configs, byteStream, sizeof(Config));
}




int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		return 1;
	}

	// Vuln - Copy Filename
	char *stream = getStream(argv[1]);
	setConfigs(stream);

	free(stream);
	return 0;
}