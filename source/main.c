#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define PORT "1337"

#pragma comment(libm "ws2_32")

typedef struct _HEADER
{
	DWORD secret1;
	DWORD secret2;
	DWORD length;
	DWORD opcode;
	DWORD checksum;
} HEADER;

#define SECRET1 0x696e7669 // invi
#define SECRET2 0x63747573 // ctus
#define XOR_KEY 0x30383132 // 0812
#define MAXBUF 256
#define MAXLENGTH 512
#define INVICTUS_LOG "C:\\windows\\temp\\invictus_log.txt"

size_t getTotalSize(va_list args)
{
	size_t totalSize = 0;

	while (1)
	{
		int currentArg = va_arg(args, int);

		if (currentArg == -1)
		{
			break;
		}

		totalSize += sizeof(int);
	}

	return totalSize;
}

char *getCurrentTimestamp()
{
	// Get current time
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	// Format the timestamp
	static char timestamp[20];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

	return timestamp;
}

char *readUntilNull(const char *input)
{
	size_t length = 0;
	while (input[length] != '\0')
	{
		length++;
	}
	char *result = (char *)malloc(length + 1);

	for (size_t i = 0; i < length; i++)
	{
		result[i] = input[i];
	}
	result[length] = '\0';
	return result;
}

PCHAR GetFileDir(PCHAR path)
{
	PCHAR last = NULL;
	for (DWORD i = 0; i < strlen(path); i++)
		if (path[i] == '\\')
			last = &path[i];

	if (last == NULL)
		return last;

	DWORD dwStrLen = last - path;
	last = (PCHAR)calloc(1, dwStrLen + 1);
	memcpy(last, path, dwStrLen);

	return last;
}

BOOL Check_Secret1(DWORD input)
{
	DWORD result = input ^ XOR_KEY;
	return result == SECRET1;
}

BOOL Check_Secret2(DWORD input)
{
	DWORD output = 0;

	time_t currentTime;
	time(&currentTime);
	unsigned int epoch = (unsigned int)currentTime;
	epoch = epoch << 4;
	epoch = epoch | 0xFFFF0000;
	epoch = epoch >> 8;

	output = input ^ XOR_KEY;
	output = output ^ epoch;

	return output == SECRET2;
}

BOOL Check_Checksum(DWORD input, DWORD length)
{
	unsigned int result = length ^ XOR_KEY;
	result = result * MAXLENGTH;
	result = result / 1000;

	return input == result;
}

VOID LogAndWriteMessage(const char *format, va_list args)
{
	size_t format_length = strlen(format);
	size_t args_length = getTotalSize(args);
	char logBuffer[format_length + args_length];

	const char* log_timestamp = getCurrentTimestamp();
	const char* separator = "=====\n";
	const char* filler = " - ";

	vsnprintf(logBuffer, sizeof(logBuffer), format, args);

	size_t totalMsgSize = strlen(log_timestamp) + strlen(filler) + strlen(logBuffer) + 1;

	char logMsg[totalMsgSize];
	strcpy(logMsg, separator);
	strcat(logMsg, log_timestamp);
	strcat(logMsg, filler);
	strcat(logMsg, logBuffer);
	strcat(logMsg, separator);

	FILE *file = fopen(INVICTUS_LOG, "a");

	if (file == NULL)
	{
		perror("Error opening the log file");
	}

	fprintf(file, logMsg);
	fclose(file);
}

VOID LogMessage(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	LogAndWriteMessage(format, args);
	va_end(args);
}

void splitPCHAR(PCHAR input, PCHAR *part1, PCHAR *part2)
{
	PCHAR nullCharPosition = strchr(input, '\0');

	if (nullCharPosition != NULL)
	{
		size_t lengthPart1 = nullCharPosition - input;
		*part1 = (PCHAR)malloc(lengthPart1 + 1);
		strncpy(*part1, input, lengthPart1);
		(*part1)[lengthPart1] = '\0';
		*part2 = nullCharPosition + 1;
	}
	else
	{
		*part1 = strdup(input);
		*part2 = NULL;
	}
}

DWORD ReturnFile(SOCKET sock, PCHAR data, DWORD length)
{
	FILE *file = CreateFileA(data, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE)
	{
		char err[] = "Error: Cannot open file";
		send(sock, err, strlen(err), 0);
		return 1;
	}

	DWORD discard = 0;
	char buf[MAXBUF];
	memset(buf, 0, sizeof(buf));

	LogMessage("Reading file: %s\n", data);

	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	unsigned int filesize = GetFileSize(file, NULL);
	ReadFile(file, buf, filesize, &discard, NULL); // VULN Reading into buf with filesize controlled by attacker

	char* msg=(char*)malloc(9+filesize);
	sprintf(msg,"0x800 OK %s", buf);
	printf("msg is: %s\n",msg);
	send(sock, msg, strlen(msg), 0);
	return 0;
}

DWORD WriteData(SOCKET sock, PCHAR data, DWORD length)
{
	PCHAR filename, content;

	splitPCHAR(data, &filename, &content);
	size_t content_length = strlen(content);
	if (content_length < 1)
	{
		char err[] = "Error: No data supplied, only filename";
		send(sock, err, strlen(err), 0);
		return 1;
	}

	content[MAXBUF] = '\0';

	FILE *file = fopen(filename, "w");

	if (file == NULL)
	{
		char err[MAXBUF + 23] = {0};
		sprintf(err, "Error: Cannot open file %s\n", filename);
		send(sock, err, strlen(err), 0);
	}

	fprintf(file, content);
	fclose(file);

	LogMessage("Written file %s with content %s\n", filename, content); // Vuln content is attacker controlled, can be used to write %x to logfile

	char msg[8] = "0x801 OK";
	send(sock, msg, sizeof(msg), 0);

	return 0;
}

// This function bypasses the length restriction in WriteData and can copy a file with content longer than 256 byte to be read by ReturnFile and crash, then control EIP..
DWORD CopyFileI(SOCKET sock, PCHAR data, DWORD length)
{
	PCHAR src, dst;

	splitPCHAR(data, &src, &dst);
	size_t dst_length = strlen(dst);
	if (dst_length < 1)
	{
		char err[] = "Error: No destination file defined";
		send(sock, err, strlen(err), 0);
		return 1;
	}

	int result = CopyFileA(src, dst, FALSE);
	if (result == 0)
	{
		char err[] = "Error: File was not copied";
		send(sock, err, strlen(err), 0);
		return 1;
	}

	LogMessage("Copied file %s to %s\n", src, dst);

	char msg[8] = "0x802 OK";
	send(sock, msg, sizeof(msg), 0);

	return 0;
}

DWORD RemoveFile(SOCKET sock, PCHAR data, DWORD length)
{
	int result = DeleteFileA(data);
	if (result == 0)
	{
		char err[] = "Error: Cannot delete file";
		send(sock, err, strlen(err), 0);
		return 1;
	}

	if (data != INVICTUS_LOG)
	{
		LogMessage("File %s was deleted\n", data);
		char msg[8] = "0x803 OK";
		send(sock, msg, sizeof(msg), 0);
	}


	return 0;
}

DWORD ReadLog(SOCKET sock, PCHAR data, DWORD length)
{
	FILE *file = CreateFileA(INVICTUS_LOG, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE)
	{
		char err[] = "Error: Cannot open log file";
		send(sock, err, strlen(err), 0);
		return 1;
	}

	DWORD discard = 0;

	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	unsigned int filesize = GetFileSize(file, NULL);

	char buf[filesize];
	memset(buf, 0, sizeof(buf));

	int result = ReadFile(file, buf, sizeof(buf), &discard, NULL);
	if (result == 0) {
		char err[] = "Error: Cannot read log file";
		send(sock, err, strlen(err), 0);
		return 1;
	}
	CloseHandle(file);

	LogMessage("Reading log file with content >>>%s<<<",buf); // reading twice when poisened with %x's will leak addresses

	char msg[9 + filesize];
	sprintf(msg,"0x804 OK %s", buf);
	send(sock, msg, sizeof(msg), 0);
	return 0;
}

DWORD DeleteLog(SOCKET sock, PCHAR data, DWORD length)
{
	int result = RemoveFile(sock, INVICTUS_LOG, length);
	if (result != 0)
	{
		char err[] = "Error: Cannot clear log";
		send(sock, err, strlen(err), 0);
		return 1;
	}
	char msg[8] = "0x805 OK";
	send(sock, msg, sizeof(msg), 0);
	return 0;
}

DWORD WINAPI Dispatch(SOCKET sock, DWORD opcode, PCHAR data, DWORD length)
{
	switch (opcode)
	{
	case 0x800:
		ReturnFile(sock, data, length);
		break;
	case 0x801:
		WriteData(sock, data, length);
		break;
	case 0x802:
		CopyFileI(sock, data, length);
		break;
	case 0x803:
		RemoveFile(sock, data, length);
		break;
	case 0x804:
		ReadLog(sock, data, length);
		break;
	case 0x805:
		DeleteLog(sock, data, length);
		break;
	}
	return 0;
}

DWORD WINAPI ConnectionHandler(LPVOID sock)
{
	char buf[1024];
	HEADER header = {0};
	DWORD dwBytesReceived = 0;
	LPVOID data = 0;

	memset(buf, 0, sizeof(buf));
	dwBytesReceived = recv((SOCKET)sock, buf, sizeof(header), 0);

	if (dwBytesReceived != sizeof(header))
	{
		char err[] = "Error: invalid header length";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	memcpy(&header, buf, sizeof(header));

	if (!Check_Secret1(header.secret1))
	{
		char err[] = "Error: invalid first packet signature";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	if (!Check_Secret2(header.secret2))
	{
		char err[] = "Error: invalid second packet signature";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	if (header.length > MAXLENGTH)
	{
		char err[] = "Error: packet length too big";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	if (header.opcode < 0x800 || header.opcode > 0x805)
	{
		char err[] = "Error: invalid opcode";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	if (!Check_Checksum(header.checksum, header.length))
	{
		char err[] = "Error: invalid checksum";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	data = VirtualAlloc(0, header.length, 0x1000, 0x4);
	if (data == NULL)
	{
		char err[] = "Error: could not allocate memory";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	dwBytesReceived = recv((SOCKET)sock, (PCHAR)data, header.length, 0);
	if (dwBytesReceived != header.length)
	{
		char err[] = "Error: could not read data";
		send((SOCKET)sock, err, strlen(err), 0);
		return 1;
	}

	Dispatch((SOCKET)sock, header.opcode, (PCHAR)data, header.length);

	VirtualFree(data, 0, MEM_RELEASE);
	return 0;
}

// socket loop stuff from: https://github.com/stephenbradshaw/vulnserver
int main(int argc, char *argv[])
{
	WSADATA wsaData;
	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL, hints;
	int Result;
	struct sockaddr_in ClientAddress;
	int ClientAddressL = sizeof(ClientAddress);

	Result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (Result != 0)
	{
		printf("WSAStartup failed with error: %d\n", Result);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	Result = getaddrinfo(NULL, PORT, &hints, &result);
	if (Result != 0)
	{
		printf("Getaddrinfo failed with error: %d\n", Result);
		WSACleanup();
		return 1;
	}

	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET)
	{
		printf("Socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	Result = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (Result == SOCKET_ERROR)
	{
		printf("Bind failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	Result = listen(ListenSocket, SOMAXCONN);
	if (Result == SOCKET_ERROR)
	{
		printf("Listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	while (ListenSocket)
	{
		printf("Waiting for client connections...\n");

		ClientSocket = accept(ListenSocket, (SOCKADDR *)&ClientAddress, &ClientAddressL);
		if (ClientSocket == INVALID_SOCKET)
		{
			printf("Accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		printf("Received a client connection from %s:%u\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port));
		HANDLE hThread = CreateThread(0, 0, ConnectionHandler, (LPVOID)ClientSocket, 0, 0);
		WaitForSingleObject(hThread, -1);
		closesocket(ClientSocket);
	}

	closesocket(ListenSocket);
	WSACleanup();

	return 0;
}