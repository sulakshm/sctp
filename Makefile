default: all


all: client server
	@echo "successfully built client and server"


client:
	gcc -g client.c -lpthread -o client

server:
	gcc -g server.c -o server
