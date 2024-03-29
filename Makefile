# Makefile for ipk-sniffer
# author: Tomáš Frátrik (xfratr01)

CC=g++
CFLAGS= -std=c++2a -g

all: sniffer

sniffer: ipk-sniffer.cpp
	$(CC) $(CFLAGS) -o ipk-sniffer ipk-sniffer.cpp -lpcap

clean: 
	rm -f ipk-sniffer

zip: 
	git archive HEAD --format=zip > xfratr01.zip