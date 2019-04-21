CC = g++
AR = ar

CFLAGS = -c -Wall
LIB = 
OBJECTS = aes.o main.o
OUTPUT = aes

$(OUTPUT) : $(OBJECTS)
			$(CC) -o $(OUTPUT) $(OBJECTS) $(LIB)
			
main.o : main.cpp
			$(CC) $(CFLAGS) main.cpp
aes.o : aes.cpp aes.h
			$(CC) $(CFLAGS) aes.cpp

clean :
			rm $(OBJECTS) $(OUTPUT)