flags=-O2 -Wall -g -Wextra -pedantic -std=c2x -I.
ldflags=
objects = Networks.o helper.o constructor.o
.PHONY: all clean cl run

all:cl clean Networks 

cl:
	clear

run: Networks
	./$<

Networks: $(objects)
	gcc $(flags) $^ -o $@ $(ldflags)

Networks.o: Networks.c Networks.h 
	gcc $(flags) -c $<
helper.o:helper.c 
	gcc $(flags) -c $<
constructor.o:constructor.c
	gcc $(flags) -c $<

clean:
	rm -rf *.o Networks

