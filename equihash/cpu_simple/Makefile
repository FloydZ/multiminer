GCC   = gcc $(FLAGS)
FLAGS = -lpthread -ffast-math -pthread -D_POSIX_SOURCE -Ofast -march=native --pedantic -Wall -std=c11

all: time-equihash

#thpool/thpool.c
time-equihash:
	$(GCC) blake/blake2b.c time-equihash.c equihash.c -o time-equihash

clean:
	rm time-equihash
