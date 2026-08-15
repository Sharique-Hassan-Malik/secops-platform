CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -O2 -g
TARGETS = zip_detector multi_detector

all: $(TARGETS)

zip_detector: zip_detector.c zip_detector.h
	$(CC) $(CFLAGS) -o $@ zip_detector.c -lm

multi_detector: multi_detector.c formats.c formats.h
	$(CC) $(CFLAGS) -o $@ multi_detector.c formats.c -lm

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
