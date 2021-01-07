COMPLR = $(shell which clang >/dev/null; echo $$?)
ifeq "$(COMPLR)" "0"
	CC = clang
else
	CC = gcc
endif
ifeq ($(CC), clang)
	CFLAGS=-O3 -pedantic -Wall -Wextra -Weverything
else
	CFLAGS=-O3 -pedantic -Wall -Wextra -std=c99
endif

CBMCH = $(shell cbmc --help)
CBMCFLAGS = --unwind 8 --partial-loops --bounds-check --pointer-check \
            --div-by-zero-check --signed-overflow-check

TARGET = sha256

$(TARGET).o: sha256.c sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: sha256.c sha256.h
	$(CC) $(CFLAGS) -o $(TARGET) -DSELF_TEST $<

all: $(TARGET)

clean:
	rm -f $(TARGET) *.o
