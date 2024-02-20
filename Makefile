
# C compiler
CC := gcc

# Source files
SRC := topup.c

# Files to generate
EXEC := topup

topup: $(SRC)
	$(CC) $(SRC) $(CXX_FLAGS) -o $(EXEC) -l nfc -l freefare

debug: CXX_FLAGS := -g
debug: topup

clean:
	rm -f $(EXEC)
