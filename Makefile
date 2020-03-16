
CFLAGS:=-g -Wall
PROG:=decrypt
NAMES:=alter-hao-ramakrishna-salomon
BIN:=$(NAMES)-decrypt
ZIP:=$(NAMES)-cs6903s20project1.zip

all: $(BIN)

$(BIN): $(PROG)
	cp $(PROG) $(BIN)

.PHONY: clean
clean:
	$(RM) $(PROG) $(BIN) $(ZIP)
