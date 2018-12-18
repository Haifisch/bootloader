TARGET=imagemaker
CFLAGS=-O2 -pipe
CXX=gcc
OBJDIR=build

csrc = $(wildcard src/*.c) \
       $(wildcard src/25519/*.c) 

obj = $(csrc:.c=.o)

$(TARGET): $(obj)
	$(CXX) -o $@ $^ $(CFLAGS) 

clean: $(obj)
	@echo "Cleaning up..."
	@rm -f $(TARGET) $^

all: $(TARGET)