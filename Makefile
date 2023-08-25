ifeq ($(OS),Windows_NT)
	WINDOWS = 1
else
	WINDOWS = 0
endif

CXX = g++
CXXFLAGS = -Wall -std=c++14 -O2 -flto -pthread
LDLIBS = -lcrypto
HEADERS = $(shell find . -name "*.hpp")
OBJDIR = obj
OBJS = $(OBJDIR)/main.o $(OBJDIR)/adblock.o $(OBJDIR)/polynet.o $(OBJDIR)/polyweb.o $(OBJDIR)/polyweb_string.o
TARGET = freedom
PREFIX = /usr/local

ifeq ($(WINDOWS),1)
	CXXFLAGS += -static -static-libgcc -static-libstdc++
	LDLIBS += -lws2_32
endif

$(TARGET): $(OBJS)
	$(CXX) $^ $(CXXFLAGS) $(LDLIBS) -o $@

$(OBJDIR)/main.o: main.cpp $(HEADERS)
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/adblock.o: adblock.cpp adblock.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polynet.o: Polyweb/Polynet/polynet.cpp Polyweb/Polynet/polynet.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polyweb.o: Polyweb/polyweb.cpp Polyweb/Polynet/polynet.hpp Polyweb/polyweb.hpp Polyweb/threadpool.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polyweb_string.o: Polyweb/string.cpp Polyweb/string.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

.PHONY: clean install

clean:
	rm -rf $(TARGET) $(OBJDIR)

install:
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)
