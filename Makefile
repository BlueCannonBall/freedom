ifeq ($(OS),Windows_NT)
	WINDOWS = 1
else
	WINDOWS = 0
endif

CXX = g++
override CXXFLAGS += -Wall -O3 -flto -pthread -std=c++14
HEADERS = $(shell find . -name "*.hpp")
OBJDIR = obj
OBJS = $(OBJDIR)/main.o $(OBJDIR)/polynet.o $(OBJDIR)/polyweb.o
TARGET = freedom
PREFIX = /usr/local

ifeq ($(WINDOWS),1)
	LIBS += -lws2_32
endif

$(TARGET): $(OBJS)
	$(CXX) $^ $(CXXFLAGS) $(LIBS) -o $@

$(OBJDIR)/main.o: main.cpp $(HEADERS)
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polynet.o: Polyweb/Polynet/polynet.cpp Polyweb/Polynet/polynet.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polyweb.o: Polyweb/polyweb.cpp Polyweb/Polynet/polynet.hpp Polyweb/polyweb.hpp Polyweb/threadpool.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

.PHONY: clean install

clean:
	$(RM) $(TARGET)

install:
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)
