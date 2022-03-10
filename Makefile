ifeq ($(OS),Windows_NT)
	WINDOWS = 1
else
	WINDOWS = 0
endif

CXX = g++
override CXXFLAGS += -Wall -s -O3 -flto -pthread -std=c++14
TARGET = freedom
PREFIX = /usr/local

ifeq ($(WINDOWS),1)
	LIBS += -lws2_32
endif

$(TARGET): main.cpp Polynet/polynet.hpp
	$(CXX) $< $(CXXFLAGS) $(LIBS) -o $@

.PHONY: clean install

clean:
	$(RM) $(TARGET)

install:
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)