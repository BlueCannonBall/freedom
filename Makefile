CXX = g++
override CXXFLAGS += -Wall -s -O3 -flto -pthread -std=c++14
TARGET = freedom
PREFIX = /usr/local

$(TARGET): main.cpp Polynet/polynet.hpp
	$(CXX) $< $(CXXFLAGS) -o $@

.PHONY: clean install

clean:
	$(RM) $(TARGET)

install:
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)