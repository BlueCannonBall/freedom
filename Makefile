CXX = g++
CXXFLAGS = -g -pthread
TARGET = freedom
PREFIX = /usr/local

$(TARGET): main.cpp Polynet/polynet.hpp
	$(CXX) $< $(CXXFLAGS) -o $@

.PHONY: clean install

clean:
	$(RM) $(TARGET)

install:
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)