# Makefile for pcap_inspect
CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall
LDFLAGS  := -lpcap

SRC      := pcap_inspect.cpp
TARGET   := pcap_inspect

all: $(TARGET)

$(TARGET): $(SRC) session_table.h packet_record.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS)

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean

