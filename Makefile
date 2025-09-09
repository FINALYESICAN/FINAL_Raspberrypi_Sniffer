# Makefile for pcap_inspect
CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Iinclude
LIBS  := -lpcap

SRC_DIR  := src
OBJ_DIR  := build
TARGET   := pcap_inspect

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

run: all
	sudo ./$(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all run clean

