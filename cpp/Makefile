CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
TARGET = des_cli

all: $(TARGET)

$(TARGET): cli.o des.o
	$(CXX) $(CXXFLAGS) -o $(TARGET) cli.o des.o

cli.o: cli.cpp des_impl.h
	$(CXX) $(CXXFLAGS) -c cli.cpp -o cli.o

des.o: des.cpp des_impl.h
	$(CXX) $(CXXFLAGS) -c des.cpp -o des.o

clean:
	rm -f *.o $(TARGET)
