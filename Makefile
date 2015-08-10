CXXFLAGS += -Wall -pipe -std=c++11 -fno-rtti -Wno-long-long -Wno-deprecated -g -DQCC_OS_LINUX -DQCC_OS_GROUP_POSIX

ALLJOYN_SDK_HOME=/home/dainis/build/AllJoyn/alljoyn-15.04.00-src/build/linux/x86_64/release/dist/cpp
ALLJOYN_LIB_DIR=$(ALLJOYN_SDK_HOME)/lib
ALLJOYN_INC_DIR=$(ALLJOYN_SDK_HOME)/inc
ALLJOYN_LIBS := $(ALLJOYN_LIB_DIR)/libajrouter.a $(ALLJOYN_LIB_DIR)/liballjoyn.a
LIBS = $(ALLJOYN_LIBS) -lstdc++ -lcrypto -lpthread

.PHONY: default clean

default: all
all: ajmesh 
clean: clean_ajmesh


ajmesh: ajmesh.o
	$(CXX) -o $@ ajmesh.o $(LIBS)

ajmesh.o: ajmesh.cpp
	$(CXX) -c $(CXXFLAGS) -Wno-unused-function -Wno-unused-variable -I$(ALLJOYN_INC_DIR) -o $@ ajmesh.cpp


clean_ajmesh:
	rm -f ajmesh.o ajmesh
