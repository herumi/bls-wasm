BLS_DIR?=./bls
MCL_DIR?=$(BLS_DIR)/mcl
OBJ_DIR?=$(BLS_DIR)/obj
LIB_DIR?=./
WASM_DIR=$(MCL_DIR)/src/wasm
#LLVM_VER?=-18

CC=clang$(LLVM_VER)
CXX=clang++$(LLVM_VER)
LD=wasm-ld$(LLVM_VER)
WASM_OPT?=wasm-opt

TARGET=--target=wasm32-unknown-unknown
CFLAGS=$(TARGET) -O3 -DNDEBUG -flto -fvisibility=hidden
CFLAGS+=-fno-threadsafe-statics -fno-rtti -fno-stack-protector -fno-exceptions
CFLAGS+=-DMCL_SIZEOF_UNIT=4 -DMCL_STANDALONE
CFLAGS+=-DCYBOZU_MINIMUM_EXCEPTION
CFLAGS+=-I $(WASM_DIR) -I $(MCL_DIR)/include -I $(MCL_DIR)/src
CFLAGS+=-Wall -Wextra -MMD -MP
CFLAGS+=-I $(BLS_DIR)/include -I $(BLS_DIR)/src
CXXFLAGS=$(CFLAGS) -std=c++03

STACK_SIZE?=1048576
LDFLAGS=--no-entry --export-dynamic -z stack-size=$(STACK_SIZE)
LDFLAGS+=--export=__stack_pointer --export=__wasm_call_ctors
LDFLAGS+=--export=malloc --export=free
LDFLAGS+=--export=stackSave --export=stackAlloc --export=stackRestore
LDFLAGS+=--import-memory --allow-undefined
LDFLAGS+=--lto-O3

DLMALLOC_FLAGS=-DLACKS_SYS_TYPES_H -DLACKS_FCNTL_H -DLACKS_UNISTD_H
DLMALLOC_FLAGS+=-DLACKS_SYS_MMAN_H -DLACKS_STRINGS_H -DLACKS_SYS_PARAM_H
DLMALLOC_FLAGS+=-DLACKS_SCHED_H -DLACKS_TIME_H
DLMALLOC_FLAGS+=-DHAVE_MORECORE=1 -DHAVE_MMAP=0 -DNO_MALLOC_STATS=1
DLMALLOC_FLAGS+=-DMORECORE_CONTIGUOUS=0
DLMALLOC_FLAGS+=-Dsize_t=unsigned\ long -Dptrdiff_t=long
DLMALLOC_FLAGS+=-DMALLOC_ALIGNMENT=16

OBJS=$(OBJ_DIR)/fp.o
OBJS+=$(OBJ_DIR)/dlmalloc.o $(OBJ_DIR)/libc.o $(OBJ_DIR)/stack.o
OBJS+=$(OBJ_DIR)/bls_c384_256.o

WASM=$(LIB_DIR)/bls.wasm
BLS_JS=$(LIB_DIR)/bls_c.js

all: $(BLS_JS)

$(BLS_JS): $(WASM) $(WASM_DIR)/glue.js
	python3 -c "import base64;w=base64.b64encode(open('$(WASM)','rb').read()).decode();print(open('$(WASM_DIR)/glue.js').read().replace('@@WASM_BASE64@@',w).replace('@@STACK_SIZE@@','$(STACK_SIZE)'),end='')" > $@

$(WASM): $(OBJS) | $(LIB_DIR)
	$(LD) -o $@.pre $(OBJS) $(LDFLAGS)
	$(WASM_OPT) -O3 --strip-debug $@.pre -o $@
	rm $@.pre

$(OBJ_DIR)/fp.o: $(MCL_DIR)/src/fp.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(INC_DIR) -c -o $@ $<

$(OBJ_DIR)/bls_c384_256.o: $(BLS_DIR)/src/bls_c384_256.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(INC_DIR) -c -o $@ $<

$(OBJ_DIR)/dlmalloc.o: $(WASM_DIR)/dlmalloc.c | $(OBJ_DIR)
	$(CC) $(TARGET) -O3 -DNDEBUG -flto -I $(WASM_DIR) $(DLMALLOC_FLAGS) -c -o $@ $< -DUSE_LOCKS=0

$(OBJ_DIR)/libc.o: $(WASM_DIR)/libc.c | $(OBJ_DIR)
	$(CC) $(TARGET) -O3 -DNDEBUG -flto -I $(WASM_DIR) -c -o $@ $<

$(OBJ_DIR)/stack.o: $(WASM_DIR)/stack.s | $(OBJ_DIR)
	$(CC) $(TARGET) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $@

$(LIB_DIR):
	mkdir -p $@

DEPS=$(OBJS:.o=.d)
-include $(DEPS)

clean:
	rm -f bls_c.js $(OBJS) $(DEPS) $(WASM) $(WASM).pre

.PHONY: clean all
