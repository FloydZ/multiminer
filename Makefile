CC=/usr/lib/emscripten/emcc
ASM=/usr/lib/emscripten/emcc

USE_ASM=1
USE_DEBUG=1
USE_PTHREAD=0

ifeq ($(USE_DEBUG),1)
DEBUG_FLAGS=-g4 -s ASSERTIONS=2 -DDEBUG_ALGO -DDEBUG
else
DEBUG_FLAGS=-Oz
endif

ifeq ($(USE_ASM),1)
	ASM_FLAGS=-mssse3 -msse3 -msse2 -s WASM=1 #--llvm-lto 2
else
	ASM_FLAGS=
endif

ifeq ($(USE_PTHREAD),1)
	THREAD_FLAGS= s USE_PTHREADS=1
else
	THREAD_FLAGS=
endif

CFLAGS=-I. -I./jansson/include -I./jansson/src -std=c11 $(DEBUG_FLAGS) $(ASM_FLAGS) $(THREAD_FLAGS) -s NO_EXIT_RUNTIME=1 -s INVOKE_RUN=0 -s RESERVED_FUNCTION_POINTERS=20 -s EXPORT_BINDINGS=1 -s NO_FILESYSTEM=1 -s EXPORTED_FUNCTIONS='["_main","_init","_registerSubmitSolutionCallBack","_registerAddHashCallBack", "_registerJobCallBack", "_getHashes","_getHashRate", "_updateStats"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["addFunction", "ccall", "cwrap"]'


INC=elist.h \
	miner.h \
	compat.h

#--memory-init-file 0 will compile but not run in non asm builds
#--llvm-lto 1 can break stuff
#-s SAFE_HEAP_LOG=1
#-S SAFE_HEAP Zerstört ALIgnment

#were actually not working. But maybe someday i need them...
#CFLAGS+= --profiling --profiling-funcs --cpuprofiler --memoryprofiler
#--profiling
#--profiling-funcs
#--cpuprofiler
#--memoryprofiler

OBJ	=   util.o \
		jansson/src/dump.o \
		jansson/src/error.o \
		jansson/src/hashtable_seed.o \
		jansson/src/hashtable.o \
		jansson/src/load.o \
		jansson/src/memory.o \
		jansson/src/pack_unpack.o \
		jansson/src/strbuffer.o \
		jansson/src/strconv.o \
		jansson/src/utf.o \
		jansson/src/value.o \
		libethash/internal.o \
		libethash/sha3.o \
		equihash/cpu_simple/equihash.o \
		equihash/cpu_simple/blake/blake2b.o \
		sha2.o \
		myr-groestl.o \
		cryptolight.o \
		cryptonight.o \
		heavy.o \
		skein.o \
		blake2.o \
		neoscrypt.o \
		quark.o \
		axiom.o \
		bastion.o \
		blakecoin.o \
		bmw256.o \
		c11.o \
		decred.o \
		drop.o \
		groestl.o \
		jha.o \
		lbry.o \
		luffa.o \
		lyra2re.o \
		lyra2rev2.o \
		nist5.o \
		pentablake.o \
		pluck.o \
		qubit.o \
		sia.o \
		sibcoin.o \
		skein2.o \
		s3.o \
		scrypt-jane.o \
		timetravel.o \
		bitcore.o \
		tribus.o \
		veltor.o \
		x11evo.o \
		x16r.o \
		x17.o \
		xevan.o \
		zr5.o \
		scrypt.o \
		keccak.o \
		quark.o \
		ink.o \
		blake.o \
		fresh.o \
		x11.o \
		x13.o \
		x14.o \
		x15.o \
		sha3/gost_streebog.o \
		sha3/mod_blakecoin.o \
		sha3/sph_ripemd.o \
		sha3/sph_sha2.o \
		sha3/sph_sha2big.o \
		sha3/sph_shavite.o \
		sha3/sph_haval.o \
		sha3/sph_keccak.o \
		sha3/sph_hefty1.o \
		sha3/sph_groestl.o \
		sha3/sph_skein.o \
		sha3/sph_bmw.o \
		sha3/sph_jh.o \
		sha3/sph_shavite.o \
		sha3/sph_blake.o \
		sha3/sph_luffa.o \
		sha3/sph_cubehash.o \
		sha3/sph_simd.o \
		sha3/sph_echo.o \
		sha3/sph_hamsi.o \
		sha3/sph_hamsi_helper.o \
		sha3/sph_fugue.o \
		sha3/sph_shabal.o \
		sha3/sph_whirlpool.o \
		crypto/oaes_lib.o \
		crypto/c_keccak.o \
		crypto/c_groestl.o \
		crypto/c_blake256.o \
		crypto/blake2b.o \
		crypto/blake2s.o \
		crypto/c_jh.o \
		crypto/c_skein.o \
		crypto/hash.o \
		crypto/aesb.o \
		crypto/aesb-x86-impl.o \
		yescrypt/sha256_Y.o \

#ASM
ifeq ($(USE_ASM),1)
OBJ+= yescrypt.o
#choose the one with the best perfomance Working currently
#		yescrypt/yescrypt-best.o \
#		yescrypt/yescrypt-common.o \
#		yescrypt/yescrypt-opt.o \
#		OBJ+= yescrypt/yescrypt-simd.o

OBJ+= yescrypt/yescrypt-common.o
OBJ+= yescrypt/yescrypt-opt.o

OBJ+= lyra2/Lyra2.o
OBJ+= lyra2/Sponge.o
endif


%.o: %.c $(INC)
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S $(INC)
	$(ASM) $(ASMFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.js *js.mem *.map *.wasm *.wasm.pre *.wasm.map *.wast *.pre sha3/*.o crypto/*.o lyra2/*.o yescrypt/*.o jansson/src/*.0 jansson.bak/*.o

ethash: $(OBJ)
	$(CC) $(CFLAGS) -s TOTAL_MEMORY=1073741824 -Dethash miner.c -o ethash_miner.js $^

equihash: $(OBJ)
	$(CC) $(CFLAGS) -s TOTAL_MEMORY=1073741824 -Dequihash miner.c -o equihash_miner.js $^

neoscrypt: $(OBJ)
	$(CC) $(CFLAGS) -Dneoscrypt miner.c -o neoscrypt_miner.js $^

axiom: $(OBJ)
	$(CC) $(CFLAGS) -Daxiom miner.c -o axiom_miner.js $^

bastion: $(OBJ)
	$(CC) $(CFLAGS) -Dbastion miner.c -o bastion_miner.js $^

blakecoin: $(OBJ)
	$(CC) $(CFLAGS) -Dblakecoin miner.c -o blakecoin_miner.js $^

bmw256: $(OBJ)
	$(CC) $(CFLAGS) -Dbmw miner.c -o bmw_miner.js $^

c11: $(OBJ)
	$(CC) $(CFLAGS) -Dc11 miner.c -o c11_miner.js $^

cryptolight: $(OBJ)
	$(CC) $(CFLAGS) -Dcryptolight miner.c -o cryptolight_miner.js $^

decred: $(OBJ)
	$(CC) $(CFLAGS) -Ddecred miner.c -o decred_miner.js $^

dmd-gr: $(OBJ)
	$(CC) $(CFLAGS) -Ddmdgr miner.c -o dmdgr_miner.js $^

drop: $(OBJ)
	$(CC) $(CFLAGS) -Ddrop miner.c -o drop_miner.js $^

groestl: $(OBJ)
	$(CC) $(CFLAGS) -Dgroestl miner.c -o groestl_miner.js $^

jha: $(OBJ)
	$(CC) $(CFLAGS) -Djha miner.c -o jha_miner.js $^

lbry: $(OBJ)
	$(CC) $(CFLAGS) -Dlbry miner.c -o lbry_miner.js $^

luffa: $(OBJ)
	$(CC) $(CFLAGS) -Dluffa miner.c -o luffa_miner.js $^

lyra2re: $(OBJ)
	$(CC) $(CFLAGS) -Dlyra2re miner.c -o lyra2re_miner.js $^

lyra2rev2: $(OBJ)
	$(CC) $(CFLAGS) -Dlyra2rev2 miner.c -o lyra2rev2_miner.js $^

myr-groestl: $(OBJ)
	$(CC) $(CFLAGS) -Dmyrgr miner.c -o myrgr_miner.js $^

nist5: $(OBJ)
	$(CC) $(CFLAGS) -Dnist5 miner.c -o nist5_miner.js $^

pentablake: $(OBJ)
	$(CC) $(CFLAGS) -Dpentablake miner.c -o pentablake_miner.js $^

pluck: $(OBJ)
	$(CC) $(CFLAGS) -Dpluck miner.c -o pluck_miner.js $^

qubit: $(OBJ)
	$(CC) $(CFLAGS) -Dqubit miner.c -o qubit_miner.js $^

scrypt-jane: $(OBJ)
	$(CC) $(CFLAGS) -Dscryptjane miner.c -o scryptjane_miner.js $^

sia: $(OBJ)
	$(CC) $(CFLAGS) -Dsia miner.c -o sia_miner.js $^

sibcoin: $(OBJ)
	$(CC) $(CFLAGS) -Dsib miner.c -o sib_miner.js $^

skein2: $(OBJ)
	$(CC) $(CFLAGS) -Dskein2 miner.c -o skein2_miner.js $^

s3: $(OBJ)
	$(CC) $(CFLAGS) -Ds3 miner.c -o s3_miner.js $^

timetravel: $(OBJ)
	$(CC) $(CFLAGS) -Dtimetravel miner.c -o timetravel_miner.js $^

bitcore: $(OBJ)
	$(CC) $(CFLAGS) -Dbitcore miner.c -o bitcore_miner.js $^

tribus: $(OBJ)
	$(CC) $(CFLAGS) -Dtribus miner.c -o tribus_miner.js $^

vanilla: $(OBJ)
	$(CC) $(CFLAGS) -Dvanilla miner.c -o vanilla_miner.js $^

veltor: $(OBJ)
	$(CC) $(CFLAGS) -Dveltor miner.c -o veltor_miner.js $^

x11evo: $(OBJ)
	$(CC) $(CFLAGS) -Dx11evo miner.c -o x11evo_miner.js $^

x16r: $(OBJ)
	$(CC) $(CFLAGS) -Dx16r miner.c -o x16r_miner.js $^

x17: $(OBJ)
	$(CC) $(CFLAGS) -Dx17 miner.c -o x17_miner.js $^

xevan: $(OBJ)
	$(CC) $(CFLAGS) -Dxevan miner.c -o xevan_miner.js $^

yescrypt: $(OBJ)
	$(CC) $(CFLAGS) -Dyescrypt miner.c -o yescrypt_miner.js $^

zr5: $(OBJ)
	$(CC) $(CFLAGS) -Dzr5 miner.c -o zr5_miner.js $^

blake2: $(OBJ)
	$(CC) $(CFLAGS) -Dblake2s miner.c -o blake2_miner.js $^

sha256d: $(OBJ)
	$(CC) $(CFLAGS) -Dsha256d_ miner.c -o sha256d_miner.js $^

keccak: $(OBJ)
	$(CC) $(CFLAGS) -Dkeccak miner.c -o keccak_miner.js $^

scrypt: $(OBJ)
	$(CC) $(CFLAGS) -Dscrypt miner.c -o scrypt_miner.js $^

heavy: $(OBJ)
	$(CC) $(CFLAGS) -Dheavy miner.c -o heavy_miner.js $^

quark: $(OBJ)
	$(CC) $(CFLAGS) -Dquark miner.c -o quark_miner.js $^

skein: $(OBJ)
	$(CC) $(CFLAGS) -Dskein miner.c -o skein_miner.js $^

ink: $(OBJ)
	$(CC) $(CFLAGS) -Dink miner.c -o ink_miner.js $^

blake: $(OBJ)
	$(CC) $(CFLAGS) -Dblake miner.c -o blake_miner.js $^

fresh: $(OBJ)
	$(CC) $(CFLAGS) -Dfresh miner.c -o fresh_miner.js $^

x11: $(OBJ)
	$(CC) $(CFLAGS) -Dx11 miner.c -o x11_miner.js $^

x13: $(OBJ)
	$(CC) $(CFLAGS) -Dx13 miner.c -o x13_miner.js $^

x14: $(OBJ)
	$(CC) $(CFLAGS) -Dx14 miner.c -o x14_miner.js $^

x15: $(OBJ)
	$(CC) $(CFLAGS) -Dx15 miner.c -o x15_miner.js $^

cryptonight: $(OBJ)
	$(CC) $(CFLAGS) -Dcryptonight miner.c -o cryptonight_miner.js $^

all: $(OBJ)
	$(MAKE) neoscrypt
	$(MAKE) axiom
	$(MAKE) bastion
	$(MAKE) blakecoin
	$(MAKE) bmw256
	$(MAKE) blake2
	$(MAKE) c11
	$(MAKE) cryptolight
	$(MAKE) decred
	$(MAKE) dmd-gr
	$(MAKE) drop
	$(MAKE) groestl
	$(MAKE) jha
	$(MAKE) luffa
	$(MAKE) lyra2re
	$(MAKE) lyra2rev2
	$(MAKE) myr-groestl
	$(MAKE) nist5
	$(MAKE) pentablake
	$(MAKE) pluck
	$(MAKE) qubit
	$(MAKE) scryptjane
	$(MAKE) sia
	$(MAKE) sibcoin
	$(MAKE) s3
	$(MAKE) timetravel
	$(MAKE) bitcore
	$(MAKE) skein2
	$(MAKE) skein
	$(MAKE) tribus
	$(MAKE) vanilla
	$(MAKE) veltor
	$(MAKE) x11evo
	$(MAKE) x17
	$(MAKE) xevan
	$(MAKE) zr5
	$(MAKE) sha256d
	$(MAKE) keccak
	$(MAKE) scrypt
	$(MAKE) heavy
	$(MAKE) quark
	$(MAKE) skein
	$(MAKE) ink
	$(MAKE) blake
	$(MAKE) blake2
	$(MAKE) fresh
	$(MAKE) x11
	$(MAKE) x13
	$(MAKE) x14
	$(MAKE) x15
	$(MAKE) x16r
	$(MAKE) cryptonight

ifeq ($(USE_ASM),1)
	$(MAKE) yescrypt
	$(MAKE) lbry
endif
