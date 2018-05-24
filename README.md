MultiMinerfor JS
================
This is a multi-threaded CPU miner,
fork of [pooler](//github.com/pooler)'s cpuminer (see AUTHORS for list of contributors).

#### Table of contents

* [Algorithms](#algorithms)
* [Dependencies](#dependencies)
* [Build](#build)
* [Usage instructions](#usage-instructions)
* [Credits](#credits)
* [License](#license)

Algorithms
==========
#### Currently supported
 * ✓ __scrypt__ (Litecoin, Dogecoin, Feathercoin, etc..)
 * ✓ __scrypt:N__ (Vertcoin [VTC])
 * ✓ __sha256d__ (Bitcoin, Freicoin, Peercoin/PPCoin, Terracoin, etc..)
 * ✓ __x11__ (Darkcoin [DRK], Hirocoin, Limecoin)
 * ✓ __x13__ (Sherlockcoin, [ACE], [B2B], [GRC], [XHC], etc..)
 * ✓ __x14__ (X14, Webcoin [WEB])
 * ✓ __x15__ (RadianceCoin [RCE])
 * ✓ __x16r__ 
 * ✓ __x17__ 
 * ✓ __cryptonight__ (Bytecoin [BCN], Monero)
 * ✓ __cryptolight__ 
 * ✓ __fresh__ (FreshCoin)
 * ✓ __keccak__ (Maxcoin  HelixCoin, CryptoMeth, Galleon, 365coin, Slothcoin, BitcointalkCoin)
 * ✓ __hefty1__ (Heavycoin)
 * ✓ __quark__ (Quarkcoin)
 * ✓ __skein__ (Skeincoin, Myriadcoin)
 * ✓ __shavite3__ (INKcoin)
 * ✓ __blake__ (Blakecoin)
 * ✓ __scrypt-jane__ (YaCoin, CopperBars, Pennies, Tickets, etc..)
 * ✓ __qubit__ (Qubitcoin, Myriadcoin)
 * ✓ __groestl__ (Groestlcoin)
 * ✓ __equihash__ 
 * ✓ __ethash__
 * ✓ __bmw__
 * ✓ __sia__
 * ✓ __sibcoin__
 * ✓ __skein__
 * ✓ __skein2__
 * ✓ __timetravel__
 * ✓ __tribus__
 * ✓ __veltor__ 
 * ✓ __xevan__   
 * ✓ __yescrypt__
 * ✓ __zr5__
 
Dependencies
============
* jansson			http://www.digip.org/jansson/ 
* emscripten		https://github.com/kripken/emscripten

Download
========
* Git tree:   https://github.com/FloydZ/multiminer
  * Clone with `git clone https://github.com/FloydZ/multiminer`

Build
=====

#### Basic *nix build instructions (needs Emscripten):
```
	git clone https://github.com/FloydZ/multiminer
	cd multiminer
	git clone http://www.digip.org/jansson/ 
	cd jansson 
	cmake .
	make 
	cd ..
	make
	
```
 * See Makefile for some specific flags like DEBUG.

Usage instructions
==================
Open Debug.html in your browser and try some algos
Or look in the example folder. There you find a captcha and miner example which uses WebWorker. 

Credits
=======
MultiMiner is forked from pooler's CPUMiner.
* [tpruvot](https://github.com/tpruvot) added some features and recent SHA3 based algorythmns
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight

License
=======
GPLv2.  See COPYING for details.
