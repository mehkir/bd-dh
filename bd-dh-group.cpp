// https://www.rfc-editor.org/rfc/rfc5114.txt
// 2048-bit MODP Group with 256-bit Prime Order Subgroup

#include <iostream>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <chrono>
#include <cassert>
#include "MODP2048_256sg.h"

using namespace std;
using namespace CryptoPP;

int main() {
    std::chrono::time_point start = std::chrono::system_clock::now();
    DH dh;		
    AutoSeededRandomPool rnd;

    dh.AccessGroupParameters().Initialize(p, q, g);

    if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
	    throw runtime_error("Failed to validate prime and generator");

    Integer v = ModularExponentiation(g, q, p);
	if(v != Integer::One())
		throw runtime_error("Failed to verify order of the subgroup");

    //////////////////////////////////////////////////////////////
    SecByteBlock M1_secret(dh.PrivateKeyLength());
    dh.GeneratePrivateKey(rnd, M1_secret);
    SecByteBlock M1_public(dh.PublicKeyLength());
    dh.GeneratePublicKey(rnd, M1_secret, M1_public);
    Integer M1_secret_int(M1_secret, M1_secret.SizeInBytes());
    Integer M1_public_int(M1_public, M1_public.SizeInBytes());
    Integer M1_public_inverse = M1_public_int.InverseMod(p);

    SecByteBlock M2_secret(dh.PrivateKeyLength());
    dh.GeneratePrivateKey(rnd, M2_secret);
    SecByteBlock M2_public(dh.PublicKeyLength());
    dh.GeneratePublicKey(rnd, M2_secret, M2_public);
    Integer M2_secret_int(M2_secret, M2_secret.SizeInBytes());
    Integer M2_public_int(M2_public, M2_public.SizeInBytes());
    Integer M2_public_inverse = M2_public_int.InverseMod(p);

    SecByteBlock M3_secret(dh.PrivateKeyLength());
    dh.GeneratePrivateKey(rnd, M3_secret);
    SecByteBlock M3_public(dh.PublicKeyLength());
    dh.GeneratePublicKey(rnd, M3_secret, M3_public);
    Integer M3_secret_int(M3_secret, M3_secret.SizeInBytes());
    Integer M3_public_int(M3_public, M3_public.SizeInBytes());
    Integer M3_public_inverse = M3_public_int.InverseMod(p);

    SecByteBlock M4_secret(dh.PrivateKeyLength());
    dh.GeneratePrivateKey(rnd, M4_secret);
    SecByteBlock M4_public(dh.PublicKeyLength());
    dh.GeneratePublicKey(rnd, M4_secret, M4_public);
    Integer M4_secret_int(M4_secret, M4_secret.SizeInBytes());
    Integer M4_public_int(M4_public, M4_public.SizeInBytes());
    Integer M4_public_inverse = M4_public_int.InverseMod(p);

    Integer X1_dv = ModularMultiplication(M2_public_int, M4_public_inverse, p);
    Integer X2_dv = ModularMultiplication(M3_public_int, M1_public_inverse, p);
    Integer X3_dv = ModularMultiplication(M4_public_int, M2_public_inverse, p);
    Integer X4_dv = ModularMultiplication(M1_public_int, M3_public_inverse, p);

    Integer X1 = ModularExponentiation(X1_dv, M1_secret_int, p);
    Integer X2 = ModularExponentiation(X2_dv, M2_secret_int, p);
    Integer X3 = ModularExponentiation(X3_dv, M3_secret_int, p);
    Integer X4 = ModularExponentiation(X4_dv, M4_secret_int, p);

    Integer member_count(4);
    Integer M1_sk_tmp = ModularExponentiation(M4_public_int, member_count*M1_secret_int, p) *
                        ModularExponentiation(X1, member_count-1, p) *
                        ModularExponentiation(X2, member_count-2, p);
    Integer M1_sk = ModularMultiplication(M1_sk_tmp, X3, p);
    Integer M2_sk_tmp = ModularExponentiation(M1_public_int, member_count*M2_secret_int, p) *
                        ModularExponentiation(X2, member_count-1, p) *
                        ModularExponentiation(X3, member_count-2, p);
    Integer M2_sk = ModularMultiplication(M2_sk_tmp, X4, p);
    Integer M3_sk_tmp = ModularExponentiation(M2_public_int, member_count*M3_secret_int, p) *
                        ModularExponentiation(X3, member_count-1, p) *
                        ModularExponentiation(X4, member_count-2, p);
    Integer M3_sk = ModularMultiplication(M3_sk_tmp, X1, p);
    Integer M4_sk_tmp = ModularExponentiation(M3_public_int, member_count*M4_secret_int, p) *
                        ModularExponentiation(X4, member_count-1, p) *
                        ModularExponentiation(X1, member_count-2, p);
    Integer M4_sk = ModularMultiplication(M4_sk_tmp, X2, p);
    
    assert(M1_sk == M2_sk);
    assert(M2_sk == M3_sk);
    assert(M3_sk == M4_sk);

    std::chrono::time_point end = std::chrono::system_clock::now();
    std::cout << "Complete duration: " << (end.time_since_epoch().count() - start.time_since_epoch().count())/1000000 << "ms" << std::endl;
    return 0;
}