// Header guard
#ifndef MWC_VALIDATION_NODE_PROOF_OF_WORK_H
#define MWC_VALIDATION_NODE_PROOF_OF_WORK_H


// Header files
#include "./common.h"
#include "./header.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Proof of work class
class ProofOfWork final {

	// Public
	public:
	
		// Constructor
		ProofOfWork() = delete;
		
		// Has valid proof of work
		static bool hasValidProofOfWork(const Header &header);
		
	// Public for header class
	private:
	
		// Header friend class
		friend class Header;
		
		// Has valid proof of work
		static bool hasValidProofOfWork(const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> &proofOfWorkHash, const uint8_t edgeBits, const uint64_t proofNonces[Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES]);
		
		// Get proof of work hash
		static array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getProofOfWorkHash(const Header &header, const uint64_t nonce);
		
	// Private
	private:
	
		// SipHash keys length
		static const size_t SIPHASH_KEYS_LENGTH = 4;
		
		// SipHash block bits
		static const uint64_t SIPHASH_BLOCK_BITS;

		// SipHash block length
		static const size_t SIPHASH_BLOCK_LENGTH;

		// SipHash block mask
		static const uint64_t SIPHASH_BLOCK_MASK;
		
		// SipHash default rotation
		static const uint8_t SIPHASH_DEFAULT_ROTATION;
		
		// C29 SipHash rotation
		static const uint8_t C29_SIPHASH_ROTATION;
	
		// SipHash-2-4 class
		class SipHash24 final {
		
			// Public
			public:
			
				// Constructor
				explicit SipHash24(const uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH]);
				
				// Hash
				void hash(const uint64_t nonce, const uint8_t rotation);
				
				// Digest
				uint64_t digest() const;
			
			// Private
			private:
			
				// Round
				void round(const uint8_t rotation);
			
				// Values
				uint64_t values[SIPHASH_KEYS_LENGTH];
		};
		
		// SipHash block
		static uint64_t sipHashBlock(const uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH], const uint64_t nonce, const uint8_t rotation);
		
		// SipNode
		static uint64_t sipNode(const uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH], const uint64_t edge, const uint64_t uorv);
};


}


#endif
