// Header guard
#ifndef RANGEPROOF_H
#define RANGEPROOF_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Classes

// Rangeproof class
class Rangeproof final : public MerkleMountainRangeLeaf<Rangeproof, sizeof(uint64_t) + Crypto::BULLETPROOF_LENGTH> {

	// Public
	public:
	
		// Constructor
		explicit Rangeproof(const uint64_t length, const uint8_t proof[Crypto::BULLETPROOF_LENGTH], const bool isGenesisBlockRangeproof = false);
		
		// Serialize
		virtual const vector<uint8_t> serialize() const override final;
		
		// Equality operator
		const bool operator==(const Rangeproof &other) const;
		
		// Inequality operator
		const bool operator!=(const Rangeproof &other) const;
		
		// Get length
		const uint64_t getLength() const;
		
		// Get proof
		const uint8_t *getProof() const;
		
		// Unserialize
		static const Rangeproof unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedRangeproof, const bool isGenesisBlockRangeproof);
	
	// Private
	private:
		
		// length
		uint64_t length;
		
		// Proof
		uint8_t proof[Crypto::BULLETPROOF_LENGTH];
};


#endif
