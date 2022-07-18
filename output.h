// Header guard
#ifndef OUTPUT_H
#define OUTPUT_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Classes

// Output class
class Output final : public MerkleMountainRangeLeaf<Output, sizeof(uint8_t) + Crypto::COMMITMENT_LENGTH, secp256k1_pedersen_commitment> {

	// Public
	public:
	
		// Features
		enum class Features : uint8_t {
		
			// Plain
			PLAIN,
			
			// Coinbase
			COINBASE,
			
			// Unknown
			UNKNOWN
		};
		
		// Constructor
		explicit Output(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH], const bool isGenesisBlockOutput = false);
		
		// Serialize
		virtual const vector<uint8_t> serialize() const override final;
		
		// Get lookup value
		virtual const optional<vector<uint8_t>> getLookupValue() const override final;
		
		// Add to sum
		virtual void addToSum(secp256k1_pedersen_commitment &sum, const AdditionReason additionReason) const override final;
		
		// Subtract from sum
		virtual void subtractFromSum(secp256k1_pedersen_commitment &sum, const SubtractionReason subtractionReason) const override final;
		
		// Equality operator
		const bool operator==(const Output &other) const;
		
		// Inequality operator
		const bool operator!=(const Output &other) const;
		
		// Get features
		const Features getFeatures() const;
		
		// Get commitment
		const secp256k1_pedersen_commitment &getCommitment() const;
		
		// Unserialize
		static const Output unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedOutput, const bool isGenesisBlockOutput);
	
	// Private
	private:
		
		// Features
		Features features;
		
		// Commitment
		secp256k1_pedersen_commitment commitment;
};


#endif
