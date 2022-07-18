// Header guard
#ifndef INPUT_H
#define INPUT_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./output.h"

using namespace std;


// Classes

// Input class
class Input final {

	// Public
	public:
	
		// Features
		enum class Features : uint8_t {
		
			// Plain
			PLAIN,
			
			// Coinbase
			COINBASE,
			
			// Unknown
			UNKNOWN,
			
			// Same as output
			SAME_AS_OUTPUT
		};
		
		// Constructor
		explicit Input(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH]);
		
		// Serialize
		const vector<uint8_t> serialize() const;
		
		// Get lookup value
		const vector<uint8_t> getLookupValue() const;
		
		// Get features
		const Features getFeatures() const;
		
		// Get commitment
		const secp256k1_pedersen_commitment &getCommitment() const;
	
	// Private
	private:
	
		// Features
		Features features;
		
		// Commitment
		secp256k1_pedersen_commitment commitment;
};


#endif
