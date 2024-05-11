// Header guard
#ifndef MWC_VALIDATION_NODE_INPUT_H
#define MWC_VALIDATION_NODE_INPUT_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./output.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


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
		vector<uint8_t> serialize() const;
		
		// Get lookup value
		vector<uint8_t> getLookupValue() const;
		
		// Get features
		Features getFeatures() const;
		
		// Set features
		void setFeatures(const Features features);
		
		// Get commitment
		const secp256k1_pedersen_commitment &getCommitment() const;
	
	// Private
	private:
	
		// Features
		Features features;
		
		// Commitment
		secp256k1_pedersen_commitment commitment;
};


}


#endif
