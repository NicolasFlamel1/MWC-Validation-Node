// Header files
#include"./common.h"
#include "./input.h"
#include "secp256k1_commitment.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Supporting function implementation

// Constructor
Input::Input(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH]) :

	// Set features to features
	features(features)
{

	// Check if features is invalid
	if(features == Features::UNKNOWN) {
	
		// Throw exception
		throw runtime_error("Features is invalid");
	}
	
	// Check if commitment is invalid
	if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &this->commitment, commitment)) {
	
		// Throw exception
		throw runtime_error("Commitment is invalid");
	}
}

// Serialize
vector<uint8_t> Input::serialize(const uint32_t protocolVersion) const {

	// Initialize serialized input
	vector<uint8_t> serializedInput;
	
	// Check if features aren't the same as output and protocol version is at most two
	if(features != Features::SAME_AS_OUTPUT && protocolVersion <= 2) {
	
		// Append features to serialized input
		Common::writeUint8(serializedInput, static_cast<underlying_type_t<Features>>(features));
	}
	
	// Check if serializing commitment failed
	uint8_t serializedCommitment[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment)) {
	
		// Throw exception
		throw runtime_error("Serializing commitment failed");
	}
	
	// Append serialized commitment to serialized input
	serializedInput.insert(serializedInput.cend(), cbegin(serializedCommitment), cend(serializedCommitment));
	
	// Return serialized input
	return serializedInput;
}

// Get lookup value
vector<uint8_t> Input::getLookupValue() const {

	// Check if serializing commitment failed
	vector<uint8_t> serializedCommitment(Crypto::COMMITMENT_LENGTH);
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment.data(), &commitment)) {
	
		// Throw exception
		throw runtime_error("Serializing commitment failed");
	}
	
	// Return serialized commitment
	return serializedCommitment;
}

// Get features
Input::Features Input::getFeatures() const {

	// Return features
	return features;
}

// Set features
void Input::setFeatures(const Features features) {

	// Set features to features
	this->features = features;
}

// Get commitment
const secp256k1_pedersen_commitment &Input::getCommitment() const {

	// Return commitment
	return commitment;
}
