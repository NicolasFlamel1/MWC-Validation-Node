// Header guard
#ifndef MWC_VALIDATION_NODE_SATURATE_MATH_H
#define MWC_VALIDATION_NODE_SATURATE_MATH_H


// Header files
#include "./common.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Saturate math class
class SaturateMath final {

	// Public
	public:
	
		// Constructor
		SaturateMath() = delete;
		
		// Add
		static uint64_t add(const uint64_t firstAddend, const uint64_t secondAddend);
		
		// Subtract
		static uint64_t subtract(const uint64_t minuend, const uint64_t subtrahend);
		
		// Multiply
		static uint64_t multiply(const uint64_t multiplicand, const uint64_t multiplier);
};


}


#endif
