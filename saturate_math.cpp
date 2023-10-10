// Header files
#include "./common.h"
#include "./saturate_math.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Supporting function implementation

// Add
uint64_t SaturateMath::add(const uint64_t firstAddend, const uint64_t secondAddend) {

	// Check if addition will overflow
	if(secondAddend > UINT64_MAX - firstAddend) {
	
		// Return max
		return UINT64_MAX;
	}
	
	// Otherwise
	else {
	
		// Return sum
		return firstAddend + secondAddend;
	}
}

// Subtract
uint64_t SaturateMath::subtract(const uint64_t minuend, const uint64_t subtrahend) {

	// Check if subtraction will underflow
	if(subtrahend > minuend) {
	
		// Return zero
		return 0;
	}
	
	// Otherwise
	else {
	
		// Return difference
		return minuend - subtrahend;
	}
}

// Multiply
uint64_t SaturateMath::multiply(const uint64_t multiplicand, const uint64_t multiplier) {

	// Check if multiplication will overflow
	if(multiplicand && multiplier > UINT64_MAX / multiplicand) {
	
		// Return max
		return UINT64_MAX;
	}
	
	// Otherwise
	else {
	
		// Return product
		return multiplicand * multiplier;
	}
}
