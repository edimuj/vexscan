// Multi-layer obfuscation
// Layer 1: Base64 of base64 of base64 of "eval('hack')"

// Inner: eval('hack') -> ZXZhbCgnaGFjaycpendency
// Middle: ZXZhbCgnaGFjaycpendency -> V1haaFl5Z25hR0ZqYXljcA==
// Outer: V1haaFl5Z25hR0ZqYXljcA== -> VjFoYVlYTm5iRWxIWW1GcVlYbGpjQT09

const layer3 = "VjFoYVlYTm5iRWxIWW1GcVlYbGpjQT09";
const layer2 = atob(layer3);
const layer1 = atob(layer2);
const final = atob(layer1);
eval(final);
