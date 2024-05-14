#include <iostream>
#include "engine.h"

int ExternalAnalysisEngine::analyze(const std::string& argument) {
    std::cout << "Calling external engine with argument: " << argument << std::endl;
    return callExternalEngine(argument);
}

int ExternalAnalysisEngine::callExternalEngine(const std::string& argument) {
    return system(argument.c_str());
}
