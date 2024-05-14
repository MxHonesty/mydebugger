#include <string>
#include <vector>

class AnalysisEngine {
    public:
    virtual int analyze(const std::string& argument) = 0;
};

class CppAnalysisEngine : public AnalysisEngine{
public:
    CppAnalysisEngine() = default;
    ~CppAnalysisEngine() = default;
    int analyze(const std::string& argument);
    bool isSyntaxCorrect(const std::string& code);
    std::vector<std::string> extractFunctions(const std::string& code);
    std::vector<std::string> extractVariables(const std::string& code);
    std::string getMostUsedFunction(const std::string& code);
};

class ExternalAnalysisEngine : public AnalysisEngine{
public:
    ExternalAnalysisEngine() = default;
    ~ExternalAnalysisEngine() = default;
    int analyze(const std::string& argument);
private:
    int callExternalEngine(const std::string& argument);
};
