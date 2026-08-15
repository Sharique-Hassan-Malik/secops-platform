CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
TARGETS  = archive_analyzer multi_detector

all: $(TARGETS)

archive_analyzer: archive_analyzer_main.cpp ArchiveAnalyzer.cpp ArchiveAnalyzer.h
	$(CXX) $(CXXFLAGS) -o $@ archive_analyzer_main.cpp ArchiveAnalyzer.cpp

multi_detector: multi_detector.cpp FormatScanner.cpp ArchiveAnalyzer.cpp FormatScanner.h ArchiveAnalyzer.h
	$(CXX) $(CXXFLAGS) -o $@ multi_detector.cpp FormatScanner.cpp ArchiveAnalyzer.cpp

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
