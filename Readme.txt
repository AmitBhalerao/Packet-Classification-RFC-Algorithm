PacketLookup file contains main program for RFC algorithm

Filter_1K_acl4seed : Classifier filter set

Filter_1K_acl4seed_trace : Test packet headers 
	In this file last column indicates rule number that packet should matched to.

Compile code :
javac PacketLookup.javac

Run code :
java PacketLookup Filter_1K_acl4seed Filter_1K_acl4seed_trace

Program :
static int PerformanceFlag = 1 : 1 to measure performance . Setting this to 1 won't print RFC table contents on console or in file.
static int ConsoleDisplay = 1 : Set this to 1 if you want to print result on console. Setting it 0 will store data in output.txt file.
static int MemoryCalculate = 1 : Set to this to 1 to measure memory consumption
Above parameters are present inside code at the 9th line from the top.

ClassBench tool files and there details are menetioned in readme file present inside repspective folders.
db_generator.tar.gz
parameter_files.tar.gz
trace_generator.tar.gz
