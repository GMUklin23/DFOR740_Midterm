Compilation:
Because these files are written in C++ but uses the win32api it's recommended to use a build tool like Visual Studio Build Tools to compile these binaries.
If on Linux, g++ can be used to compile the source code into binaries via g++ {filename}.cpp -o {outputfilename}, but you will likely run into issues because of the win32api.

tasklist.cpp is based on the Windows tasklist utility which will list the processes on the system. 
The only supported flags are [NONE], [/V], and [/SVC] per assignment instructions.
Ex: tasklist /SVC

taskkill.cpp is based on the Windows taskkill utility which will kill certain processes when supplied with either a process id or image name and requires a minimum of at least 2 commandline arguments.
The only support flags are [/PID] {process id}, [/IM] {image name}, [/F], and [/T}
