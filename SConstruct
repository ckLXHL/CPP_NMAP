HEADFILEPATH = Split('include /usr/local/include')
FILELIST = Glob('src/*.cpp')
LIB_DIR = Split('/usr/local/lib')
LIB = Split('boost_system')
TARGETNAME = 'server'
CPPFLAG = Split('--std=c++11')
Program(target = TARGETNAME,source = FILELIST,LIBS = LIB,CPPPATH = HEADFILEPATH,LIBPATH = LIB_DIR, CPPFLAGS=CPPFLAG)
