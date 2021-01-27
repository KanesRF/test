from idautils import *

InputFunctions = {

    'fgetc'    ,
    'fgets'    ,
    'fputc'    ,
    'fputs'    ,
    'ftell'    ,
    'fread'    ,
    'fwrite'   ,
    'getc'     ,
    'getchar'  ,
    'gets'     ,
    'printf'   ,
    'vprintf'  ,
    'fprintf'  ,
    'vfprintf' ,
    'perror'   ,
    'putc'     ,
    'putchar'  ,
    'fputchar' ,
    'scanf'    ,
    'vscanf'   ,
    'fscanf'   ,
    'vfscanf'  ,
    'sscanf'   ,
    'vsscanf'  ,
    'puts'     ,

}

UnsafeFunctions = {

    'strcpy'  ,
    'sprintf' ,
    'strncpy' ,
    'memcpy'  ,
    'memmove' ,
    'sprintf' ,
    'malloc'  ,
    'strcat'  ,
    'strlen'  ,
    'memset'  ,
    'atof'    ,
    'atol'    ,
    'atoi'    ,
}

def Traceroute(UnsafeFunctions):

    for func in UnsafeFunctions:
        print  "Unsafe function %s <0x%x> called from: " % (GetFunctionName(func), func)
        for ref in CodeRefsTo(func, 1):
            print "    %s <0x%x>" % (GetFunctionName(ref), ref)
        print ""
        
InputFunctionsFounded   = list()
UnsafeFunctionsFounded  = list()

print "*********************************************************************"
print "*********************************************************************"

if __name__ == '__main__':

    global InputFunctionsFounded
    global UnsafeFunctionsFounded

    ea = ScreenEA()

    for funcea in Functions(SegStart(ea), SegEnd(ea)):

        for it in InputFunctions:
            if it == GetFunctionName(funcea):
                InputFunctionsFounded.append(funcea)

        for it_1 in UnsafeFunctions:
            if it_1 == GetFunctionName(funcea):
                UnsafeFunctionsFounded.append(funcea)
        
    print "---------------INPUT FUNCTIONS---------------"
    for it_2 in InputFunctionsFounded:
        print "Input function <%s> placed at: <0x%x>" % (GetFunctionName(it_2), it_2)
    print "----------------------------------------------"

    print "---------------UNSAFE FUNCTIONS---------------"
    for it_3 in UnsafeFunctionsFounded:
        print "Unsafe function <%s> placed at: <0x%x>" % (GetFunctionName(it_3), it_3)
    print "----------------------------------------------"

    Traceroute(UnsafeFunctionsFounded)

print "*********************************************************************"
print "*********************************************************************"

