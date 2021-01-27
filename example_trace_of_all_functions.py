from idautils import *

Search_Functions = {
    'fgetc'    ,
    'fgets'    ,
    'fprintf'  ,
    'fputc'    ,
    'fputchar' ,
    'fputs'    ,
    'fread'    ,
    'fscanf'   ,
    'ftell'    ,
    'fwrite'   ,
    'getc'     ,
    'getchar'  ,
    'gets'     ,
    'perror'   ,
    'printf'   ,
    'putc'     ,
    'putchar'  ,
    'puts'     ,
    'read'     ,
    'read_chunk',
    'scanf'    ,
    'sscanf'   ,
    'vfprintf' ,
    'vfscanf'  ,
    'vprintf'  ,
    'vscanf'   ,
    'vsscanf'  ,

    'atof'    ,
    'atoi'    ,
    'atol'    ,
    'malloc'  ,
    'memcpy'  ,
    'memmove' ,
    'memset'  ,
    'sprintf' ,
    'strcat'  ,
    'strcpy'  ,
    'strlen'  ,
    'strncpy' ,
}

def Traceroute(function_name):
    ea = ScreenEA()

    for function_ea in Functions(SegStart(ea), SegEnd(ea)):

        f_name = GetFunctionName(function_ea)
    
        if function_name == f_name:

            for ref_ea in CodeRefsTo(function_ea, 0):

                #if (f_name.find('main') == -1) and (f_name.find(GetFunctionName(ref_ea)) == -1):
                if (f_name.find(GetFunctionName(ref_ea)) == -1):

                    print '\t%s (0x%x) \t<-' % (f_name, function_ea)
                    Traceroute(GetFunctionName(ref_ea))
                    return


# Get the segment's starting address
ea = ScreenEA()

# Loop through all the functions
for function_ea in Functions(SegStart(ea), SegEnd(ea)):

    f_name = GetFunctionName(function_ea)
    
    for it in Search_Functions:

        if it == f_name:

            print '\nFunction %s at 0x%x' % (f_name, function_ea)

            for ref_ea in CodeRefsTo(function_ea, 0):

                #if f_name.find('main') == -1:

                    print '\t%s (0x%x) \t<-' % (GetFunctionName(function_ea), function_ea)
                    Traceroute(GetFunctionName(ref_ea))
                    print ''
