#include <idc.idc>

static main()
{
	auto first,	function, place, count;

	// получаем текущий адрес курсора
	first = ScreenEA();

	// в цикле от начала (SegStart) до конца (SegEND) текущего сегмента
	for (function = SegStart(first); function != BADADDR && function < SegEnd(first); function = NextFunction(function))
	{
		// если текущий адрес является адресом функции
		if (GetFunctionFlags(function) != -1)
		{
			//*
			if (
				GetFunctionName(function) == "malloc" 		||
				GetFunctionName(function) == "read" 		||
				GetFunctionName(function) == "fread" 		||
				GetFunctionName(function) == "read_chunk"	||
				GetFunctionName(function) == "scanf" 		||
				GetFunctionName(function) == "fscanf" 		||
				GetFunctionName(function) == "fgets"		||
				GetFunctionName(function) == "strcpy" 		||
				GetFunctionName(function) == "strncpy"		||
				GetFunctionName(function) == "strcat"		||
				GetFunctionName(function) == "strlen"		||
				GetFunctionName(function) == "sprintf" 		||
				GetFunctionName(function) == "memcpy"		||
				GetFunctionName(function) == "memmove"		||
				GetFunctionName(function) == "memset"		||
				GetFunctionName(function) == "atof" 		||
				GetFunctionName(function) == "atol"
				)
				//*/
			{	
				count = 0;
				Message("\n\nFunction %s at 0x%x\n", GetFunctionName(function), function);
	
				// находим все ссылки на данную функцию и выводим
				for (place = RfirstB(function); place != BADADDR; place = RnextB(function, place))
				{
					count = count + 1;
					Message("%d. from %s (0x%x) function (address 0x%x)\n", count, GetFunctionName(place), FindFuncEnd((place)), place);
				}
			}
		}
	}
}
