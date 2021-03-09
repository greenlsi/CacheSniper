#include <string.h>
#define LENGHT_ARR 16000

const unsigned int cT[LENGHT_ARR] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

unsigned long int get_address_table(int index)
{
    if (index < LENGHT_ARR)
    {
        return (unsigned long int)(&cT[index]);
    }
    else
    {
        return (unsigned long int)(&cT[0]);
    }
}
